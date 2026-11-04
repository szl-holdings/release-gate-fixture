"""Offline metadata consistency fixture. A passing result never authorizes release."""
import argparse
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTITY = re.compile(r"[a-z0-9][a-z0-9._:@/-]{0,127}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z"
)
COMMON = {"status", "revision", "digest", "observed_at", "evidence_uri"}
POLICY_KEYS = {"version", "required_checks", "allowed_reviewers",
               "allowed_licenses", "max_age_seconds", "max_future_seconds"}
MAX_INPUT_BYTES = 1_048_576


def matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def timestamp(value):
    if not matches(TIMESTAMP, value):
        raise ValueError("expected an RFC3339 timestamp with timezone")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.utcoffset() is None or value.endswith("-00:00"):
        raise ValueError("unknown timezone")
    return result.astimezone(timezone.utc)


def evidence_uri(value):
    """Check a conservative URI shape only; never resolve, visit, or fetch it."""
    if type(value) is not str or not value.isascii() or not value:
        return False
    if any(ord(char) <= 32 or ord(char) == 127 for char in value):
        return False
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        return (parsed.scheme == "https" and parsed.username is None
                and parsed.password is None and parsed.port in (None, 443)
                and re.fullmatch(r"[A-Za-z0-9.-]+", host) is not None
                and not parsed.fragment and "\\" not in value
                and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
                                     label) for label in host.split(".")))
    except ValueError:
        return False


def evaluate(manifest, policy, *, expected_head, expected_digest,
             candidate_author, now=None):
    """All arguments other than manifest must come from a trusted caller."""
    errors = []

    def fail(path, reason):
        errors.append(f"{path}: {reason}")

    def shape(value, fields, path):
        if type(value) is not dict:
            fail(path, "must_be_object")
            return False
        if set(value) != fields:
            fail(path, "unexpected_or_missing_fields")
            return False
        return True

    def names(value, pattern, path):
        if (type(value) is not list or not value
                or any(not matches(pattern, item) for item in value)):
            fail(path, "must_be_nonempty_list_of_valid_strings")
            return False
        if len(set(value)) != len(value):
            fail(path, "duplicates_not_allowed")
            return False
        return True

    def result():
        return {"metadata_gate": "blocked" if errors else "passed",
                "release_authorized": False, "diagnostics": sorted(set(errors))}

    for path, value, pattern in (
        ("trusted.expected_head", expected_head, REVISION),
        ("trusted.expected_digest", expected_digest, DIGEST),
        ("trusted.candidate_author", candidate_author, IDENTITY),
    ):
        if not matches(pattern, value):
            fail(path, "invalid_pinned_value")
    now = datetime.now(timezone.utc) if now is None else now
    if not isinstance(now, datetime) or now.utcoffset() is None:
        fail("trusted.now", "must_be_timezone_aware_datetime")
    if shape(policy, POLICY_KEYS, "policy"):
        if type(policy["version"]) is not int or policy["version"] != 1:
            fail("policy.version", "must_be_integer_1")
        names(policy["required_checks"], NAME, "policy.required_checks")
        names(policy["allowed_reviewers"], IDENTITY, "policy.allowed_reviewers")
        names(policy["allowed_licenses"], NAME, "policy.allowed_licenses")
        for key, lower, upper in (("max_age_seconds", 1, 31_536_000),
                                  ("max_future_seconds", 0, 3600)):
            value = policy[key]
            if type(value) is not int or not lower <= value <= upper:
                fail("policy." + key, "integer_out_of_bounds")
    if errors:
        return result()
    if not shape(manifest, {"version", "candidate", "checks", "review", "rights",
                            "rollback"}, "manifest"):
        return result()
    if type(manifest["version"]) is not int or manifest["version"] != 1:
        fail("manifest.version", "must_be_integer_1")
    candidate = manifest["candidate"]
    if shape(candidate, {"revision", "digest", "author"}, "candidate"):
        for key, expected in (("revision", expected_head), ("digest", expected_digest),
                              ("author", candidate_author)):
            if candidate[key] != expected:
                fail("candidate." + key, "does_not_match_trusted_pin")

    def record(value, path, extra=frozenset()):
        if not shape(value, COMMON | set(extra), path):
            return False
        status = value["status"]
        if type(status) is not str or status not in ("passed", "failed", "unknown"):
            fail(path + ".status", "invalid_status")
        elif status != "passed":
            fail(path + ".status", "reported_" + status)
        for key, expected in (("revision", expected_head), ("digest", expected_digest)):
            if value[key] != expected:
                fail(path + "." + key, "does_not_match_trusted_pin")
        try:
            observed = timestamp(value["observed_at"])
            age = (now - observed).total_seconds()
            if age > policy["max_age_seconds"]:
                fail(path + ".observed_at", "stale")
            if age < -policy["max_future_seconds"]:
                fail(path + ".observed_at", "too_far_in_future")
        except (ValueError, OverflowError):
            fail(path + ".observed_at", "invalid_timezone_aware_timestamp")
        if not evidence_uri(value["evidence_uri"]):
            fail(path + ".evidence_uri", "invalid_https_evidence_uri")
        return True

    checks = manifest["checks"]
    if type(checks) is not dict:
        fail("checks", "must_be_object")
    else:
        if set(checks) != set(policy["required_checks"]):
            fail("checks", "must_match_trusted_required_checks_exactly")
        for name in sorted(policy["required_checks"]):
            if name not in checks:
                fail("checks." + name, "missing_required_check")
            else:
                record(checks[name], "checks." + name)
    review = manifest["review"]
    if record(review, "review", {"reviewer"}):
        reviewer = review["reviewer"]
        if not matches(IDENTITY, reviewer) or reviewer not in policy["allowed_reviewers"]:
            fail("review.reviewer", "not_allowed_reviewer")
        if reviewer == candidate_author:
            fail("review.reviewer", "must_be_independent_of_candidate_author")
    rights = manifest["rights"]
    if record(rights, "rights", {"license_id", "rights_status"}):
        if rights["rights_status"] != "allowed":
            fail("rights.rights_status", "must_be_explicitly_allowed")
        if (not matches(NAME, rights["license_id"])
                or rights["license_id"] not in policy["allowed_licenses"]):
            fail("rights.license_id", "not_allowed_license")
    record(manifest["rollback"], "rollback")
    return result()


def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def reject_constant(_value):
    raise ValueError("non_finite_json_number")


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non_finite_json_number")
    return number


def load_json(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("input_too_large")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates,
                      parse_constant=reject_constant, parse_float=finite_float)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="untrusted local JSON file")
    parser.add_argument("--policy", required=True, help="trusted local policy JSON file")
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--candidate-author", required=True)
    parser.add_argument("--now", help="trusted RFC3339 clock override for fixtures")
    args = parser.parse_args(argv)
    try:
        outcome = evaluate(load_json(args.manifest), load_json(args.policy),
                           expected_head=args.expected_head,
                           expected_digest=args.expected_digest,
                           candidate_author=args.candidate_author,
                           now=timestamp(args.now) if args.now else None)
    except (OSError, ValueError, OverflowError, RecursionError):
        outcome = {"metadata_gate": "blocked", "release_authorized": False,
                   "diagnostics": ["input: unreadable_or_invalid_json_or_clock"]}
        print(json.dumps(outcome, sort_keys=True))
        return 2
    print(json.dumps(outcome, sort_keys=True))
    return 0 if outcome["metadata_gate"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
