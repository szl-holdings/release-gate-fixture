"""Original synthetic fixtures; all identifiers and evidence are illustrative."""
import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import release_gate as gate

HEAD = "1" * 40
DIGEST = "sha256:" + "2" * 64
AUTHOR = "author@example.invalid"
NOW = datetime(2026, 10, 10, 9, 0, tzinfo=timezone.utc)


def fixtures():
    policy = {"version": 1, "required_checks": ["tests", "build"],
              "allowed_reviewers": ["reviewer@example.invalid", AUTHOR],
              "allowed_licenses": ["MIT", "Apache-2.0"],
              "max_age_seconds": 3600, "max_future_seconds": 60}
    evidence = {"status": "passed", "revision": HEAD, "digest": DIGEST,
                "observed_at": NOW.isoformat(),
                "evidence_uri": "https://evidence.example.invalid/report/fixture"}
    manifest = {"version": 1,
                "candidate": {"revision": HEAD, "digest": DIGEST, "author": AUTHOR},
                "checks": {"tests": copy.deepcopy(evidence), "build": copy.deepcopy(evidence)},
                "review": dict(evidence, reviewer="reviewer@example.invalid"),
                "rights": dict(evidence, license_id="MIT", rights_status="allowed"),
                "rollback": copy.deepcopy(evidence)}
    return manifest, policy


class GateTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.policy = fixtures()

    def run_gate(self, **overrides):
        args = dict(expected_head=HEAD, expected_digest=DIGEST,
                    candidate_author=AUTHOR, now=NOW)
        args.update(overrides)
        return gate.evaluate(self.manifest, self.policy, **args)

    def blocked(self, diagnostic=None, **overrides):
        result = self.run_gate(**overrides)
        self.assertEqual(result["metadata_gate"], "blocked", result)
        self.assertIs(result["release_authorized"], False)
        if diagnostic:
            self.assertIn(diagnostic, result["diagnostics"])
        return result

    def test_complete_metadata_passes_but_does_not_authorize(self):
        self.assertEqual(self.run_gate(), {"metadata_gate": "passed",
                         "release_authorized": False, "diagnostics": []})

    def test_missing_required_check_blocks(self):
        del self.manifest["checks"]["build"]
        self.blocked("checks.build: missing_required_check")

    def test_manifest_cannot_change_policy(self):
        self.manifest["required_checks"] = []
        self.blocked("manifest: unexpected_or_missing_fields")

    def test_unexpected_check_blocks(self):
        self.manifest["checks"]["optional"] = self.manifest["checks"]["tests"]
        self.blocked("checks: must_match_trusted_required_checks_exactly")

    def test_unknown_is_not_pass(self):
        self.manifest["checks"]["tests"]["status"] = "unknown"
        self.blocked("checks.tests.status: reported_unknown")

    def test_failed_is_not_pass(self):
        self.manifest["checks"]["tests"]["status"] = "failed"
        self.blocked("checks.tests.status: reported_failed")

    def test_status_requires_exact_known_string(self):
        for status in [True, 1, None, "success", "PASSED", [], {}]:
            with self.subTest(status=status):
                self.manifest["checks"]["tests"]["status"] = status
                self.blocked("checks.tests.status: invalid_status")

    def test_all_evidence_is_bound_to_head_and_digest(self):
        for section in ["tests", "build", "review", "rights", "rollback"]:
            for field, value in [("revision", "3" * 40), ("digest", "sha256:" + "4" * 64)]:
                with self.subTest(section=section, field=field):
                    self.manifest, self.policy = fixtures()
                    target = self.manifest["checks"][section] if section in ("tests", "build") else self.manifest[section]
                    target[field] = value
                    self.blocked()

    def test_candidate_must_match_all_trusted_pins(self):
        for field, value in [("revision", "5" * 40), ("digest", "sha256:" + "6" * 64),
                              ("author", "other@example.invalid")]:
            with self.subTest(field=field):
                self.manifest, self.policy = fixtures()
                self.manifest["candidate"][field] = value
                self.blocked("candidate." + field + ": does_not_match_trusted_pin")

    def test_every_pin_must_have_exact_immutable_format(self):
        for key, values in {"expected_head": ["main", "1" * 7, True, None],
                            "expected_digest": ["latest", "2" * 64, False],
                            "candidate_author": ["", " Author", "AUTHOR@example.invalid"]}.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.blocked(**{key: value})

    def test_sha256_revision_is_accepted(self):
        head = "a" * 64
        self.manifest["candidate"]["revision"] = head
        for value in list(self.manifest["checks"].values()) + [self.manifest[x] for x in ["review", "rights", "rollback"]]:
            value["revision"] = head
        self.assertEqual(self.run_gate(expected_head=head)["metadata_gate"], "passed")

    def test_staleness_boundary_is_inclusive(self):
        self.manifest["checks"]["tests"]["observed_at"] = (NOW - timedelta(seconds=3600)).isoformat()
        self.assertEqual(self.run_gate()["metadata_gate"], "passed")
        self.manifest["checks"]["tests"]["observed_at"] = (NOW - timedelta(seconds=3600, microseconds=1)).isoformat()
        self.blocked("checks.tests.observed_at: stale")

    def test_future_boundary_is_inclusive(self):
        self.manifest["checks"]["tests"]["observed_at"] = (NOW + timedelta(seconds=60)).isoformat()
        self.assertEqual(self.run_gate()["metadata_gate"], "passed")
        self.manifest["checks"]["tests"]["observed_at"] = (NOW + timedelta(seconds=60, microseconds=1)).isoformat()
        self.blocked("checks.tests.observed_at: too_far_in_future")

    def test_zero_future_tolerance(self):
        self.policy["max_future_seconds"] = 0
        self.manifest["rollback"]["observed_at"] = (NOW + timedelta(microseconds=1)).isoformat()
        self.blocked("rollback.observed_at: too_far_in_future")

    def test_timezone_offsets_are_compared_as_instants(self):
        self.manifest["review"]["observed_at"] = "2026-10-10T11:00:00+02:00"
        self.assertEqual(self.run_gate()["metadata_gate"], "passed")

    def test_z_timestamp_is_accepted(self):
        self.manifest["review"]["observed_at"] = "2026-10-10T09:00:00Z"
        self.assertEqual(self.run_gate()["metadata_gate"], "passed")

    def test_invalid_or_naive_timestamps_block(self):
        for value in ["2026-10-10T09:00:00", "2026-10-10", "2026-10-10T09:00:00-00:00",
                      "2026-02-30T00:00:00Z", "2026-10-10T09:00:00+25:00", True, 0, None]:
            with self.subTest(value=value):
                self.manifest["rollback"]["observed_at"] = value
                self.blocked("rollback.observed_at: invalid_timezone_aware_timestamp")

    def test_clock_must_be_aware(self):
        for value in [NOW.replace(tzinfo=None), "2026-10-10", True, 0]:
            with self.subTest(value=value):
                self.blocked("trusted.now: must_be_timezone_aware_datetime", now=value)

    def test_offset_components_are_not_silently_normalized(self):
        for offset in ["+00:60", "-00:60", "+23:99", "-23:99", "+24:00", "-24:00"]:
            with self.subTest(offset=offset):
                self.manifest["review"]["observed_at"] = "2026-10-10T09:00:00" + offset
                self.blocked("review.observed_at: invalid_timezone_aware_timestamp")

    def test_policy_integer_fields_reject_bool_and_float(self):
        for key in ["version", "max_age_seconds", "max_future_seconds"]:
            for value in [True, False, 1.0, "1"]:
                with self.subTest(key=key, value=value):
                    self.manifest, self.policy = fixtures()
                    self.policy[key] = value
                    self.blocked()

    def test_manifest_version_rejects_bool(self):
        self.manifest["version"] = True
        self.blocked("manifest.version: must_be_integer_1")

    def test_policy_bounds_are_enforced(self):
        for key, values in {"max_age_seconds": [0, -1, 31_536_001],
                            "max_future_seconds": [-1, 3601]}.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.manifest, self.policy = fixtures()
                    self.policy[key] = value
                    self.blocked("policy." + key + ": integer_out_of_bounds")

    def test_policy_lists_must_be_nonempty_valid_and_unique(self):
        for key in ["required_checks", "allowed_reviewers", "allowed_licenses"]:
            for value in [[], "tests", [True], ["x", "x"], [""], [{}]]:
                with self.subTest(key=key, value=value):
                    self.manifest, self.policy = fixtures()
                    self.policy[key] = value
                    self.blocked()

    def test_review_must_be_independent_even_if_author_is_allowed(self):
        self.manifest["review"]["reviewer"] = AUTHOR
        self.blocked("review.reviewer: must_be_independent_of_candidate_author")

    def test_review_must_be_by_allowed_identity(self):
        for reviewer in ["other@example.invalid", "Reviewer@example.invalid", [], None]:
            with self.subTest(reviewer=reviewer):
                self.manifest["review"]["reviewer"] = reviewer
                self.blocked("review.reviewer: not_allowed_reviewer")

    def test_rights_require_explicit_allowed_status(self):
        for status in ["unknown", "denied", "", True, 1, None]:
            with self.subTest(status=status):
                self.manifest["rights"]["rights_status"] = status
                self.blocked("rights.rights_status: must_be_explicitly_allowed")

    def test_license_requires_trusted_allowlist(self):
        for license_id in ["UNKNOWN", "", True, None, ["MIT"]]:
            with self.subTest(license_id=license_id):
                self.manifest["rights"]["license_id"] = license_id
                self.blocked("rights.license_id: not_allowed_license")

    def test_rollback_is_mandatory_and_current(self):
        del self.manifest["rollback"]
        self.blocked("manifest: unexpected_or_missing_fields")
        self.manifest, self.policy = fixtures()
        self.manifest["rollback"]["observed_at"] = "2026-10-09T09:00:00Z"
        self.blocked("rollback.observed_at: stale")

    def test_unknown_review_rights_or_rollback_blocks(self):
        for section in ["review", "rights", "rollback"]:
            with self.subTest(section=section):
                self.manifest, self.policy = fixtures()
                self.manifest[section]["status"] = "unknown"
                self.blocked(section + ".status: reported_unknown")

    def test_uri_has_conservative_https_shape(self):
        for uri in ["http://evidence.example.invalid/x", "file:///report", "relative/report",
                    "https://user@example.invalid/x", "https://example.invalid:80/x",
                    "https://example.invalid/x#section", "https://example.invalid/a b",
                    "https://-example.invalid/x", "https://example..invalid/x", "https://[",
                    "https://example.invalid\\report", True, [], None]:
            with self.subTest(uri=uri):
                self.manifest["review"]["evidence_uri"] = uri
                self.blocked("review.evidence_uri: invalid_https_evidence_uri")

    def test_evidence_uri_does_not_verify_content_or_reachability(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            self.assertEqual(self.run_gate()["metadata_gate"], "passed")

    def test_manifest_wrong_shapes_block_without_exception(self):
        for value in [None, True, 1, "manifest", [], {}]:
            with self.subTest(value=value):
                self.manifest = value
                self.blocked()

    def test_nested_wrong_shapes_block_without_exception(self):
        for key in ["candidate", "checks", "review", "rights", "rollback"]:
            for value in [None, True, 1, [], "value", {}]:
                with self.subTest(key=key, value=value):
                    self.manifest, self.policy = fixtures()
                    self.manifest[key] = value
                    self.blocked()

    def test_missing_or_extra_evidence_fields_block(self):
        del self.manifest["checks"]["tests"]["evidence_uri"]
        self.blocked("checks.tests: unexpected_or_missing_fields")
        self.manifest, self.policy = fixtures()
        self.manifest["checks"]["tests"]["allow_unknown"] = True
        self.blocked("checks.tests: unexpected_or_missing_fields")

    def test_policy_unknown_or_missing_fields_block(self):
        self.policy["allow_unknown"] = True
        self.blocked("policy: unexpected_or_missing_fields")
        del self.policy["allow_unknown"]
        del self.policy["required_checks"]
        self.blocked("policy: unexpected_or_missing_fields")

    def test_diagnostics_are_sorted_stable_and_do_not_mutate_inputs(self):
        self.manifest["rights"]["status"] = "unknown"
        self.manifest["checks"]["tests"]["status"] = "failed"
        before = copy.deepcopy((self.manifest, self.policy))
        first = self.blocked()
        self.assertEqual(first, self.run_gate())
        self.assertEqual(first["diagnostics"], sorted(first["diagnostics"]))
        self.assertEqual(before, (self.manifest, self.policy))


class InputAndCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest, self.policy = fixtures()
        self.mp, self.pp = self.root / "manifest.json", self.root / "policy.json"
        self.mp.write_text(json.dumps(self.manifest), encoding="utf-8")
        self.pp.write_text(json.dumps(self.policy), encoding="utf-8")

    def cli(self, extra=None):
        output = io.StringIO()
        with redirect_stdout(output):
            code = gate.main(["--manifest", str(self.mp), "--policy", str(self.pp),
                              "--expected-head", HEAD, "--expected-digest", DIGEST,
                              "--candidate-author", AUTHOR, "--now", NOW.isoformat()] + (extra or []))
        return code, json.loads(output.getvalue())

    def test_duplicate_json_keys_are_rejected(self):
        self.mp.write_text('{"version": 1, "version": 1}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate_json_key"):
            gate.load_json(self.mp)

    def test_nonfinite_json_constants_are_rejected(self):
        for value in ["NaN", "Infinity", "-Infinity"]:
            with self.subTest(value=value):
                self.mp.write_text(value, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "non_finite_json_number"):
                    gate.load_json(self.mp)

    def test_oversized_input_is_rejected(self):
        self.mp.write_bytes(b" " * (gate.MAX_INPUT_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "input_too_large"):
            gate.load_json(self.mp)

    def test_overflowed_json_numbers_are_rejected_at_every_depth(self):
        for value in ("1e999", "-1e999", "1.7976931348623159e308"):
            for raw in (value, '[' + value + ']', '{"nested":[' + value + ']}'):
                with self.subTest(raw=raw):
                    self.mp.write_text(raw, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "non_finite_json_number"):
                        gate.load_json(self.mp)

    def test_finite_json_float_parsing_is_preserved(self):
        raw = '[0.0,-0.0,1.25,-2.5,1e308,-1e308,1e-999,1.7976931348623157e308]'
        self.mp.write_text(raw, encoding="utf-8")
        self.assertEqual(gate.load_json(self.mp), json.loads(raw))

    def test_cli_overflow_in_manifest_or_policy_is_input_error(self):
        for target in (self.mp, self.pp):
            for value in ("1e999", "-1e999"):
                with self.subTest(target=target.name, value=value):
                    before = target.read_text(encoding="utf-8")
                    target.write_text('{"nested":[' + value + ']}', encoding="utf-8")
                    code, report = self.cli()
                    self.assertEqual(code, 2)
                    self.assertEqual(report["metadata_gate"], "blocked")
                    self.assertIs(report["release_authorized"], False)
                    target.write_text(before, encoding="utf-8")

    def test_cli_passes_and_only_reads_inputs(self):
        before = {path: path.read_bytes() for path in self.root.iterdir()}
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            code, report = self.cli()
        self.assertEqual(code, 0)
        self.assertEqual(report["metadata_gate"], "passed")
        self.assertIs(report["release_authorized"], False)
        self.assertEqual(before, {path: path.read_bytes() for path in self.root.iterdir()})

    def test_cli_blocks_unknown_and_exits_one(self):
        self.manifest["rollback"]["status"] = "unknown"
        self.mp.write_text(json.dumps(self.manifest), encoding="utf-8")
        code, report = self.cli()
        self.assertEqual(code, 1)
        self.assertEqual(report["metadata_gate"], "blocked")

    def test_cli_invalid_json_exits_two(self):
        self.mp.write_text("not-json", encoding="utf-8")
        code, report = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(report["metadata_gate"], "blocked")

    def test_cli_invalid_clock_exits_two(self):
        for value in ["2026-10-10", "2026-10-10T09:00:00+00:60", "2026-10-10T09:00:00-00:60"]:
            with self.subTest(value=value):
                code, report = self.cli(["--now", value])
                self.assertEqual(code, 2)
                self.assertEqual(report["metadata_gate"], "blocked")

    def test_cli_unreadable_file_exits_two(self):
        code, report = self.cli(["--manifest", str(self.root / "missing.json")])
        self.assertEqual(code, 2)
        self.assertEqual(report["metadata_gate"], "blocked")


if __name__ == "__main__":
    unittest.main()
