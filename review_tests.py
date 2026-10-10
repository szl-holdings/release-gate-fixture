"""Independent offline boundary checks for the synthetic metadata fixture."""
import copy
import io
import json
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from datetime import timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import release_gate as gate
from test_release_gate import AUTHOR, DIGEST, HEAD, NOW, fixtures


class IndependentReviewTests(unittest.TestCase):
    def evaluate(self, manifest, policy, **overrides):
        args = dict(expected_head=HEAD, expected_digest=DIGEST,
                    candidate_author=AUTHOR, now=NOW)
        args.update(overrides)
        return gate.evaluate(manifest, policy, **args)

    def assert_blocked(self, report):
        self.assertEqual(report['metadata_gate'], 'blocked', report)
        self.assertIs(report['release_authorized'], False)
        self.assertTrue(report['diagnostics'])

    def cli(self, root, manifest_text, policy_text, now=None):
        mp, pp = root / 'manifest.json', root / 'policy.json'
        mp.write_bytes(manifest_text.encode('utf-8') if isinstance(manifest_text, str) else manifest_text)
        pp.write_bytes(policy_text.encode('utf-8') if isinstance(policy_text, str) else policy_text)
        args = ['--manifest', str(mp), '--policy', str(pp),
                '--expected-head', HEAD, '--expected-digest', DIGEST,
                '--candidate-author', AUTHOR, '--now', now or NOW.isoformat()]
        out = io.StringIO()
        with redirect_stdout(out):
            code = gate.main(args)
        return code, json.loads(out.getvalue())

    def test_timestamp_offset_minutes_must_not_normalize(self):
        for value in ['2026-10-10T10:00:00+00:60',
                      '2026-10-10T08:00:00-00:60',
                      '2026-10-10T10:39:00+00:99']:
            with self.subTest(value=value):
                manifest, policy = fixtures()
                manifest['review']['observed_at'] = value
                report = self.evaluate(manifest, policy)
                self.assert_blocked(report)
                self.assertIn('review.observed_at: invalid_timezone_aware_timestamp', report['diagnostics'])

    def test_timezone_extremes_and_unknown_zone_fail_closed(self):
        for value in ['0001-01-01T00:00:00+23:59',
                      '9999-12-31T23:59:59-23:59',
                      '2026-10-10T09:00:00-00:00',
                      '2026-10-10T09:00:00+24:00']:
            with self.subTest(value=value):
                manifest, policy = fixtures()
                manifest['rollback']['observed_at'] = value
                self.assert_blocked(self.evaluate(manifest, policy))

    def test_full_age_limit_and_clock_offsets(self):
        manifest, policy = fixtures()
        policy['max_age_seconds'] = 31_536_000
        manifest['rollback']['observed_at'] = (NOW - timedelta(seconds=31_536_000)).isoformat()
        shifted_clock = NOW.astimezone(timezone(timedelta(hours=-7)))
        self.assertEqual(self.evaluate(manifest, policy, now=shifted_clock)['metadata_gate'], 'passed')
        manifest['rollback']['observed_at'] = (NOW - timedelta(seconds=31_536_000, microseconds=1)).isoformat()
        self.assert_blocked(self.evaluate(manifest, policy, now=shifted_clock))

    def test_every_record_rejects_wrong_json_leaf_types(self):
        values = [None, False, True, 0, 1, 1.0, [], {}, '']
        paths = [('candidate',), ('checks', 'tests'), ('checks', 'build'),
                 ('review',), ('rights',), ('rollback',)]
        for path in paths:
            initial, _ = fixtures()
            target = initial
            for part in path:
                target = target[part]
            for field in target:
                for value in values:
                    with self.subTest(path=path, field=field, value=value):
                        manifest, policy = fixtures()
                        target = manifest
                        for part in path:
                            target = target[part]
                        target[field] = copy.deepcopy(value)
                        self.assert_blocked(self.evaluate(manifest, policy))

    def test_every_record_unknown_is_blocked(self):
        for path in [('checks', 'tests'), ('checks', 'build'), ('review',), ('rights',), ('rollback',)]:
            manifest, policy = fixtures()
            target = manifest
            for part in path:
                target = target[part]
            target['status'] = 'unknown'
            self.assert_blocked(self.evaluate(manifest, policy))

    def test_policy_root_and_nested_types_fail_closed(self):
        for value in [None, False, 1, 1.0, 'policy', [], {}]:
            manifest, _ = fixtures()
            self.assert_blocked(self.evaluate(manifest, value))
        for key in ['required_checks', 'allowed_reviewers', 'allowed_licenses']:
            for value in [None, False, 1, {}, [None], [['x']], [{'x': 'x'}], ['x', 'x']]:
                with self.subTest(key=key, value=value):
                    manifest, policy = fixtures()
                    policy[key] = value
                    self.assert_blocked(self.evaluate(manifest, policy))

    def test_manifest_cannot_supply_trusted_policy_or_pins(self):
        for key, value in [('policy', {'required_checks': []}), ('expected_head', HEAD),
                           ('expected_digest', DIGEST), ('candidate_author', AUTHOR)]:
            manifest, policy = fixtures()
            manifest[key] = value
            self.assert_blocked(self.evaluate(manifest, policy))
        manifest, policy = fixtures()
        manifest['candidate']['author'] = manifest['review']['reviewer']
        self.assert_blocked(self.evaluate(manifest, policy))

    def test_nested_and_escaped_duplicate_json_keys_rejected(self):
        for raw in ['{"a":{"x":1,"x":2}}', '{"a":{"x":1,"\\u0078":2}}',
                    '{"a":[{"status":"passed","status":"unknown"}]}']:
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'duplicates.json'
                path.write_text(raw, encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'duplicate_json_key'):
                    gate.load_json(path)

    def test_cli_json_roots_cannot_be_coerced(self):
        manifest, policy = fixtures()
        with tempfile.TemporaryDirectory() as directory:
            for value in [None, False, True, 0, 1, 1.0, 'manifest', [], {}]:
                for where in ['manifest', 'policy']:
                    with self.subTest(where=where, value=value):
                        code, report = self.cli(Path(directory),
                            json.dumps(value if where == 'manifest' else manifest),
                            json.dumps(value if where == 'policy' else policy))
                        self.assertEqual(code, 1)
                        self.assert_blocked(report)

    def test_cli_bad_encoding_deep_json_and_nonfinite_block(self):
        _, policy = fixtures()
        cases = [b'\xff', b'\xef\xbb\xbf{}', '{} trailing',
                 'NaN', 'Infinity', '-Infinity', '{"version":1,"version":1}']
        with tempfile.TemporaryDirectory() as directory:
            for value in cases:
                with self.subTest(value=repr(value)[:80]):
                    code, report = self.cli(Path(directory), value, json.dumps(policy))
                    self.assertEqual(code, 2)
                    self.assert_blocked(report)
            code, report = self.cli(Path(directory), '[' * 2000 + '0' + ']' * 2000, json.dumps(policy))
            self.assertIn(code, (1, 2))  # Schema or decoder-depth rejection are both fail-closed.
            self.assert_blocked(report)

    def test_input_byte_limit_is_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'boundary.json'
            path.write_bytes(b'{}' + b' ' * (gate.MAX_INPUT_BYTES - 2))
            self.assertEqual(gate.load_json(path), {})
            path.write_bytes(b'{}' + b' ' * (gate.MAX_INPUT_BYTES - 1))
            with self.assertRaisesRegex(ValueError, 'input_too_large'):
                gate.load_json(path)

    def test_cli_rejects_invalid_offset_clock(self):
        manifest, policy = fixtures()
        with tempfile.TemporaryDirectory() as directory:
            code, report = self.cli(Path(directory), json.dumps(manifest), json.dumps(policy),
                                    now='2026-10-10T10:00:00+00:60')
            self.assertEqual(code, 2)
            self.assert_blocked(report)

    def test_cli_uses_read_modes_without_network_or_process_calls(self):
        manifest, policy = fixtures()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mp, pp = root / 'manifest.json', root / 'policy.json'
            mp.write_text(json.dumps(manifest), encoding='utf-8')
            pp.write_text(json.dumps(policy), encoding='utf-8')
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            modes = []
            real_open = Path.open
            def readonly_open(path, mode='r', *args, **kwargs):
                modes.append(mode)
                self.assertNotIn('+', mode)
                self.assertFalse(any(char in mode for char in 'wax'))
                return real_open(path, mode, *args, **kwargs)
            with ExitStack() as stack:
                stack.enter_context(patch.object(Path, 'open', readonly_open))
                for target in ['socket.socket', 'socket.create_connection', 'subprocess.Popen', 'os.system']:
                    stack.enter_context(patch(target, side_effect=AssertionError('external action forbidden')))
                output = io.StringIO()
                with redirect_stdout(output):
                    code = gate.main(['--manifest', str(mp), '--policy', str(pp),
                        '--expected-head', HEAD, '--expected-digest', DIGEST,
                        '--candidate-author', AUTHOR, '--now', NOW.isoformat()])
            self.assertEqual(code, 0)
            self.assertEqual(modes, ['rb', 'rb'])
            self.assertIs(json.loads(output.getvalue())['release_authorized'], False)
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})


if __name__ == '__main__':
    unittest.main()
