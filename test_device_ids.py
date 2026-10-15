"""Device-ID metadata checks use fictional state only; never delete test artifacts."""
import copy
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import test_local_state as fixtures
import review_tools as review

guard = fixtures.guard
DEVICE_VALUES = ('FICTIONAL_DEVICE_CAMEL_DO_NOT_EMIT', 'FICTIONAL_DEVICE_SNAKE_DO_NOT_EMIT',
                 'FICTIONAL_DEVICE_CAPITAL_DO_NOT_EMIT')


class DeviceIdTests(unittest.TestCase):
    setUp = fixtures.LocalStateTests.setUp

    def write_state(self, data):
        self.state.write_text(json.dumps(data))

    def audit(self, data=None):
        if data is not None:
            self.write_state(data)
        path = self.base / 'audit.json'
        guard.audit(self.roots, path, str(self.state))
        return path, guard.safe_json(path)

    def resolve(self, data, location):
        """Resolve structural locations locally without exposing user-defined keys."""
        key = None
        for part in location:
            if 'object_key_index' in part:
                key = list(data)[part['object_key_index']]
                data = data[key]
            else:
                key = part['array_index']
                data = data[key]
        return key, data

    def test_all_three_top_level_spellings_are_recognized_without_values(self):
        path, audit = self.audit(dict(zip(guard.DEVICE_ID_KEYS, DEVICE_VALUES)))
        state = audit['state']
        self.assertEqual(state['identity_keys_present'], list(guard.DEVICE_ID_KEYS))
        self.assertEqual(state['device_id_field_count'], 3)
        self.assertEqual(state['unclassified_top_level_key_count'], 0)
        self.assertEqual({r['field'] for r in state['device_id_fields']}, set(guard.DEVICE_ID_KEYS))
        for value in DEVICE_VALUES:
            self.assertNotIn(value, path.read_text())

    def test_nested_objects_and_arrays_have_locally_resolvable_locations(self):
        data = {'container': {'deep': [{'other': 'keep'}, {'device_id': DEVICE_VALUES[0]}]},
                'second': [[{'deviceID': DEVICE_VALUES[1]}]], 'deviceId': {'device_id': DEVICE_VALUES[2]}}
        _, audit = self.audit(data)
        rows = audit['state']['device_id_fields']
        self.assertEqual(len(rows), 4)
        self.assertEqual([r['field'] for r in rows], ['device_id', 'deviceID', 'deviceId', 'device_id'])
        for row in rows:
            key, value = self.resolve(data, row['location'])
            self.assertEqual(key, row['field'])
            self.assertIn(type(value), (str, dict))
            self.assertIs(row['present'], True)
            self.assertIs(row['value_recorded'], False)
            self.assertIs(row['preserve'], True)
            self.assertEqual(row['ownership'], 'unverified')

    def test_same_named_fields_in_siblings_keep_distinct_locations(self):
        data = {'outer': [{'deviceID': DEVICE_VALUES[0]}, {'deviceID': DEVICE_VALUES[1]}]}
        _, audit = self.audit(data)
        locations = [r['location'] for r in audit['state']['device_id_fields']]
        self.assertEqual(len(locations), 2)
        self.assertNotEqual(locations[0], locations[1])
        self.assertEqual([self.resolve(data, p)[1] for p in locations], list(DEVICE_VALUES[:2]))

    def test_identifier_email_path_and_markup_in_ancestor_keys_are_never_output(self):
        keys = ['FICTIONAL_ANCESTOR_DEVICE_ID', 'fictional-owner@example.invalid',
                '/private/fictional/account/path', '<svg onload=globalThis.XSS=1>']
        data = {'device_id': DEVICE_VALUES[0]}
        for key in keys:
            data = {key: data}
        path, audit = self.audit(data)
        html = self.base / 'report.html'
        review.render_report(guard, str(path), html)
        for text in [path.read_text(), html.read_text()]:
            for value in keys + list(DEVICE_VALUES):
                self.assertNotIn(value, text)
        row = audit['state']['device_id_fields'][0]
        self.assertEqual(len(row['location']), 5)
        self.assertEqual(self.resolve(data, row['location'])[1], DEVICE_VALUES[0])

    def test_presence_does_not_imply_a_nonempty_or_valid_identifier(self):
        values = [None, '', False, 12345678901234567890, {}, []]
        data = {'items': [{'deviceId': value} for value in values]}
        path, audit = self.audit(data)
        rows = audit['state']['device_id_fields']
        self.assertEqual([r['value_type'] for r in rows], ['null', 'string', 'boolean', 'number', 'object', 'array'])
        self.assertTrue(all(r['present'] for r in rows))
        self.assertNotIn('12345678901234567890', path.read_text())
        self.assertTrue(audit['state']['device_id_scan_complete'])

    def test_names_are_exact_and_strings_are_not_parsed_as_nested_json(self):
        data = {'deviceid': 'wrong-case', 'DeviceId': 'wrong-case', 'device_id_backup': 'different-field',
                'text': '{"device_id":"FICTIONAL_EMBEDDED_DO_NOT_EMIT"}',
                'base64': 'eyJkZXZpY2VfaWQiOiJmaWN0aW9uYWwifQ=='}
        _, audit = self.audit(data)
        self.assertEqual(audit['state']['device_id_fields'], [])
        self.assertEqual(audit['state']['device_id_field_count'], 0)
        self.assertTrue(audit['state']['device_id_scan_complete'])

    def test_recursive_detection_does_not_open_other_payloads_or_change_source(self):
        self.write_state({'nested': [{'device_id': DEVICE_VALUES[0]}]})
        (self.config / 'telemetry/failed.json').write_text('{"deviceID":"FICTIONAL_TELEMETRY_PRIVATE"}')
        before = guard.snapshot(self.roots, hashed=True)
        original = guard.os.open
        source_reads = []
        def track(path, *args, **kwargs):
            value = Path(path)
            if value == self.state or self.config in value.parents:
                source_reads.append(value)
                self.assertEqual(value, self.state)
                self.assertFalse(args[0] & (os.O_RDWR | os.O_WRONLY))
            return original(path, *args, **kwargs)
        with patch.object(guard.os, 'open', side_effect=track):
            path, audit = self.audit()
        self.assertEqual(source_reads, [self.state])
        self.assertNotIn('FICTIONAL_TELEMETRY_PRIVATE', path.read_text())
        self.assertEqual(before, guard.snapshot(self.roots, hashed=True))
        self.assertFalse(audit['history_content_read'])
        self.assertFalse(audit['credentials_payload_read'])
        self.assertFalse(audit['source_changed_by_tool'])

    def test_state_parsing_still_requires_explicit_selection(self):
        self.write_state({'deviceID': DEVICE_VALUES[0]})
        path = self.base / 'audit.json'
        with patch.object(guard, 'safe_json', side_effect=AssertionError('no state parse without --state-file')):
            guard.audit(self.roots, path)
        self.assertNotIn('state', json.loads(path.read_text()))
        self.assertNotIn(DEVICE_VALUES[0], path.read_text())

    def test_missing_selected_state_does_not_claim_a_completed_scan(self):
        missing = self.base / 'absent' / '.claude.json'
        roots = {'state': missing}
        path = self.base / 'audit.json'
        guard.audit(roots, path, str(missing))
        state = guard.safe_json(path)['state']
        self.assertEqual(state, {'missing': True})
        html = self.base / 'report.html'
        review.render_report(guard, str(path), html)
        payload = json.loads(re.search(r'<script id="data" type="application/json">([\s\S]*?)</script>', html.read_text())[1])
        self.assertNotIn('device_id_scan_complete', payload['state'])

    def test_duplicate_json_keys_refuse_scan_without_exposing_values(self):
        self.state.write_text('{"outer":{"device_id":"FICTIONAL_FIRST","device_id":"FICTIONAL_LAST"}}')
        stdout, stderr = io.StringIO(), io.StringIO()
        path = self.base / 'audit.json'
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = guard.main(['audit', '--root', f'state={self.state}', '--state-file', str(self.state), '--output', str(path)])
        self.assertEqual(code, 2)
        self.assertFalse(path.exists())
        self.assertNotIn('FICTIONAL_FIRST', stdout.getvalue() + stderr.getvalue())
        self.assertNotIn('FICTIONAL_LAST', stdout.getvalue() + stderr.getvalue())

    def test_deep_traversal_does_not_use_python_recursion(self):
        data = {'deviceID': DEVICE_VALUES[0]}
        for _ in range(1500):
            data = {'outer': [data]}
        rows = guard.device_id_fields(data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]['location']), 3001)
        self.assertEqual(self.resolve(data, rows[0]['location'])[1], DEVICE_VALUES[0])

    def test_json_decoder_recursion_failure_is_sanitized_and_never_a_clean_scan(self):
        self.state.write_text('{"outer":"FICTIONAL_TOO_DEEP"}')
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(guard.json, 'loads', side_effect=RecursionError('FICTIONAL_TOO_DEEP')), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = guard.main(['audit', '--root', f'state={self.state}', '--state-file', str(self.state),
                               '--output', str(self.base / 'audit.json')])
        self.assertEqual(code, 2)
        self.assertNotIn('FICTIONAL_TOO_DEEP', stdout.getvalue() + stderr.getvalue())
        self.assertFalse((self.base / 'audit.json').exists())

    def test_cli_and_html_keep_values_private_and_write_only_new_reports(self):
        self.write_state({'outer': [{'device_id': DEVICE_VALUES[1], 'deviceID': DEVICE_VALUES[2]}]})
        original = self.state.read_bytes()
        helper = fixtures.WORK / 'cc-clean/scripts/local_state.py'
        path, html = self.base / 'audit.json', self.base / 'report.html'
        first = subprocess.run([sys.executable, '-B', str(helper), 'audit', '--root', f'state={self.state}',
                                '--state-file', str(self.state), '--output', str(path)], capture_output=True, text=True, timeout=20)
        self.assertEqual(first.returncode, 0)
        second = subprocess.run([sys.executable, '-B', str(helper), 'report', '--audit', str(path),
                                 '--output', str(html)], capture_output=True, text=True, timeout=20)
        self.assertEqual(second.returncode, 0)
        outputs = first.stdout + first.stderr + second.stdout + second.stderr + path.read_text() + html.read_text()
        for value in DEVICE_VALUES:
            self.assertNotIn(value, outputs)
        self.assertIn('device_id_scan_complete', html.read_text())
        self.assertIn('deviceID', html.read_text())
        self.assertEqual(self.state.read_bytes(), original)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(html.stat().st_mode & 0o777, 0o600)

    def test_legacy_audit_without_device_summary_still_renders(self):
        path, audit = self.audit({'deviceId': DEVICE_VALUES[0]})
        state = audit['state']
        for key in ['device_id_fields', 'device_id_field_count', 'device_id_scan_scope', 'device_id_scan_complete']:
            state.pop(key)
        path.write_text(json.dumps(audit))
        html = self.base / 'report.html'
        self.assertEqual(review.render_report(guard, str(path), html)['status'], 'readonly_report_written')

    def test_report_rejects_values_hidden_in_device_metadata(self):
        path, audit = self.audit({'deviceId': DEVICE_VALUES[0]})
        variants = []
        for key, value in [('value', DEVICE_VALUES[0]), ('value_sha256', 'a' * 64), ('raw_parent_key', DEVICE_VALUES[0])]:
            bad = copy.deepcopy(audit)
            bad['state']['device_id_fields'][0][key] = value
            variants.append(bad)
        bad = copy.deepcopy(audit)
        bad['state']['device_id_fields'][0]['location'] = [{'object_key_index': DEVICE_VALUES[0]}]
        variants.append(bad)
        for index, bad in enumerate(variants):
            path.write_text(json.dumps(bad))
            output = self.base / f'refused-{index}.html'
            with self.subTest(index=index), self.assertRaises(guard.GuardError):
                review.render_report(guard, str(path), output)
            self.assertFalse(output.exists())

    def test_report_rejects_cleanup_authorization_and_invalid_location_metadata(self):
        path, audit = self.audit({'device_id': DEVICE_VALUES[0]})
        rows = []
        for key, value in [('preserve', False), ('value_recorded', True), ('ownership', 'old-account'),
                           ('present', False), ('field', 'unknown'), ('value_type', 'secret')]:
            bad = copy.deepcopy(audit)
            bad['state']['device_id_fields'][0][key] = value
            rows.append(bad)
        for location in [[], [{'array_index': 0}], [{'object_key_index': -1}], [{'object_key_index': True}],
                         [{'key': 'private-parent'}], [{'object_key_index': 0, 'array_index': 0}]]:
            bad = copy.deepcopy(audit)
            bad['state']['device_id_fields'][0]['location'] = location
            rows.append(bad)
        for index, bad in enumerate(rows):
            path.write_text(json.dumps(bad))
            with self.subTest(index=index), self.assertRaises(guard.GuardError):
                review.render_report(guard, str(path), self.base / f'refused-{index}.html')

    def test_report_rejects_incomplete_counts_duplicate_locations_and_false_scope(self):
        path, audit = self.audit({'device_id': DEVICE_VALUES[0]})
        rows = []
        for key, value in [('device_id_field_count', 2), ('device_id_field_count', True),
                           ('device_id_scan_complete', False), ('device_id_scan_scope', 'whole-machine'), ('missing', True)]:
            bad = copy.deepcopy(audit)
            bad['state'][key] = value
            rows.append(bad)
        bad = copy.deepcopy(audit)
        bad['state'].pop('device_id_fields')
        rows.append(bad)
        bad = copy.deepcopy(audit)
        bad['state']['device_id_fields'].append(copy.deepcopy(bad['state']['device_id_fields'][0]))
        bad['state']['device_id_field_count'] = 2
        rows.append(bad)
        for index, bad in enumerate(rows):
            path.write_text(json.dumps(bad))
            with self.subTest(index=index), self.assertRaises(guard.GuardError):
                review.render_report(guard, str(path), self.base / f'refused-{index}.html')


if __name__ == '__main__':
    unittest.main(verbosity=2)
