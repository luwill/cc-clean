"""Behavioral checks on synthetic fixtures only; artifacts retained, no deletion."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

WORK = Path(__file__).resolve().parent
sys.path.insert(0, str(WORK / 'cc-clean/scripts'))
spec = importlib.util.spec_from_file_location('local_state', WORK / 'cc-clean/scripts/local_state.py')
guard = importlib.util.module_from_spec(spec)
sys.modules['local_state'] = guard
spec.loader.exec_module(guard)


class LocalStateTests(unittest.TestCase):
    def setUp(self):
        parent = WORK / 'test-artifacts'
        parent.mkdir(exist_ok=True)
        self.base = Path(tempfile.mkdtemp(prefix='case-', dir=parent))
        self.config = self.base / '.claude'
        self.config.mkdir(mode=0o700)
        (self.config / 'skills').mkdir()
        (self.config / 'skills/example.md').write_text('keep this skill\n')
        (self.config / 'plugins').mkdir()
        (self.config / 'plugins/plugin.json').write_text('{"enabled":true}\n')
        (self.config / 'telemetry').mkdir()
        (self.config / 'telemetry/failed.json').write_text('{"event_name":"synthetic"}\n')
        (self.config / 'history.jsonl').write_text('{"display":"synthetic history"}\n')
        (self.config / '.credentials.json').write_text('{"claudeAiOauth":{"accessToken":"SYNTHETIC_TOKEN_DO_NOT_PRINT"},"mcpOAuth":{"keep":true}}')
        os.chmod(self.config / '.credentials.json', 0o600)
        self.state = self.base / '.claude.json'
        self.state.write_text(json.dumps({'oauthAccount': {'emailAddress': 'synthetic@example.invalid'},
                                         'userID': 'SYNTHETIC_ID_DO_NOT_PRINT', 'projects': {'/synthetic/project': {}},
                                         'mcpServers': {'local': {'command': 'example'}}}))
        os.chmod(self.state, 0o600)
        self.roots = {'default': self.config, 'state': self.state}

    def new_backup(self):
        dest = self.base / 'backup'
        guard.backup(self.roots, dest)
        return dest

    def test_audit_has_no_secret_values_or_history_content(self):
        report = self.base / 'audit.json'
        before = guard.snapshot(self.roots, hashed=True)
        result = guard.audit(self.roots, report, str(self.state))
        text = report.read_text()
        self.assertNotIn('SYNTHETIC_TOKEN_DO_NOT_PRINT', text)
        self.assertNotIn('SYNTHETIC_ID_DO_NOT_PRINT', text)
        self.assertNotIn('synthetic@example.invalid', text)
        self.assertNotIn('synthetic history', text)
        self.assertEqual(result['status'], 'audit_written')
        self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
        self.assertEqual(guard.snapshot(self.roots, hashed=True), before)

    def test_audit_does_not_open_history_or_credentials(self):
        original = os.open
        opened = []
        def track(path, *args, **kwargs):
            opened.append(str(path))
            return original(path, *args, **kwargs)
        with patch.object(guard.os, 'open', side_effect=track):
            guard.audit(self.roots, self.base / 'audit.json', str(self.state))
        self.assertFalse(any(p.endswith('history.jsonl') or p.endswith('.credentials.json') for p in opened))

    def test_feature_cache_is_reported_for_review_without_marking_deletion(self):
        value = json.loads(self.state.read_text())
        value['cachedGrowthBookFeatures'] = {'sensitive-internal-value': 'DO_NOT_PRINT_CACHE_CONTENT'}
        value['unknownFutureField'] = 'DO_NOT_PRINT_UNKNOWN_CONTENT'
        self.state.write_text(json.dumps(value))
        before = guard.snapshot(self.roots, hashed=True)
        guard.audit(self.roots, self.base / 'audit.json', str(self.state))
        report = guard.safe_json(self.base / 'audit.json')
        self.assertIn('cachedGrowthBookFeatures', report['state']['cache_keys_present'])
        self.assertEqual(report['state']['unclassified_top_level_key_count'], 1)
        self.assertNotIn('DO_NOT_PRINT_CACHE_CONTENT', (self.base / 'audit.json').read_text())
        self.assertNotIn('DO_NOT_PRINT_UNKNOWN_CONTENT', (self.base / 'audit.json').read_text())
        self.assertEqual(guard.snapshot(self.roots, hashed=True), before)

    def test_excluded_gateway_not_included(self):
        gateway = self.base / '.claude-gateway'
        gateway.mkdir()
        (gateway / 'settings.json').write_text('keep independently')
        guard.audit(self.roots, self.base / 'audit.json')
        self.assertNotIn('.claude-gateway', (self.base / 'audit.json').read_text())

    def test_external_and_broken_symlinks_not_followed_and_preserved(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'outside-secret').write_text('OUTSIDE_DATA_NOT_IN_BACKUP')
        (self.config / 'skills/shared').symlink_to(outside, target_is_directory=True)
        (self.config / 'broken').symlink_to(self.base / 'does-not-exist')
        dest = self.new_backup()
        self.assertEqual(os.readlink(dest / 'copies/default/skills/shared'), str(outside))
        self.assertEqual(os.readlink(dest / 'copies/default/broken'), str(self.base / 'does-not-exist'))
        manifest = (dest / 'manifest.json').read_text()
        self.assertNotIn('outside-secret', manifest)
        self.assertEqual(guard.verify(dest, check_source=True)['symlinks'], 2)

    def test_symlink_root_is_rejected(self):
        link = self.base / 'alias'
        link.symlink_to(self.config, target_is_directory=True)
        with self.assertRaises(guard.GuardError):
            guard.parse_roots([f'default={link}'])

    def test_output_inside_source_is_rejected(self):
        with self.assertRaises(guard.GuardError):
            guard.audit(self.roots, self.config / 'audit.json')
        self.assertFalse((self.config / 'audit.json').exists())

    def test_output_symlink_parent_is_rejected(self):
        link = self.base / 'outlink'
        link.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(guard.GuardError):
            guard.audit(self.roots, link / 'audit.json')
        self.assertFalse((self.base / 'audit.json').exists())

    def test_invalid_state_json_does_not_echo_input(self):
        self.state.write_text('INVALID_PRIVATE_CONTENT')
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = guard.main(['audit', '--root', f'state={self.state}', '--state-file', str(self.state),
                                 '--output', str(self.base / 'audit.json')])
        self.assertEqual(result, 2)
        self.assertNotIn('INVALID_PRIVATE_CONTENT', stdout.getvalue() + stderr.getvalue())
        self.assertFalse((self.base / 'audit.json').exists())

    def test_missing_source_is_reported_but_not_backed_up(self):
        roots = guard.parse_roots([f'absent={self.base / "absent"}'], allow_missing=True)
        self.assertEqual(guard.audit(roots, self.base / 'audit.json')['missing_roots'], 1)
        with self.assertRaises(guard.GuardError):
            guard.backup(roots, self.base / 'backup')
        self.assertFalse((self.base / 'backup').exists())

    def test_backup_restores_contents_and_basic_permissions(self):
        before = guard.snapshot(self.roots, hashed=True)
        dest = self.new_backup()
        self.assertEqual(guard.snapshot(self.roots, hashed=True), before)
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((dest / 'manifest.json').stat().st_mode), 0o600)
        self.assertEqual((dest / 'copies/state').read_bytes(), self.state.read_bytes())
        self.assertEqual(stat.S_IMODE((dest / 'copies/state').stat().st_mode), 0o600)
        result = guard.verify(dest, check_source=True)
        self.assertEqual(result['status'], 'backup_verified')
        self.assertEqual(result['restore_samples'], 2)
        receipt = guard.safe_json(dest / 'verified.json')
        self.assertEqual(receipt['restore_samples'][0]['root'], 'state')
        self.assertEqual(receipt['restore_samples'][0]['path'], '.')
        self.assertEqual((dest / 'restore-samples/sample-1.bin').read_bytes(), self.state.read_bytes())
        self.assertFalse(guard.safe_json(dest / 'verified.json')['acl_xattr_contents_independently_verified'])

    def test_backup_verification_survives_intentional_later_source_change(self):
        dest = self.new_backup()
        self.state.write_text('{"new":"source"}')
        self.assertEqual(guard.verify(dest)['status'], 'backup_verified')
        with self.assertRaises(guard.GuardError):
            guard.verify(dest, check_source=True)

    def test_backup_content_tampering_is_rejected(self):
        dest = self.new_backup()
        (dest / 'copies/state').write_text('tampered')
        with self.assertRaises(guard.GuardError):
            guard.verify(dest)

    def test_backup_added_file_is_rejected(self):
        dest = self.new_backup()
        (dest / 'copies/default/new-file').write_text('unexpected')
        with self.assertRaises(guard.GuardError):
            guard.verify(dest)

    def test_manifest_tampering_is_rejected(self):
        dest = self.new_backup()
        manifest = guard.safe_json(dest / 'manifest.json')
        manifest['trees']['state']['entries']['.']['bytes'] += 1
        (dest / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaises(guard.GuardError):
            guard.verify(dest)

    def test_existing_destination_is_not_overwritten(self):
        dest = self.base / 'backup'
        dest.mkdir()
        (dest / 'original').write_text('keep')
        with self.assertRaises(guard.GuardError):
            guard.backup(self.roots, dest)
        self.assertEqual((dest / 'original').read_text(), 'keep')

    def test_overlapping_roots_are_rejected(self):
        with self.assertRaises(guard.GuardError):
            guard.parse_roots([f'default={self.config}', f'inner={self.config / "history.jsonl"}'])

    def test_parent_traversal_and_duplicate_labels_are_rejected(self):
        with self.assertRaises(guard.GuardError):
            guard.parse_roots([f'default={self.base}/../outside'])
        with self.assertRaises(guard.GuardError):
            guard.parse_roots([f'default={self.config}', f'default={self.state}'])

    def test_special_file_refused_without_opening(self):
        os.mkfifo(self.config / 'pipe')
        with self.assertRaises(guard.GuardError):
            guard.audit(self.roots, self.base / 'audit.json')

    def test_source_change_during_copy_never_marks_backup_verified(self):
        original = guard.copy_root
        def change(source, destination):
            result = original(source, destination)
            if source == self.state:
                self.state.write_text('{"changed":"during copy"}')
            return result
        with patch.object(guard, 'copy_root', side_effect=change):
            with self.assertRaises(guard.GuardError):
                guard.backup(self.roots, self.base / 'backup')
        self.assertFalse((self.base / 'backup/verified.json').exists())
        self.assertTrue((self.base / 'backup/started.json').is_file())

    def test_recovery_sample_tampering_is_rejected(self):
        dest = self.new_backup()
        (dest / 'restore-samples/sample-1.bin').write_text('tampered')
        with self.assertRaises(guard.GuardError):
            guard.verify(dest)

    def test_credentials_cannot_be_parsed_as_main_state(self):
        with self.assertRaises(guard.GuardError):
            guard.audit(self.roots, self.base / 'audit.json', str(self.config / '.credentials.json'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
