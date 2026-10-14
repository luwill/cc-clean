"""New behavior checked on fictional files only. No fixture deletion or live environment access."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import test_local_state as fixtures
guard = fixtures.guard
import review_tools as review

SESSION = '12345678-1234-1234-1234-123456789abc'
SECOND = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


class ReviewTests(unittest.TestCase):
    setUp = fixtures.LocalStateTests.setUp
    new_backup = fixtures.LocalStateTests.new_backup

    def fixture(self, env=False):
        project = self.config / 'projects/-synthetic-a-b'
        project.mkdir(parents=True)
        (project / (SESSION + '.jsonl')).write_text('SESSION_PRIVATE_BODY_NOT_READ')
        history = self.config / 'file-history' / SESSION
        history.mkdir(parents=True)
        (history / 'snapshot').write_text('HISTORY_PRIVATE_BODY_NOT_READ')
        debug = self.config / 'debug'
        debug.mkdir()
        (debug / (SESSION + '.txt')).write_text('DEBUG_PRIVATE_BODY_NOT_READ')
        todos = self.config / 'todos'
        todos.mkdir()
        (todos / (SESSION + '-agent-agent1.json')).write_text('{}')
        if env:
            (self.config / 'session-env' / SESSION).mkdir(parents=True)
        return project

    def audit(self):
        output = self.base / 'audit.json'
        guard.audit(self.roots, output, str(self.state))
        return output

    def pair(self):
        old = self.base / 'old'
        guard.backup(self.roots, old)
        self.state.write_text('{"new_account":"fictional"}')
        current = self.base / 'current'
        guard.backup(self.roots, current)
        plan = self.base / 'restore-plan.json'
        review.prepare_restore(guard, old, current, ['state:.'], plan)
        return old, current, plan

    def restore_fictional_state(self, old):
        self.state.write_bytes((old / 'copies/state').read_bytes())
        os.chmod(self.state, 0o600)

    def test_missing_env_is_related_and_preserved(self):
        self.fixture()
        graph = guard.safe_json(self.audit())['relationships']
        group = graph['groups'][0]
        self.assertTrue(group['project_session_present'])
        self.assertFalse(group['session_env_present'])
        self.assertEqual({i['role'] for i in group['items']}, {'project-session', 'file-history', 'debug', 'todos'})
        self.assertFalse(group['cleanup_authorized'])
        self.assertEqual(group['review_status'], 'preserve')
        self.assertNotIn('PRIVATE_BODY', (self.base / 'audit.json').read_text())

    def test_graph_only_scans_metadata_and_never_follows_links(self):
        self.fixture()
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'SECRET_NAME').write_text('secret')
        (self.config / 'session-env').mkdir()
        (self.config / 'session-env' / SESSION).symlink_to(outside, target_is_directory=True)
        with patch.object(guard, 'file_digest', side_effect=AssertionError('audit must not hash')):
            graph = guard.safe_json(self.audit())['relationships']
        self.assertFalse(graph['groups'][0]['session_env_present'])
        self.assertTrue(any(i['kind'] == 'symlink' for i in graph['unresolved']))
        self.assertNotIn('SECRET_NAME', (self.base / 'audit.json').read_text())

    def test_same_uuid_in_two_roots_is_not_cross_correlated(self):
        self.fixture(env=True)
        other = self.base / 'other'
        (other / 'file-history' / SESSION).mkdir(parents=True)
        trees = guard.snapshot({'default': self.config, 'other': other})
        groups = review.relationships(trees)['groups']
        self.assertEqual(len(groups), 2)
        self.assertEqual({g['root'] for g in groups}, {'default', 'other'})
        self.assertFalse(next(g for g in groups if g['root'] == 'other')['project_session_present'])

    def test_colliding_project_labels_are_not_decoded(self):
        project = self.fixture()
        (project / (SECOND + '.jsonl')).write_text('same encoded project may represent distinct paths')
        graph = guard.safe_json(self.audit())['relationships']
        self.assertEqual(len(graph['groups']), 2)
        self.assertTrue(all(g['project_directory_labels'] == ['-synthetic-a-b'] for g in graph['groups']))
        self.assertTrue(all('真实项目路径未验证' in g['unverified_reason'] for g in graph['groups']))

    def test_duplicate_uuid_in_two_project_labels_is_flagged(self):
        self.fixture()
        other = self.config / 'projects/-synthetic-other'
        other.mkdir()
        (other / (SESSION + '.jsonl')).write_text('duplicate identifier')
        group = guard.safe_json(self.audit())['relationships']['groups'][0]
        self.assertEqual(len(group['project_directory_labels']), 2)
        self.assertIn('不能推定单一归属', group['unverified_reason'])

    def test_report_escapes_xss_masks_identity_and_does_not_probe_source(self):
        self.fixture()
        audit_file = self.audit()
        data = guard.safe_json(audit_file)
        attack = 'odd-</script><script>globalThis.XSS_EXECUTED=1</script>'
        data['trees']['default']['entries'][attack] = {'kind': 'file', 'bytes': 1}
        data['trees']['default']['entries']['synthetic@example.invalid-sk-proj-FICTIONAL123456789'] = {'kind': 'file', 'bytes': 1}
        data['roots']['default'] = '/Users/fictional/private/.claude'
        data['roots']['state'] = '/Users/fictional/private/.claude.json'
        audit_file.write_text(json.dumps(data))
        output = self.base / 'report.html'
        original = guard.no_symlink_parents
        probed = []
        def track(path, *args, **kwargs):
            probed.append(str(path))
            return original(path, *args, **kwargs)
        with patch.object(guard, 'no_symlink_parents', side_effect=track):
            result = review.render_report(guard, str(audit_file), output)
        text = output.read_text()
        self.assertNotIn(attack, text)
        self.assertIn('\\u003c/script\\u003e', text)
        self.assertNotIn('synthetic@example.invalid', text)
        self.assertNotIn('FICTIONAL123456789', text)
        self.assertNotIn(SESSION, text)
        self.assertNotIn('/Users/fictional', text)
        self.assertFalse(any(p.startswith('/Users/fictional') for p in probed))
        self.assertFalse(result['live_source_inspected'])
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)

    def test_report_has_valid_csp_hashes_and_no_network_resources(self):
        text_file = self.base / 'report.html'
        review.render_report(guard, str(self.audit()), text_file)
        text = text_file.read_text()
        import base64
        for kind, pattern in [('script', r'<script id="app">([\s\S]*?)</script>'), ('style', r'<style>([\s\S]*?)</style>')]:
            content = re.search(pattern, text)[1]
            digest = base64.b64encode(hashlib.sha256(content.encode()).digest()).decode()
            self.assertIn(f"{kind}-src 'sha256-{digest}'", text)
        self.assertIn("connect-src 'none'", text)
        self.assertNotRegex(text, r'(?:src|href)=["\']https?://')
        self.assertNotIn('innerHTML', text)
        self.assertNotIn('fetch(', text)

    def test_report_refuses_existing_output_and_output_inside_source(self):
        audit = self.audit()
        output = self.base / 'report.html'
        output.write_text('keep')
        with self.assertRaises(FileExistsError):
            review.render_report(guard, str(audit), output)
        self.assertEqual(output.read_text(), 'keep')
        with self.assertRaises(guard.GuardError):
            review.render_report(guard, str(audit), self.config / 'report.html')

    def test_report_refuses_receipt_from_different_roots(self):
        receipt = self.base / 'receipt.json'
        receipt.write_text(json.dumps({'kind':'restore-observation','schema':1,'status':'verified','roots':{}}))
        with self.assertRaises(guard.GuardError):
            review.render_report(guard, str(self.audit()), self.base / 'report.html', str(receipt))

    def test_report_refuses_private_payload_mislabelled_as_state_summary(self):
        audit_file = self.audit()
        data = guard.safe_json(audit_file)
        data['state']['oauthAccount'] = {'accessToken': 'PRIVATE_PAYLOAD'}
        audit_file.write_text(json.dumps(data))
        with self.assertRaises(guard.GuardError):
            review.render_report(guard, str(audit_file), self.base / 'report.html')
        self.assertFalse((self.base / 'report.html').exists())

    def test_report_refuses_private_payload_in_receipt_metadata(self):
        old, _, plan = self.pair()
        self.restore_fictional_state(old)
        receipt_file = self.base / 'receipt.json'
        review.record_restore(guard, str(plan), receipt_file)
        receipt = guard.safe_json(receipt_file)
        receipt['selected_results'][0]['expected']['accessToken'] = 'PRIVATE_PAYLOAD'
        receipt_file.write_text(json.dumps(receipt))
        with self.assertRaises(guard.GuardError):
            review.render_report(guard, str(self.audit()), self.base / 'report.html', str(receipt_file))
        self.assertFalse((self.base / 'report.html').exists())

    def test_cli_does_not_create_python_cache_without_B_flag(self):
        skill = self.base / 'skill-copy'
        shutil.copytree(fixtures.WORK / 'cc-clean', skill)
        command = [sys.executable, str(skill / 'scripts/local_state.py'), 'audit', '--root',
                   f'default={self.config}', '--output', str(self.base / 'cache-check-audit.json')]
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(any(skill.rglob('__pycache__')))

    def test_prepare_is_read_only_and_observer_detects_no_restore(self):
        old, _, plan = self.pair()
        before = guard.snapshot(self.roots, hashed=True)
        self.assertFalse(guard.safe_json(plan)['restore_authorized'])
        result = review.record_restore(guard, str(plan), self.base / 'receipt.json')
        self.assertEqual(result['status'], 'restore_failed')
        self.assertEqual(before, guard.snapshot(self.roots, hashed=True))
        self.assertTrue(guard.safe_json(self.base / 'receipt.json')['unselected_unchanged'])
        self.assertFalse(guard.safe_json(self.base / 'receipt.json')['restore_performed_by_helper'])

    def test_external_fictional_restore_verifies_and_can_be_rendered(self):
        old, _, plan = self.pair()
        self.restore_fictional_state(old)
        receipt = self.base / 'receipt.json'
        before = guard.snapshot(self.roots, hashed=True)
        result = review.record_restore(guard, str(plan), receipt)
        self.assertEqual(result['status'], 'restore_verified')
        self.assertEqual(before, guard.snapshot(self.roots, hashed=True))
        report = self.base / 'with-receipt.html'
        review.render_report(guard, str(self.audit()), report, str(receipt))
        self.assertIn('restore_performed_by_helper', report.read_text())

    def test_unselected_new_file_prevents_verified_status(self):
        old, _, plan = self.pair()
        self.restore_fictional_state(old)
        (self.config / 'new-file').write_text('unexpected')
        result = review.record_restore(guard, str(plan), self.base / 'receipt.json')
        self.assertEqual(result['status'], 'restore_partial')
        self.assertEqual(result['unselected_changes'], 1)
        self.assertFalse(guard.safe_json(self.base / 'receipt.json')['unselected_unchanged'])

    def test_unselected_changed_file_and_link_detected(self):
        target = self.base / 'target'
        target.write_text('fictional')
        (self.config / 'link').symlink_to(target)
        old, _, plan = self.pair()
        self.restore_fictional_state(old)
        # Test replacement is an explicit synthetic mutation; no unlink or real source.
        replacement = self.config / 'new-link'
        replacement.symlink_to(self.base / 'different-target')
        os.replace(replacement, self.config / 'link')
        (self.config / 'history.jsonl').write_text('changed unselected')
        result = review.record_restore(guard, str(plan), self.base / 'receipt.json')
        self.assertEqual(result['status'], 'restore_partial')
        self.assertEqual(result['unselected_changes'], 2)

    def test_restore_plan_rejects_source_changed_since_pre_snapshot(self):
        old, current, _ = self.pair()
        self.state.write_text('changed again')
        with self.assertRaises(guard.GuardError):
            review.prepare_restore(guard, old, current, ['state:.'], self.base / 'other-plan.json')
        self.assertFalse((self.base / 'other-plan.json').exists())

    def test_plan_refuses_path_traversal_directories_and_duplicate_selection(self):
        old, current, _ = self.pair()
        for selections in [['default:../.claude.json'], ['default:/history.jsonl'], ['default:skills'],
                           ['default:skills//example.md'], ['state:.','state:.'], ['unknown:.']]:
            with self.subTest(selections=selections), self.assertRaises(guard.GuardError):
                review.prepare_restore(guard, old, current, selections, self.base / 'invalid-plan.json')

    def test_plan_refuses_output_inside_backup_and_selected_symlink(self):
        (self.config / 'shared').symlink_to(self.state)
        old, current, _ = self.pair()
        with self.assertRaises(guard.GuardError):
            review.prepare_restore(guard, old, current, ['default:shared'], self.base / 'invalid-plan.json')
        with self.assertRaises(guard.GuardError):
            review.prepare_restore(guard, old, current, ['state:.'], old / 'plan.json')

    def test_observer_refuses_tampered_backup_or_plan(self):
        old, _, plan = self.pair()
        original = plan.read_text()
        altered = json.loads(original)
        altered['items'][0]['path'] = 'other'
        plan.write_text(json.dumps(altered))
        with self.assertRaises(guard.GuardError):
            review.record_restore(guard, str(plan), self.base / 'receipt.json')
        plan.write_text(original)
        (old / 'copies/state').write_text('tampered')
        with self.assertRaises(guard.GuardError):
            review.record_restore(guard, str(plan), self.base / 'receipt.json')

    def test_plan_roots_must_match_and_current_backup_must_be_separate(self):
        old, current, _ = self.pair()
        with self.assertRaises(guard.GuardError):
            review.prepare_restore(guard, old, old, ['state:.'], self.base / 'invalid.json')
        differently_named = self.base / 'renamed'
        guard.backup({'different': self.config}, differently_named)
        with self.assertRaises(guard.GuardError):
            review.prepare_restore(guard, old, differently_named, ['state:.'], self.base / 'invalid.json')

    def test_partial_cli_has_nonzero_exit_with_receipt(self):
        old, _, plan = self.pair()
        self.restore_fictional_state(old)
        (self.config / 'history.jsonl').write_text('unexpected change')
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = guard.main(['record-restore','--plan',str(plan),'--output',str(self.base / 'receipt.json')])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout.getvalue())['status'], 'restore_partial')

    def test_unreadable_or_unstable_observation_cannot_be_verified(self):
        old, _, plan = self.pair()
        self.restore_fictional_state(old)
        original = guard.snapshot
        def cannot_observe(roots, *args, **kwargs):
            if roots == self.roots:
                raise guard.GuardError('simulated source not stable')
            return original(roots, *args, **kwargs)
        with patch.object(guard, 'snapshot', side_effect=cannot_observe):
            result = review.record_restore(guard, str(plan), self.base / 'receipt.json')
        self.assertEqual(result['status'], 'restore_failed')
        self.assertFalse(guard.safe_json(self.base / 'receipt.json')['unselected_unchanged'])

    def test_missing_file_can_be_planned_and_observed_without_helper_restore(self):
        old = self.base / 'old'
        guard.backup(self.roots, old)
        os.rename(self.config / 'history.jsonl', self.base / 'retained-history.jsonl')
        current = self.base / 'current'
        guard.backup(self.roots, current)
        plan = self.base / 'plan.json'
        review.prepare_restore(guard, old, current, ['default:history.jsonl'], plan)
        self.assertIsNone(guard.safe_json(plan)['items'][0]['before'])
        self.assertFalse((self.config / 'history.jsonl').exists())
        (self.config / 'history.jsonl').write_bytes((old / 'copies/default/history.jsonl').read_bytes())
        self.assertEqual(review.record_restore(guard, str(plan), self.base / 'receipt.json')['status'], 'restore_verified')

    def test_missing_parent_cannot_expand_restore_scope(self):
        old = self.base / 'old'
        guard.backup(self.roots, old)
        os.rename(self.config / 'skills', self.base / 'retained-skills')
        current = self.base / 'current'
        guard.backup(self.roots, current)
        with self.assertRaises(guard.GuardError):
            review.prepare_restore(guard, old, current, ['default:skills/example.md'], self.base / 'plan.json')

    def test_selected_mode_mismatch_and_unselected_missing_file_fail_verification(self):
        old, _, plan = self.pair()
        self.restore_fictional_state(old)
        os.chmod(self.state, 0o644)
        os.rename(self.config / 'history.jsonl', self.base / 'retained-history.jsonl')
        result = review.record_restore(guard, str(plan), self.base / 'receipt.json')
        self.assertEqual(result['status'], 'restore_failed')
        self.assertEqual(result['unselected_changes'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
