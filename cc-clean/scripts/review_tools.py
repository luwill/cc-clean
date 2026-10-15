"""Metadata relationships, offline HTML, and observations of externally approved restores."""
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

UUID = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
UUID_RE = re.compile(UUID)
AREAS = {'projects', 'session-env', 'file-history', 'debug', 'todos'}
REASONS = {
    'current-login': '身份或配置候选；存在性不证明属于旧账号，需另行核实',
    'historical': '历史工作数据；默认保留，缺少 session-env 不构成可删证据',
    'work-asset': '配置、Skills、插件或其他工作资产；默认保留',
    'unverified': '尚未核实用途或账号归属；保留并补证据',
}


def classify(rel, kind, root_name=''):
    if kind == 'symlink':
        return 'unverified'
    parts = PurePosixPath(rel).parts
    top = root_name if rel == '.' and root_name else (parts[0] if parts else '.')
    if (top in {'.credentials.json', 'credentials.json', '.claude.json', 'telemetry', 'statsig',
                'stats-cache.json', 'backups'} or top.startswith('.claude.json.backup')):
        return 'current-login'
    if top in {'skills', 'plugins', 'commands', 'agents', 'rules', 'hooks', 'mcp', 'ide'} or top.startswith('settings') or top == 'CLAUDE.md':
        return 'work-asset'
    if len(parts) >= 3 and parts[0] == 'projects' and parts[2] in {'memory', 'CLAUDE.md'}:
        return 'work-asset'
    if top in AREAS or top in {'history.jsonl', 'logs', 'shell-snapshots', 'transcripts', 'tasks', 'plans'}:
        return 'historical'
    return 'unverified'


def relationships(trees):
    """Join only identifiers in one explicit root; never decode a project directory."""
    groups = {}
    unresolved = []
    for label, value in trees.items():
        for rel, record in value['entries'].items():
            parts = PurePosixPath(rel).parts
            if len(parts) < 2 or parts[0] not in AREAS:
                continue
            area, session_id, role = parts[0], None, None
            if record['kind'] != 'symlink':
                if area == 'projects' and len(parts) >= 3:
                    name = parts[2]
                    if name in {'memory', 'CLAUDE.md'}:
                        continue
                    if len(parts) == 3 and name.endswith('.jsonl') and record['kind'] == 'file':
                        name, role = name[:-6], 'project-session'
                    elif len(parts) > 3 or record['kind'] == 'directory':
                        role = 'project-session-artifact'
                    if role and UUID_RE.fullmatch(name):
                        session_id = name.lower()
                elif area in {'session-env', 'file-history'} and UUID_RE.fullmatch(parts[1]):
                    session_id, role = parts[1].lower(), area
                elif area == 'debug' and len(parts) == 2 and record['kind'] == 'file':
                    match = re.fullmatch(f'({UUID})\\.txt', parts[1])
                    if match:
                        session_id, role = match[1].lower(), 'debug'
                elif area == 'todos' and len(parts) == 2 and record['kind'] == 'file':
                    match = re.fullmatch(f'({UUID})-agent-[^/]+\\.json', parts[1])
                    if match:
                        session_id, role = match[1].lower(), 'todos'
            node = {'root': label, 'path': rel, 'kind': record['kind'], 'bytes': record.get('bytes', 0),
                    'preserve_reason': REASONS['historical']}
            if not session_id:
                # Project category folders themselves have no session identifier.
                if area == 'projects' and len(parts) == 2 and record['kind'] == 'directory':
                    continue
                node.update(confidence='unverified', relationship_source='path-metadata',
                            unverified_reason='未识别会话标识，或为未跟随的符号链接')
                unresolved.append(node)
                continue
            node['role'] = role
            group = groups.setdefault((label, session_id), {'root': label, 'session_id': session_id, 'items': []})
            group['items'].append(node)
    result = []
    for _, group in sorted(groups.items()):
        roles = {item['role'] for item in group['items']}
        projects = sorted({PurePosixPath(item['path']).parts[1] for item in group['items']
                           if item['role'].startswith('project-session')})
        group.update(
            project_directory_labels=projects,
            relationship_source='same-root UUID path match; no contents or project-path decoding',
            confidence='identifier-match',
            project_session_present='project-session' in roles,
            session_env_present='session-env' in roles,
            unverified_reason='账号归属、会话是否仍在使用及真实项目路径未验证',
            preserve_reason=REASONS['historical'],
            review_status='preserve', cleanup_authorized=False,
        )
        if len(projects) > 1:
            group['unverified_reason'] += '；同标识出现在多个项目目录，不能推定单一归属'
        result.append(group)
    return {'schema': 1, 'method': 'metadata-only, root-isolated', 'groups': result,
            'unresolved': unresolved, 'group_count': len(result), 'cleanup_authorized': False,
            'limitations': ['UUID 一致只证明路径标识关联', '未解码项目路径，也不以路径存在性判断可删',
                            'session-env 缺失不代表孤儿或过期', '跨显式根不合并']}


def safe_relative(core, text):
    core.require(isinstance(text, str) and bool(text), 'Invalid selected relative path')
    if text == '.':
        return text
    parts = text.split('/')
    core.require(not text.startswith('/') and '\\' not in text and all(p not in ('', '.', '..') for p in parts),
                 'Selected path must be normalized and cannot traverse parents')
    return text


def source_path(roots, label, rel):
    return roots[label] if rel == '.' else roots[label] / rel


def plan_payload(core, old_dir, current_dir, selections):
    old_dir, current_dir = core.lexical_path(old_dir), core.lexical_path(current_dir)
    roots, old, _ = core.verified_bundle(old_dir)
    current_roots, current, _ = core.verified_bundle(current_dir)
    core.require(roots == current_roots, 'Restore backup roots must match exactly')
    core.require(old_dir != current_dir, 'Pre-restore snapshot must be a separate verified backup')
    items, seen = [], set()
    for selected in selections:
        core.require(isinstance(selected, str), 'Invalid selection')
        label, sep, rel = selected.partition(':')
        core.require(sep and label in roots, 'Selection must name an exact backup root')
        rel = safe_relative(core, rel)
        core.require((label, rel) not in seen, 'Duplicate restore selection')
        seen.add((label, rel))
        target = source_path(roots, label, rel)
        core.no_symlink_parents(target)
        intended = old['trees'][label]['entries'].get(rel)
        before = current['trees'][label]['entries'].get(rel)
        core.require(intended is not None and intended['kind'] == 'file', 'Select a regular file from the old backup')
        core.require(before is None or before['kind'] == 'file', 'Current selected target must be a regular file or absent')
        if rel == '.':
            core.require(target.parent.is_dir(), 'Restore parent must already exist; directory creation needs a separate plan')
        # A newly created parent would broaden the plan and change an unselected node.
        for parent in PurePosixPath(rel).parents if rel != '.' else []:
            parent_rel = str(parent)
            core.require(current['trees'][label]['entries'].get(parent_rel, {}).get('kind') == 'directory',
                         'Restore parent must already exist; directory creation needs a separate plan')
        items.append({'root': label, 'path': rel, 'before': before, 'intended_after': intended})
    core.require(items, 'At least one exact file must be selected')
    return roots, current, {
        'schema': 1, 'kind': 'restore-plan', 'backup_dir': str(old_dir), 'pre_restore_backup': str(current_dir),
        'roots': old['roots'], 'backup_manifest_sha256': core.canonical_digest(old),
        'pre_restore_manifest_sha256': core.canonical_digest(current), 'items': items,
        'cleanup_authorized': False, 'restore_authorized': False, 'source_changed_by_tool': False,
        'verification_scope': ['selected file bytes/mode/uid/gid', 'every unselected entry and link'],
        'acl_xattr_contents_independently_verified': False,
    }


def prepare_restore(core, old_dir, current_dir, selections, output):
    roots, current, plan = plan_payload(core, old_dir, current_dir, selections)
    core.outside_sources(output, roots)
    for directory in (core.lexical_path(old_dir), core.lexical_path(current_dir)):
        core.outside_sources(output, {'backup': directory})
    core.require(core.snapshot(roots, hashed=True) == current['trees'],
                 'Live source no longer matches the pre-restore snapshot')
    plan['created_at'] = core.now()
    plan['plan_sha256'] = core.canonical_digest(plan)
    core.private_json(output, plan)
    return {'status': 'restore_plan_written', 'selected_files': len(plan['items']), 'restore_authorized': False,
            'source_changed_by_tool': False}


def record_restore(core, plan_file, output):
    plan = core.safe_json(core.lexical_path(plan_file))
    core.require(isinstance(plan, dict) and plan.get('schema') == 1 and plan.get('kind') == 'restore-plan',
                 'Unsupported restore plan')
    body = {k: v for k, v in plan.items() if k != 'plan_sha256'}
    core.require(core.canonical_digest(body) == plan.get('plan_sha256'), 'Restore plan changed')
    selections = [f"{row['root']}:{row['path']}" for row in plan['items']]
    roots, current, expected = plan_payload(core, plan['backup_dir'], plan['pre_restore_backup'], selections)
    core.require(all(plan.get(key) == value for key, value in expected.items()), 'Plan differs from verified backups')
    core.outside_sources(output, roots)
    for directory in (core.lexical_path(plan['backup_dir']), core.lexical_path(plan['pre_restore_backup'])):
        core.outside_sources(output, {'backup': directory})
    core.require(output != core.lexical_path(plan_file), 'Receipt must not overwrite the plan')
    rows, changes, observed_error = [], [], None
    try:
        after = core.snapshot(roots, hashed=True)
        core.require(core.snapshot(roots, hashed=True) == after, 'Source changed during restore observation')
    except (core.GuardError, OSError):
        after, observed_error = None, '源无法完整验收或仍在变化；没有宣称恢复成功'
    selected = {(row['root'], row['path']) for row in plan['items']}
    for row in plan['items']:
        actual = after[row['root']]['entries'].get(row['path']) if after is not None else None
        verified = after is not None and actual == row['intended_after']
        rows.append({'root': row['root'], 'path': row['path'], 'expected': row['intended_after'], 'observed': actual,
                     'result': 'verified' if verified else ('unverified' if after is None else 'mismatch')})
    if after is not None:
        for label, before_tree in current['trees'].items():
            old_entries, new_entries = before_tree['entries'], after[label]['entries']
            for rel in sorted(set(old_entries) | set(new_entries)):
                if (label, rel) not in selected and old_entries.get(rel) != new_entries.get(rel):
                    changes.append({'root': label, 'path': rel, 'result': 'unselected-entry-changed'})
    good = sum(row['result'] == 'verified' for row in rows)
    status = 'verified' if good == len(rows) and not changes and after is not None else ('partial' if good else 'failed')
    receipt = {'schema': 1, 'kind': 'restore-observation', 'status': status, 'observed_at': core.now(),
               'plan_sha256': plan['plan_sha256'], 'roots': plan['roots'],
               'backup_manifest_sha256': plan['backup_manifest_sha256'],
               'pre_restore_manifest_sha256': plan['pre_restore_manifest_sha256'],
               'backup_dir': plan['backup_dir'], 'pre_restore_backup': plan['pre_restore_backup'],
               'selected_results': rows, 'unselected_changes': changes,
               'unselected_unchanged': after is not None and not changes, 'observation_error': observed_error,
               'restore_performed_by_helper': False, 'authorization_verified_by_helper': False,
               'acl_xattr_contents_independently_verified': False}
    core.private_json(output, receipt)
    return {'status': 'restore_' + status, 'selected_verified': good, 'selected_files': len(rows),
            'unselected_changes': len(changes), 'source_changed_by_tool': False}


def masked_text(text, roots):
    for label, root in sorted(roots.items(), key=lambda row: len(row[1]), reverse=True):
        text = text.replace(root, f'<root:{label}>')
    text = re.sub(r'/(?:Users|home)/[^/\s]+', '<home>', text)
    text = re.sub(r'-(?:Users|home)-[^/\s]+', '<encoded-project>', text)
    text = re.sub(r'[\w.+-]+@[\w.-]+\.(?!(?:jsonl?|md|txt|py|js|ts|html|css|ya?ml|sh|toml|lock|bin)\b)[A-Za-z]{2,}',
                  '<email>', text)
    text = UUID_RE.sub('<session-id>', text)
    text = re.sub(r'(?i)(?:sk-(?:proj-|ant-)?|gh[pousr]_|github_pat_|Bearer[ _-])[A-Za-z0-9_-]{6,}', '<secret>', text)
    text = re.sub(r'(?i)\b[a-f0-9]{24,}\b', '<fingerprint>', text)
    return text


def mask_data(data, roots):
    if isinstance(data, str):
        return masked_text(data, roots)
    if isinstance(data, list):
        return [mask_data(value, roots) for value in data]
    if isinstance(data, dict):
        return {masked_text(str(key), roots): mask_data(value, roots) for key, value in data.items()}
    return data


def receipt_metadata(core, record):
    if record is None:
        return None
    core.require(isinstance(record, dict) and set(record) <= {'kind', 'bytes', 'sha256', 'mode', 'uid', 'gid', 'target'},
                 'Receipt must contain metadata only')
    core.require(record.get('kind') in {'file', 'directory', 'symlink'}, 'Invalid receipt file kind')
    for key in ('bytes', 'mode', 'uid', 'gid'):
        if key in record:
            core.require(type(record[key]) is int and record[key] >= 0, 'Invalid receipt metadata number')
    if 'sha256' in record:
        core.require(isinstance(record['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', record['sha256']),
                     'Invalid receipt fingerprint')
    if 'target' in record:
        core.require(isinstance(record['target'], str), 'Invalid receipt link metadata')
    return record


def validate_device_id_summary(core, state):
    keys = {'device_id_fields', 'device_id_field_count', 'device_id_scan_scope', 'device_id_scan_complete'}
    if not keys.intersection(state):
        return  # v0.2.1 and older audits contain no recursive device-ID summary.
    core.require(keys <= state.keys(), 'Incomplete device-ID summary')
    core.require(state.get('missing') is not True, 'Missing state cannot have a completed device-ID scan')
    fields = state['device_id_fields']
    core.require(isinstance(fields, list) and type(state['device_id_field_count']) is int and
                 state['device_id_field_count'] == len(fields), 'Invalid device-ID field count')
    core.require(state['device_id_scan_scope'] == 'selected-state-json-objects-and-arrays' and
                 state['device_id_scan_complete'] is True, 'Invalid device-ID scan scope')
    seen = set()
    for row in fields:
        core.require(isinstance(row, dict) and set(row) == {'field', 'location', 'value_type', 'present',
                     'value_recorded', 'ownership', 'preserve'}, 'Device-ID findings must contain metadata only')
        core.require(isinstance(row['field'], str) and row['field'] in core.DEVICE_ID_KEYS and
                     isinstance(row['value_type'], str) and row['value_type'] in
                     {'null', 'boolean', 'number', 'string', 'array', 'object'}, 'Invalid device-ID metadata')
        core.require(row['present'] is True and row['value_recorded'] is False and row['preserve'] is True and
                     row['ownership'] == 'unverified', 'Device-ID findings cannot authorize cleanup')
        core.require(isinstance(row['location'], list) and bool(row['location']), 'Device-ID location missing')
        path = []
        for segment in row['location']:
            core.require(isinstance(segment, dict) and len(segment) == 1 and
                         next(iter(segment)) in {'object_key_index', 'array_index'}, 'Invalid device-ID location')
            kind, index = next(iter(segment.items()))
            core.require(type(index) is int and index >= 0, 'Device-ID location must contain numeric indices only')
            path.append((kind, index))
        core.require(path[-1][0] == 'object_key_index' and tuple(path) not in seen, 'Ambiguous device-ID location')
        seen.add(tuple(path))


def render_report(core, audit_file, output, receipt_file=None):
    audit = core.safe_json(core.lexical_path(audit_file))
    core.require(isinstance(audit, dict) and audit.get('schema') == core.SCHEMA and audit.get('mode') == 'metadata-only',
                 'Expected a metadata-only audit')
    # Offline rendering must not probe the original environment, even for symlinks.
    core.require(isinstance(audit['roots'], dict) and bool(audit['roots']), 'Audit roots are missing')
    roots = {}
    for label, path in audit['roots'].items():
        core.require(re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', label), 'Invalid audit root label')
        roots[label] = core.lexical_path(path)
    for label, value in audit['trees'].items():
        core.require(label in roots and isinstance(value, dict) and isinstance(value.get('entries'), dict),
                     'Invalid audit tree')
        for rel, record in value['entries'].items():
            safe_relative(core, rel)
            core.require(record.get('kind') in {'file', 'directory', 'symlink'} and
                         isinstance(record.get('bytes', 0), int) and record.get('bytes', 0) >= 0, 'Invalid audit entry')
    core.outside_sources(output, roots)
    core.require(set(audit['trees']) == set(roots), 'Audit root labels mismatch')
    # Rebuild from metadata instead of trusting an imported graph's conclusions.
    graph = relationships(audit['trees'])
    rows = []
    counts = Counter()
    for label, value in audit['trees'].items():
        for rel, record in value['entries'].items():
            if record['kind'] == 'directory':
                continue
            category = classify(rel, record['kind'], roots[label].name)
            counts[category] += 1
            rows.append({'root': label, 'path': rel, 'kind': record['kind'], 'bytes': record.get('bytes', 0),
                         'category': category, 'review_status': 'preserve', 'preserve_reason': REASONS[category]})
    receipt = None
    if receipt_file:
        receipt = core.safe_json(core.lexical_path(receipt_file))
        core.require(isinstance(receipt, dict) and receipt.get('schema') == 1 and receipt.get('kind') == 'restore-observation',
                     'Expected a restore-observation receipt')
        core.require(receipt.get('roots') == audit['roots'], 'Receipt and audit roots must match exactly')
        core.require(receipt.get('status') in {'verified', 'partial', 'failed'}, 'Invalid restore receipt status')
        selected, unselected = [], []
        core.require(isinstance(receipt.get('selected_results'), list) and isinstance(receipt.get('unselected_changes'), list),
                     'Restore receipt result lists missing')
        for row in receipt['selected_results']:
            core.require(row['root'] in roots and row['result'] in {'verified', 'unverified', 'mismatch'}, 'Invalid receipt result')
            safe_relative(core, row['path'])
            selected.append({'root': row['root'], 'path': row['path'], 'result': row['result'],
                             'expected': receipt_metadata(core, row['expected']),
                             'observed': receipt_metadata(core, row['observed'])})
        for row in receipt['unselected_changes']:
            core.require(row['root'] in roots and row['result'] == 'unselected-entry-changed', 'Invalid unselected receipt result')
            safe_relative(core, row['path'])
            unselected.append({'root': row['root'], 'path': row['path'], 'result': row['result']})
        # The viewer neither verifies a live restore nor renders arbitrary imported fields.
        receipt = {key: receipt.get(key) for key in ('status', 'observed_at', 'selected_results', 'unselected_changes',
                   'unselected_unchanged', 'observation_error', 'restore_performed_by_helper',
                   'authorization_verified_by_helper', 'acl_xattr_contents_independently_verified')}
        receipt.update(selected_results=selected, unselected_changes=unselected)
    state = audit.get('state')
    if state is not None:
        core.require(isinstance(state, dict), 'Invalid audit state summary')
        core.require(set(state) <= {'missing', 'identity_keys_present', 'cache_keys_present',
                     'unclassified_top_level_key_count', 'projects_count', 'mcp_servers_count',
                     'device_id_fields', 'device_id_field_count', 'device_id_scan_scope', 'device_id_scan_complete'},
                     'Unexpected audit state fields')
        for key, known in (('identity_keys_present', core.IDENTITY_KEYS), ('cache_keys_present', core.CACHE_KEYS)):
            if key in state:
                core.require(isinstance(state[key], list) and all(value in known for value in state[key]),
                             'Invalid audit field-presence list')
        for key in ('unclassified_top_level_key_count', 'projects_count', 'mcp_servers_count'):
            if key in state:
                core.require(state[key] is None or (type(state[key]) is int and state[key] >= 0), 'Invalid audit count')
        if 'missing' in state:
            core.require(type(state['missing']) is bool, 'Invalid missing-state flag')
        validate_device_id_summary(core, state)
    payload = mask_data({'created_at': audit.get('created_at'), 'summary': audit['summary'], 'state': state,
                         'categories': dict(counts), 'rows': rows, 'relationships': graph, 'receipt': receipt,
                         'cleanup_authorized': False, 'masked': True}, audit['roots'])
    template = (Path(__file__).resolve().parent.parent / 'assets/report.html').read_text(encoding='utf-8')
    # JSON is a data node. Escape HTML delimiters even though JSON quotes are already encoded.
    encoded = json.dumps(payload, ensure_ascii=False).replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')
    script = re.search(r'<script id="app">([\s\S]*?)</script>', template).group(1)
    style = re.search(r'<style>([\s\S]*?)</style>', template).group(1)
    def digest(value):
        return base64.b64encode(hashlib.sha256(value.encode()).digest()).decode()
    template = template.replace('__SCRIPT_HASH__', digest(script)).replace('__STYLE_HASH__', digest(style))
    template = template.replace('__AUDIT_DATA__', encoded)
    core.private_text(output, template)
    return {'status': 'readonly_report_written', 'items': len(rows), 'relationship_groups': graph['group_count'],
            'masked': True, 'cleanup_authorized': False, 'live_source_inspected': False}
