#!/usr/bin/env python3
"""Audit, offline review and verified copies/receipts. No source edits or deletions."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

# A read-only invocation must not leave Python caches in the installed skill.
sys.dont_write_bytecode = True

SCHEMA = 1
IDENTITY_KEYS = (
    'oauthAccount', 'userID', 'machineID', 'deviceId', 'groveConfigCache',
    'passesEligibilityCache', 'overageCreditGrantCache', 'fotwUpsellFulfilled',
    'clientDataCacheSlots', 'cachedArtifactRoster', 'githubWebConnectionStatusCache',
    'cachedUsageUtilization', 'promoStartupStatusCache',
)
CACHE_KEYS = (
    'cachedGrowthBookFeatures', 'cachedStatsigGates', 'cachedDynamicConfigs',
    'cachedExtraUsageDisabledReason', 'cachedChromeExtensionInstalled',
    'skillUsage', 'tipsHistory', 'toolUsage', 's1mAccessCache', 'metricsStatusCache',
    'clientDataCache', 'feedbackSurveyState', 'reactVulnerabilityCache',
)


class GuardError(Exception):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def require(condition, message):
    if not condition:
        raise GuardError(message)


def lexical_path(value):
    path = Path(value).expanduser()
    require(path.is_absolute(), 'Use an absolute path')
    require('..' not in path.parts, 'Parent traversal is not allowed')
    return path


def no_symlink_parents(path, include_leaf=True):
    chain = [path, *path.parents] if include_leaf else list(path.parents)
    for part in chain:
        require(not part.is_symlink(), 'Symlinked root/output/parent must be resolved explicitly')


def parse_roots(values, allow_missing=False):
    roots = {}
    for item in values:
        label, sep, value = item.partition('=')
        require(sep and re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', label), 'Expected --root label=/absolute/path')
        require(label not in roots, 'Duplicate root label')
        path = lexical_path(value)
        no_symlink_parents(path)
        if not allow_missing:
            require(path.exists(), 'Backup source is missing')
        for previous in roots.values():
            require(path != previous and path not in previous.parents and previous not in path.parents,
                    'Source roots overlap; include an internal state file only through its directory root')
        roots[label] = path
    require(roots, 'At least one explicit root is required')
    return roots


def outside_sources(path, roots):
    for root in roots.values():
        require(path != root and root not in path.parents and path not in root.parents,
                'Output must be outside and must not contain any source root')


def safe_json(path):
    no_symlink_parents(path)
    require(path.is_file(), 'JSON file is missing or not a regular file')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), 'JSON input is not a regular file')
        raw = stream.read()
        after = os.fstat(stream.fileno())
    require(stable(before) == stable(after), 'JSON input changed during reading')
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError):
        raise GuardError('Invalid JSON; contents intentionally not printed') from None


def private_text(path, content):
    no_symlink_parents(path)
    require(path.parent.is_dir(), 'Output parent must already exist')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def private_json(path, data):
    private_text(path, json.dumps(data, ensure_ascii=False, indent=2) + '\n')


def canonical_digest(data):
    raw = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    return hashlib.sha256(raw).hexdigest()


def stable(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def file_digest(path):
    no_symlink_parents(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), 'Refusing to read a non-regular file')
        digest = hashlib.sha256()
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    require(stable(before) == stable(after) == stable(path.lstat()), 'Source changed during hashing')
    return digest.hexdigest()


def entry(path, hashed):
    meta = path.lstat()
    record = {'mode': stat.S_IMODE(meta.st_mode), 'uid': meta.st_uid, 'gid': meta.st_gid}
    if stat.S_ISLNK(meta.st_mode):
        return dict(record, kind='symlink', target=os.readlink(path))
    if stat.S_ISDIR(meta.st_mode):
        return dict(record, kind='directory')
    if stat.S_ISREG(meta.st_mode):
        record.update(kind='file', bytes=meta.st_size)
        if hashed:
            record['sha256'] = file_digest(path)
            require(stable(meta) == stable(path.lstat()), 'Source changed during inventory')
        return record
    raise GuardError('Unsupported special file; no complete backup or clean bill of health')


def tree(path, hashed=False):
    no_symlink_parents(path)
    if not path.exists():
        return {'missing': True, 'entries': {}}
    result = {'.': entry(path, hashed)}
    if path.is_dir():
        def walk(directory):
            with os.scandir(directory) as items:
                children = sorted(items, key=lambda item: item.name)
            for child in children:
                p = Path(child.path)
                rel = p.relative_to(path).as_posix()
                result[rel] = entry(p, hashed)
                if result[rel]['kind'] == 'directory':
                    walk(p)
        walk(path)
    return {'missing': False, 'entries': result}


def snapshot(roots, hashed=False):
    return {label: tree(path, hashed) for label, path in roots.items()}


def summary(trees):
    counts = Counter()
    total = 0
    missing = 0
    for value in trees.values():
        missing += int(value['missing'])
        for record in value['entries'].values():
            counts[record['kind']] += 1
            total += record.get('bytes', 0)
    return {'files': counts['file'], 'directories': counts['directory'],
            'symlinks': counts['symlink'], 'bytes': total, 'missing_roots': missing}


def audit(roots, output, state_file=None):
    from review_tools import relationships
    outside_sources(output, roots)
    trees = snapshot(roots, hashed=False)
    data = {'schema': SCHEMA, 'mode': 'metadata-only', 'created_at': now(),
            'roots': {k: str(v) for k, v in roots.items()}, 'trees': trees,
            'summary': summary(trees), 'credentials_payload_read': False,
            'history_content_read': False, 'source_changed_by_tool': False}
    data['relationships'] = relationships(trees)
    if state_file is not None:
        state_file = lexical_path(state_file)
        require(any(state_file == p or (p.is_dir() and p in state_file.parents) for p in roots.values()),
                'State file must be within an explicitly selected root')
        require(state_file.name == '.claude.json', 'Only the explicitly selected .claude.json may be parsed in audit')
        if state_file.exists():
            state = safe_json(state_file)
            require(isinstance(state, dict), 'State JSON must be an object')
            data['state'] = {
                'identity_keys_present': [key for key in IDENTITY_KEYS if key in state],
                'cache_keys_present': [key for key in CACHE_KEYS if key in state],
                'unclassified_top_level_key_count': len(set(state) - set(IDENTITY_KEYS) - set(CACHE_KEYS)
                                                        - {'projects', 'mcpServers'}),
                'projects_count': len(state['projects']) if isinstance(state.get('projects'), dict) else None,
                'mcp_servers_count': len(state['mcpServers']) if isinstance(state.get('mcpServers'), dict) else None,
            }
        else:
            data['state'] = {'missing': True}
    private_json(output, data)
    return {'status': 'audit_written', **data['summary'], 'state_inspected': state_file is not None}


def copy_root(source, destination):
    if sys.platform == 'darwin':
        require(Path('/usr/bin/ditto').is_file(), 'ditto unavailable; choose and verify another backup method')
        result = subprocess.run(['/usr/bin/ditto', '--rsrc', '--extattr', '--acl', str(source), str(destination)],
                                capture_output=True, timeout=1800)
        require(result.returncode == 0, 'Native copy failed; partial backup kept, source untouched')
        return 'ditto-with-acl-and-xattr-requested'
    require(os.name == 'posix', 'Backup requires a platform-native implementation on this OS')
    if source.is_dir():
        shutil.copytree(source, destination, symlinks=True)
    else:
        shutil.copy2(source, destination, follow_symlinks=False)
    return 'posix-copy2-basic-metadata'


def backup(roots, output, allow_missing=False):
    require(os.name == 'posix', 'Use native ACL-aware backup on Windows')
    outside_sources(output, roots)
    no_symlink_parents(output)
    require(not output.exists(), 'Backup destination must be new')
    require(output.parent.is_dir(), 'Backup parent must already exist')
    before = snapshot(roots, hashed=True)
    missing_count = summary(before)['missing_roots']
    if allow_missing:
        require(missing_count < len(roots), 'At least one backup root must exist')
        for label, value in before.items():
            if value['missing']:
                no_symlink_parents(roots[label].parent)
                require(roots[label].parent.is_dir(), 'Missing backup root parent must already exist')
    else:
        require(not missing_count, 'Missing backup root')
    candidates = [(label, rel, record) for label, value in before.items()
                  for rel, record in value['entries'].items() if record['kind'] == 'file']
    # Exercise a primary state file and a retained session when available.
    # Full copied-file hashes are verified separately, so this is not statistical sampling.
    state_candidates = [row for row in candidates if (row[1] == '.' and roots[row[0]].name == '.claude.json')
                        or Path(row[1]).name == '.claude.json']
    session_candidates = [row for row in candidates if row[1].endswith('.jsonl') and row[2]['bytes'] > 0]
    chosen = []
    for group in [state_candidates, session_candidates, candidates]:
        for row in sorted(group, key=lambda item: item[2]['bytes']):
            if row not in chosen and len(chosen) < 2:
                chosen.append(row)
                break
    if len(chosen) < 2:
        chosen.extend(row for row in sorted(candidates, key=lambda item: item[2]['bytes'])
                      if row not in chosen and len(chosen) < 2)
    sample_bytes = sum(row[2]['bytes'] for row in chosen)
    needed = summary(before)['bytes'] + sample_bytes + 1024 * 1024
    require(shutil.disk_usage(output.parent).free >= needed, 'Not enough free space for backup and recovery samples')
    output.mkdir(mode=0o700)
    private_json(output / 'started.json', {'status': 'backup_started', 'created_at': now()})
    private_json(output / 'manifest.json', {'schema': SCHEMA, 'roots': {k: str(v) for k, v in roots.items()},
                                          'trees': before})
    copies = output / 'copies'
    copies.mkdir(mode=0o700)
    methods = {label: ('absent-at-backup' if before[label]['missing'] else copy_root(source, copies / label))
               for label, source in roots.items()}
    copied = snapshot({label: copies / label for label in roots}, hashed=True)
    require(copied == before, 'Copied contents or base metadata differ; partial backup kept')
    require(snapshot(roots, hashed=True) == before, 'Source changed while backing up; recheck before any cleanup')
    sample_dir = output / 'restore-samples'
    sample_dir.mkdir(mode=0o700)
    samples = []
    for index, (label, rel, record) in enumerate(chosen):
        source = copies / label if rel == '.' else copies / label / rel
        dest = sample_dir / f'sample-{index + 1}.bin'
        with source.open('rb') as src:
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as target:
                shutil.copyfileobj(src, target)
                target.flush()
                os.fsync(target.fileno())
        require(file_digest(dest) == record['sha256'], 'Recovery sample mismatch')
        samples.append({'sample': dest.name, 'root': label, 'path': rel,
                        'sha256': record['sha256'], 'bytes': record['bytes']})
    manifest = safe_json(output / 'manifest.json')
    receipt = {'status': 'backup_verified', 'schema': SCHEMA, 'verified_at': now(),
               'manifest_sha256': canonical_digest(manifest), 'summary': summary(before),
               'restore_samples': samples, 'copy_methods': methods,
               'source_unchanged_during_backup': True,
               'verified_attributes': ['content-sha256', 'mode', 'uid', 'gid', 'symbolic-link-target'],
               'acl_xattr_contents_independently_verified': False,
               'contains_sensitive_originals': True}
    private_json(output / 'verified.json', receipt)
    return {'status': receipt['status'], **receipt['summary'], 'restore_samples': len(samples)}


def verified_bundle(directory):
    directory = lexical_path(directory)
    no_symlink_parents(directory)
    require(directory.is_dir(), 'Backup directory missing')
    require(stat.S_IMODE(directory.stat().st_mode) == 0o700, 'Backup directory must have mode 0700')
    manifest = safe_json(directory / 'manifest.json')
    receipt = safe_json(directory / 'verified.json')
    require(manifest.get('schema') == SCHEMA and receipt.get('schema') == SCHEMA, 'Unsupported backup schema')
    require(receipt.get('status') == 'backup_verified', 'Backup was not completely verified')
    require(canonical_digest(manifest) == receipt.get('manifest_sha256'), 'Manifest changed since verification')
    roots = parse_roots([f'{label}={path}' for label, path in manifest['roots'].items()], allow_missing=True)
    require(set(roots) == set(manifest['trees']), 'Backup manifest roots mismatch')
    outside_sources(directory, roots)
    copies = {label: directory / 'copies' / label for label in roots}
    require(snapshot(copies, hashed=True) == manifest['trees'], 'Backup contents changed or are incomplete')
    for sample in receipt['restore_samples']:
        require(re.fullmatch(r'sample-[12]\.bin', sample['sample']), 'Invalid recovery sample name')
        require(file_digest(directory / 'restore-samples' / sample['sample']) == sample['sha256'],
                'Recovery sample changed')
    return roots, manifest, receipt


def verify(directory, check_source=False):
    roots, manifest, receipt = verified_bundle(directory)
    if check_source:
        require(snapshot(roots, hashed=True) == manifest['trees'], 'Source no longer matches backup; recheck the plan')
    return {'status': 'backup_verified', **receipt['summary'],
            'restore_samples': len(receipt['restore_samples']), 'source_checked': check_source}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    inspect_parser = sub.add_parser('audit', help='Metadata only; optional key-presence inspection of .claude.json')
    inspect_parser.add_argument('--root', action='append', required=True)
    inspect_parser.add_argument('--state-file')
    inspect_parser.add_argument('--output', required=True)
    backup_parser = sub.add_parser('backup', help='Copy explicit roots to a new private directory and verify')
    backup_parser.add_argument('--root', action='append', required=True)
    backup_parser.add_argument('--allow-missing', action='store_true',
                               help='Record absent roots for pre-restore snapshots')
    backup_parser.add_argument('--output', required=True)
    verify_parser = sub.add_parser('verify', help='Verify an existing backup; never restore or edit source')
    verify_parser.add_argument('--backup-dir', required=True)
    verify_parser.add_argument('--check-source', action='store_true')
    report_parser = sub.add_parser('report', help='Render a masked, offline read-only HTML from an audit')
    report_parser.add_argument('--audit', required=True)
    report_parser.add_argument('--receipt', help='Optional restore-observation receipt; no source reads')
    report_parser.add_argument('--output', required=True)
    plan_parser = sub.add_parser('prepare-restore', help='Verify two backups and write a plan; never restore')
    plan_parser.add_argument('--backup-dir', required=True)
    plan_parser.add_argument('--pre-restore-backup', required=True)
    plan_parser.add_argument('--select', action='append', required=True, help='Exact root-label:relative-file; . for file root')
    plan_parser.add_argument('--output', required=True)
    record_parser = sub.add_parser('record-restore', help='Observe a separately authorized restore; never restore')
    record_parser.add_argument('--plan', required=True)
    record_parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in ('report', 'prepare-restore', 'record-restore'):
            from review_tools import render_report, prepare_restore, record_restore
            core = sys.modules[__name__]
            if args.command == 'report':
                result = render_report(core, args.audit, lexical_path(args.output), args.receipt)
            elif args.command == 'prepare-restore':
                result = prepare_restore(core, args.backup_dir, args.pre_restore_backup,
                                         args.select, lexical_path(args.output))
            else:
                result = record_restore(core, args.plan, lexical_path(args.output))
        elif args.command == 'verify':
            result = verify(args.backup_dir, args.check_source)
        else:
            allow_missing = args.command == 'audit' or getattr(args, 'allow_missing', False)
            roots = parse_roots(args.root, allow_missing=allow_missing)
            output = lexical_path(args.output)
            if args.command == 'audit':
                result = audit(roots, output, args.state_file)
            else:
                result = backup(roots, output, allow_missing=args.allow_missing)
        print(json.dumps(result, ensure_ascii=False))
        return 2 if result.get('status') in ('restore_partial', 'restore_failed') else 0
    except GuardError as error:
        # GuardError messages are constant strings defined above, without raw input values.
        print('ERROR: ' + str(error), file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError, KeyError, TypeError, ValueError):
        # Never stringify external exceptions: path/config contents can carry sensitive data.
        print('ERROR: operation could not be verified; source was not edited by this helper. '
              'Check paths, permissions, idle state and any partial backup locally.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
