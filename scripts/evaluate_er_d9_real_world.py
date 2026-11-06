#!/usr/bin/env python3
"""Reproduce ER-D9 against a pinned public EJS checkout; never execute upstream code."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient
from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.services.scan_service import ApiSettings

SHA = '88bd19074205f01df65dc9f118fb1a0000c40ec8'
REPO = 'https://github.com/mde/ejs.git'
REQUEST = {'target_id': 'local-project', 'rule_profile_id': 'baseline'}
FILES = ('ejs.js', 'utils.js', 'parseargs.js', 'package.json')


def run(command: list[str], cwd: Path, *, allowed: tuple[int, ...] = (0,), timeout: int = 120) -> subprocess.CompletedProcess:
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env={**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_LFS_SKIP_SMUDGE': '1',
                            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                            'SEMGREP_SEND_METRICS': 'off', 'SEMGREP_ENABLE_VERSION_CHECK': '0'})
    if result.returncode not in allowed:
        raise RuntimeError('external_command_failed')
    return result


def copy_target(source: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for name in FILES:
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('upstream_file_invalid')
        shutil.copyfile(path, destination / name)


def scan(client: TestClient, headers: dict[str, str], path: str) -> dict:
    response = client.post(path, headers=headers, json=REQUEST)
    if response.status_code != 200:
        raise RuntimeError('scan_http_failed')
    if headers['X-Local-API-Token'] in response.text:
        raise RuntimeError('token_disclosed')
    return response.json()


def pair(source: Path, root: Path, repository: Path, mode: str, expected_ids: set[str]) -> dict:
    target = root / ('target-' + mode); copy_target(source, target)
    rules = root / ('rules-' + mode); rules.mkdir(mode=0o700)
    shutil.copyfile(repository / 'rules/security-baseline.yml', rules / 'security-baseline.yml')
    token = secrets.token_urlsafe(32); headers = {'X-Local-API-Token': token}
    app = create_app(ApiSettings(target, rules, token, allowed_hosts=('testserver',)), investigation_api_enabled=True)
    with TestClient(app) as client:
        route = '/api/v2/investigation-scans/rule-bytes' if mode in ('same', 'comment') else '/api/v2/investigation-scans'
        baseline = scan(client, headers, route)
        original = baseline['scan']
        assert original['scan_status'] == 'completed' and original['finding_count'] == 2
        if mode == 'code':
            path = target / 'ejs.js'; data = path.read_text(encoding='utf-8')
            assert data.count('new Function(') == 2
            path.write_text(data.replace('new Function(', 'globalThis.Function(', 1), encoding='utf-8')
            diff = run(['git', 'diff', '--no-index', '--', str(source / 'ejs.js'), str(path)], repository, allowed=(1,))
            assert b'new Function(' in diff.stdout and b'globalThis.Function(' in diff.stdout
        elif mode == 'ignore':
            (target / '.semgrepignore').write_text('ejs.js\n', encoding='utf-8')
        elif mode == 'comment':
            with (rules / 'security-baseline.yml').open('ab') as stream:
                stream.write(b'\n# ER-D9 isolated comment-only change\n')
        current = scan(client, headers, route)
        baseline_ids = {item['finding_id'] for item in original['findings']}
        current_ids = {item['finding_id'] for item in current['scan']['findings']}
        assert baseline_ids == expected_ids
        partition = {'shared': len(baseline_ids & current_ids), 'baselineOnly': len(baseline_ids - current_ids), 'currentOnly': len(current_ids - baseline_ids)}
        same_run = client.post('/api/v2/investigations', headers=headers, json={'baseline_handle': baseline['run_handle'], 'current_handle': baseline['run_handle']})
        assert same_run.status_code == 409
        session = client.post('/api/v2/investigations', headers=headers, json={'baseline_handle': baseline['run_handle'], 'current_handle': current['run_handle']})
        assert session.status_code == 201
        handle = session.json()['investigation_handle']
        response = client.post('/api/v2/investigations/evaluate', headers=headers, json={'investigation_handle': handle})
        assert response.status_code == 200
        result = response.json()
        assert {key: sum(item['category'] == key for item in result['findings']) for key in partition} == partition
        assert 'source_snapshot_not_collected' in result['limitation_codes']
        assert 'loaded_rule_identity_unverified' in result['limitation_codes']
        assert 'scope_completeness_unverified' in result['limitation_codes']
        projection = {'partition': partition, 'scan_status': current['scan']['scan_status'], 'overall': result['overall_assessment'],
                      'ordinary_comparison': 'blocked_partial' if not current['scan']['completed'] else 'comparable'}
        if mode == 'code':
            assert partition == {'shared': 1, 'baselineOnly': 1, 'currentOnly': 0}
            assert result['overall_assessment'] == 'UNDETERMINED'
            missing = next(item for item in result['findings'] if item['category'] == 'baselineOnly')
            assert missing['path_observation'] == 'PATH_REPORTED_SCANNED'
            assert missing['source_snapshot_hypothesis'] == 'UNDETERMINED'
            projection.update(path_observation=missing['path_observation'], source_hypothesis=missing['source_snapshot_hypothesis'])
            projection['controlled_git_diff_confirmed'] = True
        if mode == 'ignore':
            assert partition == {'shared': 0, 'baselineOnly': 2, 'currentOnly': 0}
            assert current['scan']['scan_status'] == 'partial' and not current['scan']['completed']
            assert result['overall_assessment'] == 'INCOMPARABLE'
            assert all(item['path_observation'] == 'PATH_EXPLICITLY_SKIPPED' and item['skip_hypothesis'] == 'SUPPORTED' for item in result['findings'])
            scope = app.state.investigation_registry.get_run(current['run_handle']).manifest.scope_evidence
            assert any(item.path == 'ejs.js' and item.reason_code == 'semgrepignore_patterns_match' for item in scope.skipped_paths)
            projection.update(path_observation='PATH_EXPLICITLY_SKIPPED', skip_hypothesis='SUPPORTED', internal_skip_reason='semgrepignore_patterns_match')
        if mode in ('same', 'comment'):
            equality = client.post('/api/v2/investigations/rule-bytes/evaluate', headers=headers, json={'investigation_handle': handle})
            assert equality.status_code == 200
            expected = 'SAME_SELECTED_BYTES' if mode == 'same' else 'DIFFERENT_SELECTED_BYTES'
            assert equality.json()['status'] == expected and partition == {'shared': 2, 'baselineOnly': 0, 'currentOnly': 0}
            assert 'digest' not in equality.text.lower() and 'sha256' not in equality.text.lower()
            projection['rule_bytes'] = expected
        for text in (response.text, json.dumps(projection)):
            assert all(value not in text for value in (token, str(root), 'new Function(', baseline['run_handle'], current['run_handle'], handle))
        assert client.post('/api/v2/investigation-release', headers=headers, json={'kind': 'investigation', 'handle': handle}).status_code == 204
        assert client.post('/api/v2/investigations/evaluate', headers=headers, json={'investigation_handle': handle}).status_code == 404
        for entry in (baseline, current):
            assert client.post('/api/v2/investigation-release', headers=headers, json={'kind': 'run', 'handle': entry['run_handle']}).status_code == 204
        projection['released_session_status'] = 404
        return projection


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument('--browser', action='store_true'); args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    if sys.version_info[:3] != (3, 12, 7) or run(['semgrep', '--version'], repository).stdout.strip() != b'1.182.1':
        raise RuntimeError('environment_version_mismatch')
    with tempfile.TemporaryDirectory(prefix='er-d9-ejs-') as temporary:
        root = Path(temporary).resolve(); checkout = root / 'upstream'
        run(['git', '-c', 'core.hooksPath=/dev/null', 'clone', '--quiet', '--no-checkout', '--filter=blob:none', REPO, str(checkout)], root)
        run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'filter.lfs.smudge=', '-c', 'filter.lfs.required=false', '-C', str(checkout), 'checkout', '--quiet', '--detach', SHA], root)
        assert run(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], root).stdout.decode().strip() == SHA
        assert b'Apache License' in (checkout / 'LICENSE').read_bytes()
        source = checkout / 'lib/esm'
        token = secrets.token_urlsafe(32)
        app = create_app(ApiSettings(source, repository / 'rules', token, allowed_hosts=('testserver',)), investigation_api_enabled=True)
        with TestClient(app) as client:
            response = scan(client, {'X-Local-API-Token': token}, '/api/v1/scans')
            assert client.post('/api/v1/scans', headers={'X-Local-API-Token': 'incorrect'}, json=REQUEST).status_code == 401
        assert response['scan_status'] == 'completed' and response['finding_count'] == 2
        findings = [{key: item[key] for key in ('finding_id', 'rule_id', 'file_path', 'line_number', 'severity')} for item in response['findings']]
        assert all(item['file_path'] == 'ejs.js' and item['rule_id'] == 'baseline.javascript-dynamic-eval' for item in findings)
        expected_ids = {item['finding_id'] for item in response['findings']}
        results = {mode: pair(source, root, repository, mode, expected_ids) for mode in ('code', 'ignore', 'same', 'comment')}
        if args.browser:
            env = {**os.environ, 'D9_CASE': 'upstream-ignore', 'D9_UPSTREAM_DIR': str(source), 'SEMGREP_REQUIRED': '1'}
            browser = subprocess.run(['mise', 'exec', 'node@24', '--', 'npm', 'run', 'test:e2e:real'], cwd=repository / 'frontend', env=env, timeout=180)
            if browser.returncode != 0:
                raise RuntimeError('browser_e2e_failed')
        assert not run(['git', '-C', str(checkout), 'status', '--porcelain'], root).stdout
        print(json.dumps({'repository': 'mde/ejs', 'commit': SHA, 'license': 'Apache-2.0', 'scope': 'lib/esm', 'javascript_files': 3,
                          'original_findings': findings, 'scenarios': results, 'browser': 'passed' if args.browser else 'not_run',
                          'upstream_checkout_clean': True}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'ER_D9_FAILED: {type(exc).__name__}', file=sys.stderr)
        raise SystemExit(1) from None
