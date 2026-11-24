#!/usr/bin/env python3
"""Reconstruct and publish the exact pre-signed Normal APK. The feed is separate."""

import base64
import datetime
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.request
from pathlib import Path

REPO = 'JMosh89/Walkcraft-Descargas'
TAG = 'v0.9.23'
BRANCH = 'walkcraft-release-0.9.23'
ROOT = f'release-data/{TAG}'
ASSET = 'Walkcraft-Android-0.9.23-Normal.apk'
RELEASES = f'repos/{REPO}/releases'
BASE_URL = f'https://github.com/{REPO}/releases/download/v0.9.22/Walkcraft-Android-0.9.22-Normal.apk'
ASSET_URL = f'https://github.com/{REPO}/releases/download/{TAG}/{ASSET}'
TITLE = 'Walkcraft 0.9.23 — Torre de Dios, recompensas y avisos de Android'


def gh(args, *, body=None, check=True):
    result = subprocess.run(['gh', *args], input=body, capture_output=True, text=True, timeout=600)
    if check and result.returncode:
        raise RuntimeError(f'GitHub operation failed: {result.stderr.strip()[:500]}')
    return result


def api(path):
    return json.loads(gh(['api', path]).stdout)


def mutate(method, path, data):
    return json.loads(gh(['api', '--method', method, path, '--input', '-'], body=json.dumps(data)).stdout)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify(path, expected):
    if Path(path).stat().st_size != expected['size'] or digest(path) != expected['sha256']:
        raise RuntimeError(f'APK size or digest mismatch: {path}')


def download(url, path, expected):
    request = urllib.request.Request(url, headers={'User-Agent': 'Walkcraft-release-verifier/0.9.23'})
    with urllib.request.urlopen(request, timeout=120) as source, open(path, 'wb') as target:
        if source.status != 200:
            raise RuntimeError(f'Unexpected HTTP status: {source.status}')
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            target.write(chunk)
            if target.tell() > expected['size']:
                raise RuntimeError('Download exceeded expected APK size')
    verify(path, expected)


def record(result):
    path = f'repos/{REPO}/contents/{ROOT}/result.json'
    saved = gh(['api', f'{path}?ref={BRANCH}'], check=False)
    data = {'branch': BRANCH, 'message': f'Record Walkcraft {TAG} publication',
            'content': base64.b64encode((json.dumps(result, indent=2) + '\n').encode()).decode()}
    if saved.returncode == 0:
        data['sha'] = json.loads(saved.stdout)['sha']
    elif 'HTTP 404' not in saved.stderr:
        raise RuntimeError('Unable to inspect the publication record on its staging branch')
    mutate('PUT', path, data)


def validate(start):
    if start['tag'] != TAG or start['output']['name'] != ASSET or start['base']['url'] != BASE_URL:
        raise RuntimeError('Release metadata names another artifact')
    if not re.fullmatch(r'[0-9a-f]{40}', start['target_commitish']):
        raise RuntimeError('Release target must be an immutable main-branch commit')
    for data in (start['base'], start['output']):
        if type(data['size']) is not int or data['size'] <= 0 or not re.fullmatch(r'[0-9a-f]{64}', data['sha256']):
            raise RuntimeError('Invalid expected APK metadata')
    if digest('patch.gz') != start['patch_sha256']:
        raise RuntimeError('Patch transfer digest mismatch')


def find_release(marker, target, body):
    pages = json.loads(gh(['api', '--paginate', '--slurp', f'{RELEASES}?per_page=100']).stdout)
    matches = [release for page in pages for release in page if release['tag_name'] == TAG]
    if len(matches) > 1:
        raise RuntimeError('More than one release has the requested tag')
    if matches:
        release = matches[0]
        if marker not in (release.get('body') or '').splitlines() or release['target_commitish'] != target:
            raise RuntimeError('The existing release does not match these signed bytes and target')
        return release
    ref = gh(['api', f'repos/{REPO}/git/ref/tags/{TAG}'], check=False)
    if ref.returncode == 0 or 'HTTP 404' not in ref.stderr:
        raise RuntimeError('Cannot safely create the release tag')
    relation = gh(['api', f'repos/{REPO}/compare/{target}...main?per_page=1', '--jq', '.status']).stdout.strip()
    if relation not in ('identical', 'ahead'):
        raise RuntimeError('The pinned release target does not belong to main')
    return mutate('POST', RELEASES, {'tag_name': TAG, 'target_commitish': target, 'name': TITLE, 'body': body,
                                    'draft': True, 'prerelease': False})


def matching_asset(release):
    matches = [asset for asset in release['assets'] if asset['name'] == ASSET]
    if len(matches) > 1:
        raise RuntimeError('Duplicate matching release assets')
    return matches[0] if matches else None


if (os.environ.get('GITHUB_REPOSITORY'), os.environ.get('GITHUB_REF')) != (REPO, f'refs/heads/{BRANCH}'):
    raise SystemExit('Refusing to publish outside the exact Walkcraft staging branch')

phase = 'initialization'
result = {'status': 'FAILED', 'repository': REPO, 'tag': TAG, 'source_commit': os.environ['GITHUB_SHA'],
          'run_id': os.environ.get('GITHUB_RUN_ID'), 'feed_modified': False, 'signing_key_used': False}
try:
    start = json.loads(Path('start.json').read_text(encoding='utf-8'))
    validate(start)
    phase = 'baseline-download'
    download(start['base']['url'], 'baseline.apk', start['base'])
    phase = 'artifact-reconstruction'
    subprocess.run(['python3', 'delta.py', 'apply', 'baseline.apk', 'patch.gz', ASSET, '--metadata', 'start.json'],
                   check=True, timeout=600)
    output = start['output']
    verify(ASSET, output)

    phase = 'draft-creation'
    marker = f"APK SHA-256: {output['sha256']}"
    body = Path('notes.md').read_text(encoding='utf-8').rstrip() + f'\n\n{marker}\n'
    release = find_release(marker, start['target_commitish'], body)
    endpoint = f"{RELEASES}/{release['id']}"
    phase = 'asset-upload'
    if not matching_asset(release):
        if not release['draft']:
            raise RuntimeError('Published release is missing the exact expected APK')
        gh(['release', 'upload', TAG, ASSET, '--repo', REPO])

    phase = 'authenticated-download-verification'
    Path('verified').mkdir(exist_ok=True)
    gh(['release', 'download', TAG, '--pattern', ASSET, '--dir', 'verified', '--repo', REPO, '--clobber'])
    verify(Path('verified') / ASSET, output)

    phase = 'publication'
    release = api(endpoint)
    if release['draft']:
        release = mutate('PATCH', endpoint, {'draft': False, 'prerelease': False, 'make_latest': 'true'})
    asset = matching_asset(release)
    if release['draft'] or not asset or asset['browser_download_url'] != ASSET_URL or asset['size'] != output['size']:
        raise RuntimeError('Published release metadata does not match the verified APK')

    phase = 'anonymous-download-verification'
    for attempt in range(3):
        try:
            download(ASSET_URL, 'public.apk', output)
            break
        except Exception:
            if attempt == 2:
                raise
            time.sleep(3 * (attempt + 1))

    result.update(status='PUBLIC_DOWNLOAD_VERIFIED', release_id=release['id'], release_url=release['html_url'],
                  asset_id=asset['id'], asset_url=ASSET_URL, sha256=output['sha256'], size_bytes=output['size'],
                  published_at=release['published_at'], verified_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  target_commitish=start['target_commitish'], anonymous_download_verified=True)
except Exception as error:
    result.update(phase=phase, error=str(error)[:750])
    raise
finally:
    try:
        record(result)
    finally:
        print(json.dumps(result, sort_keys=True), flush=True)
