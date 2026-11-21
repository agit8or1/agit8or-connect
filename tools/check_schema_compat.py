"""Backward-compatibility check of schemas/ and test-vectors/ against a base git revision.

    python tools/check_schema_compat.py [BASE]        (default: origin/main)

Fails (exit 1) when a change could break an existing peer or verifier within the major version:
- a schema file or an existing test-vector file was removed, or a vector file's bytes changed;
- a property was removed, or a type, const or format changed;
- a property became required, or an enum lost a value;
- `additionalProperties` was tightened (true/absent -> false or a schema).
Additions (new files, new optional properties, new enum values) are allowed.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def git_show(base: str, path: str):
    r = subprocess.run(['git', 'show', f'{base}:{path}'], cwd=ROOT, capture_output=True)
    return r.stdout if r.returncode == 0 else None


def git_ls(base: str, directory: str):
    r = subprocess.run(['git', 'ls-tree', '--name-only', f'{base}', f'{directory}/'], cwd=ROOT, capture_output=True,
                       text=True, check=True)
    return [os.path.basename(p) for p in r.stdout.split()]


def compare(old, new, where: str, problems: list):
    if not isinstance(old, dict) or not isinstance(new, dict):
        if old != new:
            problems.append(f'{where}: changed')
        return
    for k in ('type', 'const', 'format', 'pattern', '$ref'):
        if k in old and old.get(k) != new.get(k):
            problems.append(f'{where}: {k} changed {old.get(k)!r} -> {new.get(k)!r}')
    added_req = set(new.get('required', [])) - set(old.get('required', []))
    if added_req:
        problems.append(f'{where}: newly required {sorted(added_req)}')
    if 'enum' in old:
        lost = [v for v in old['enum'] if v not in new.get('enum', [])]
        if lost:
            problems.append(f'{where}: enum lost {lost}')
    oap, nap = old.get('additionalProperties', True), new.get('additionalProperties', True)
    if oap is True and nap is not True:
        problems.append(f'{where}: additionalProperties tightened')
    for name, sub in (old.get('properties') or {}).items():
        if name not in (new.get('properties') or {}):
            problems.append(f'{where}.{name}: property removed')
        else:
            compare(sub, new['properties'][name], f'{where}.{name}', problems)
    for key in ('items', 'additionalProperties'):
        if isinstance(old.get(key), dict) and isinstance(new.get(key), dict):
            compare(old[key], new[key], f'{where}[{key}]', problems)
    for key in ('oneOf', 'anyOf', 'allOf'):
        if key in old and len(new.get(key, [])) < len(old[key]):
            problems.append(f'{where}: {key} lost alternatives')


def main(argv) -> int:
    base = argv[0] if argv else 'origin/main'
    problems: list = []
    for name in git_ls(base, 'schemas'):
        old = git_show(base, f'schemas/{name}')
        path = os.path.join(ROOT, 'schemas', name)
        if not os.path.exists(path):
            problems.append(f'schemas/{name}: removed')
            continue
        with open(path, 'rb') as f:
            compare(json.loads(old), json.loads(f.read()), name, problems)
    for name in git_ls(base, 'test-vectors'):
        old = git_show(base, f'test-vectors/{name}')
        path = os.path.join(ROOT, 'test-vectors', name)
        if not os.path.exists(path):
            problems.append(f'test-vectors/{name}: removed')
            continue
        with open(path, 'rb') as f:
            if f.read() != old:
                problems.append(f'test-vectors/{name}: bytes changed (existing vectors never change)')
    for p in problems:
        print('INCOMPATIBLE', p)
    print(f'compared against {base}: {len(problems)} problem(s)')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
