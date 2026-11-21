"""Shared helpers for the conformance suite. Not a test module.

Paths can be overridden so the suite runs against another checkout:
  AGIT8OR_CONNECT_VECTORS   directory of the vector files (default: ../test-vectors)
  AGIT8OR_CONNECT_SDK       directory containing the agit8or_connect package (default: ../python)
"""
import base64
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, '..'))
VECTORS = os.environ.get('AGIT8OR_CONNECT_VECTORS') or os.path.join(ROOT, 'test-vectors')
SDK = os.environ.get('AGIT8OR_CONNECT_SDK') or os.path.join(ROOT, 'python')
SCHEMAS = os.path.join(ROOT, 'schemas')
TYPESCRIPT = os.path.join(ROOT, 'typescript')

if SDK not in sys.path:
    sys.path.insert(0, SDK)


def vector(name):
    with open(os.path.join(VECTORS, name), encoding='utf-8') as f:
        return json.load(f)


def b64url_json(segment):
    return json.loads(base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4)))


def jws_parts(token):
    h, p, _ = token.split('.')
    return b64url_json(h), b64url_json(p)


# --- a minimal JSON Schema (2020-12 subset) validator -----------------------------------
# Covers exactly the keywords used in schemas/: type, required, properties,
# additionalProperties, items, const, enum, pattern, minLength, maxLength,
# minimum, maximum, minItems, maxItems, oneOf, $ref (to a sibling file).
# `format` and annotation keywords are ignored, as JSON Schema allows.

def load_schema(name):
    with open(os.path.join(SCHEMAS, name if name.endswith('.json') else name + '.schema.json'),
              encoding='utf-8') as f:
        return json.load(f)


_TYPES = {
    'object': lambda v: isinstance(v, dict),
    'array': lambda v: isinstance(v, list),
    'string': lambda v: isinstance(v, str),
    'integer': lambda v: isinstance(v, int) and not isinstance(v, bool),
    'number': lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    'boolean': lambda v: isinstance(v, bool),
    'null': lambda v: v is None,
}


def schema_errors(schema, value, path='$'):
    errs = []
    if '$ref' in schema:
        errs += schema_errors(load_schema(schema['$ref']), value, path)
    t = schema.get('type')
    if t is not None:
        ts = t if isinstance(t, list) else [t]
        if not any(_TYPES[x](value) for x in ts):
            return errs + [f'{path}: expected {t}']
    if 'const' in schema and value != schema['const']:
        errs.append(f'{path}: expected const {schema["const"]!r}')
    if 'enum' in schema and value not in schema['enum']:
        errs.append(f'{path}: not in enum')
    if isinstance(value, str):
        if 'pattern' in schema and not re.search(schema['pattern'], value):
            errs.append(f'{path}: does not match {schema["pattern"]}')
        if len(value) < schema.get('minLength', 0) or len(value) > schema.get('maxLength', 1 << 30):
            errs.append(f'{path}: length')
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if 'minimum' in schema and value < schema['minimum']:
            errs.append(f'{path}: below minimum')
        if 'maximum' in schema and value > schema['maximum']:
            errs.append(f'{path}: above maximum')
    if isinstance(value, list):
        if len(value) < schema.get('minItems', 0) or len(value) > schema.get('maxItems', 1 << 30):
            errs.append(f'{path}: item count')
        if 'items' in schema:
            for i, v in enumerate(value):
                errs += schema_errors(schema['items'], v, f'{path}[{i}]')
    if isinstance(value, dict):
        for r in schema.get('required', []):
            if r not in value:
                errs.append(f'{path}: missing {r}')
        props = schema.get('properties', {})
        for k, v in value.items():
            if k in props:
                errs += schema_errors(props[k], v, f'{path}.{k}')
            elif schema.get('additionalProperties') is False:
                errs.append(f'{path}: unexpected member {k}')
            elif isinstance(schema.get('additionalProperties'), dict):
                errs += schema_errors(schema['additionalProperties'], v, f'{path}.{k}')
    if 'oneOf' in schema:
        ok = [s for s in schema['oneOf'] if not schema_errors(s, value, path)]
        if len(ok) != 1:
            errs.append(f'{path}: matches {len(ok)} of oneOf')
    return errs
