# agit8or-connect (Python reference SDK)

> Draft. Not yet independently security-reviewed. Do not describe or deploy it as production secure.

Reference implementation of the Agit8or Connect protocol `agit8or-connect/1` and the
optional revision 1.1 Quick Connect extensions. Runtime dependencies: `cryptography`
and `PyJWT`. No web framework.

```bash
pip install -e .              # or: pip install cryptography PyJWT
python -m unittest discover   # SDK tests, run from this directory
python -m agit8or_connect.tools.generate_vectors --check   # vectors on disk are what the SDK produces
```

`PyYAML` is optional; without it the test that compares `openapi/openapi.yaml` with the
vectors is skipped (the conformance suite checks the JSON Schemas instead).

Set `AGIT8OR_CONNECT_VECTORS=/path/to/test-vectors` to run against another copy of the
vectors. Modules are listed in `agit8or_connect/__init__.py`. `agit8or_connect.reference_peer`
is a complete in-memory implementation of both roles; it is test code, not production code.
