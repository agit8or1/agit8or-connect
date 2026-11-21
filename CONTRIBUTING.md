# Contributing

Thanks for helping. This repository is a protocol specification first and code second, so changes are reviewed
for interoperability before anything else.

## Ground rules

- **Specification changes** start as an issue describing the problem, the proposed wire change and how a 1.0 peer is
  affected. Additive changes go into a new, negotiated extension; nothing in an existing major version changes
  bytes or meaning.
- **Vectors are pinned.** Never hand-edit `test-vectors/`. Change the generator
  (`python/agit8or_connect/tools/generate_vectors.py`), regenerate, update `conformance/VECTORS.sha256`, and explain
  in the pull request why existing vectors changed (they normally must not).
- **Both SDKs move together.** A change to a message or a check lands in Python and TypeScript in the same pull
  request, and both pass the shared vectors.
- **Schemas are generated.** Edit `openapi/openapi.yaml` or `tools/build_schemas.py`, then run
  `python tools/build_schemas.py`.
- **No secrets, no deployment details.** Do not add real keys, tokens, host names, internal addresses or e-mail
  addresses. Use `example.test` / `example.com` names and the documentation address ranges (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).
- **No marketing comparisons** with other products in documents.
- Security issues: follow [SECURITY.md](SECURITY.md), not the public tracker.

## Before opening a pull request

```bash
cd python && python -m unittest discover && python -m agit8or_connect.tools.generate_vectors --check && cd ..
cd typescript && npm test && cd ..
python tools/build_schemas.py --check
cd conformance && CONFORMANCE_REQUIRE_NODE=1 python -m unittest discover && cd ..
```

CI runs the same commands. Add a [CHANGELOG.md](CHANGELOG.md) entry under "Unreleased".

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
