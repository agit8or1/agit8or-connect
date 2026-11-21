# Security policy

Agit8or Connect is a **draft** protocol with reference SDKs. It has **not** been independently security-reviewed.
Do not rely on it as production secure.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** through GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability** (GitHub security advisories).

Do not open a public issue or pull request for a vulnerability, and do not include exploit details in public
discussions. If private reporting is unavailable, open a public issue that only asks for a private contact channel,
without any details.

Useful in a report: the affected document section, SDK function or vector file; the protocol revision; a minimal
reproduction (for example a vector-style input and the expected vs actual error code); and the impact you see.

## What is in scope

- The specifications in `docs/` (a design flaw is a vulnerability even if both SDKs implement it faithfully).
- The Python and TypeScript SDKs, the vector generator and the reference peer.
- The conformance suite, where it would pass an insecure implementation.

Out of scope: the published TEST-ONLY keys in `test-vectors/` (they are public on purpose), and the example peers
in `examples/` (they are not hardened).

## Response

Reports are acknowledged as soon as practical. Fixes to the specification are published as a new protocol revision
or extension with new vectors, together with an advisory. There is no bug bounty.

## Supported versions

Only the latest release on the default branch receives fixes while the protocol is a draft.
