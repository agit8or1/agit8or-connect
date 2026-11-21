"""Vector integrity: the published files are exactly the pinned ones, and the
Python reference generator reproduces every byte of them.

The digests in VECTORS.sha256 are the authoritative identity of this vector
set. An implementation that ships its own copy of the vectors can compare it
with `sha256sum -c conformance/VECTORS.sha256` (run inside test-vectors/), or
run this suite with AGIT8OR_CONNECT_VECTORS pointing at its copy."""
import hashlib
import os
import unittest

from _support import HERE, VECTORS

MANIFEST = os.path.join(HERE, 'VECTORS.sha256')


def pinned():
    out = {}
    with open(MANIFEST, encoding='utf-8') as f:
        for line in f:
            if line.strip():
                digest, name = line.split()
                out[name.lstrip('*')] = digest
    return out


class VectorDigests(unittest.TestCase):
    def test_every_file_matches_its_pinned_digest(self):
        expected = pinned()
        present = sorted(n for n in os.listdir(VECTORS) if n.endswith('.json'))
        self.assertEqual(present, sorted(expected), 'vector file set differs from VECTORS.sha256')
        for name, digest in expected.items():
            with open(os.path.join(VECTORS, name), 'rb') as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest, name)

    def test_every_file_is_labelled_test_only(self):
        for name in pinned():
            if name in ('canonical-json.json', 'audit-chain.json'):
                continue  # no keys or signatures in these
            with open(os.path.join(VECTORS, name), encoding='utf-8') as f:
                self.assertIn('TEST-ONLY', f.read(), name)


class GeneratorReproducesVectors(unittest.TestCase):
    def test_generator_check(self):
        from agit8or_connect.tools import generate_vectors as g
        g.OUT = VECTORS
        self.assertEqual(g.main(['--check']), 0)


if __name__ == '__main__':
    unittest.main()
