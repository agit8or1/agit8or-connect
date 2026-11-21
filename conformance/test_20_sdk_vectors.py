"""Both reference SDKs reproduce and verify every vector file.

Python: the SDK's own vector tests (python/agit8or_connect/tests/test_vectors.py
and test_qc_vectors.py) are loaded into this suite, pointed at the vectors in
use (AGIT8OR_CONNECT_VECTORS).
TypeScript: `node --test` runs typescript/test/*.test.ts against the same
directory. Without Node the TypeScript test is skipped, unless
CONFORMANCE_REQUIRE_NODE=1 (CI) turns that into a failure."""
import os
import shutil
import subprocess
import unittest

from _support import TYPESCRIPT, VECTORS

os.environ['AGIT8OR_CONNECT_VECTORS'] = VECTORS


def load_tests(loader, standard_tests, pattern):
    from agit8or_connect.tests import test_qc_vectors, test_vectors
    suite = unittest.TestSuite(standard_tests)
    for mod in (test_vectors, test_qc_vectors):
        mod.DIR = VECTORS
        suite.addTests(loader.loadTestsFromModule(mod))
    return suite


class TypeScriptSdkVectors(unittest.TestCase):
    def test_node_test_passes(self):
        node = shutil.which('node')
        if node is None:
            if os.environ.get('CONFORMANCE_REQUIRE_NODE') == '1':
                self.fail('node not found and CONFORMANCE_REQUIRE_NODE=1')
            self.skipTest('node not installed')
        tests = sorted(os.path.join('test', n) for n in os.listdir(os.path.join(TYPESCRIPT, 'test'))
                       if n.endswith('.test.ts'))
        r = subprocess.run([node, '--test', *tests], cwd=TYPESCRIPT, capture_output=True, text=True,
                           env=dict(os.environ, AGIT8OR_CONNECT_VECTORS=VECTORS), timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout[-4000:] + r.stderr[-2000:])
        self.assertIn('# fail 0', r.stdout)


if __name__ == '__main__':
    unittest.main()
