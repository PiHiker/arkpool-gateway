"""Reject dependency regressions before publishing the translator binary."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).parent / 'scripts/verify-translator-dependencies.sh'


class TranslatorDependencies(unittest.TestCase):
    def check(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'dependencies.txt'
            path.write_text(text)
            return subprocess.run(['sh', str(SCRIPT), str(path)], capture_output=True).returncode

    def test_accepts_patched_minimal_graph_with_optional_anyhow(self):
        graph = 'translator_sv2 v0.8.0 (/source/miner-apps/translator)\ntokio v1.53.3\n'
        self.assertEqual(self.check(graph), 0)
        self.assertEqual(self.check(graph + 'anyhow v1.0.103\n'), 0)

    def test_rejects_old_versions_even_alongside_patched_copy(self):
        graph = 'translator_sv2 v0.8.0 (/source)\ntokio v1.53.3\n'
        for entry in ('tokio v1.52.3', 'anyhow v1.0.102'):
            with self.subTest(entry=entry):
                self.assertNotEqual(self.check(graph + entry + '\n'), 0)

    def test_rejects_monitoring_and_tls_dependencies(self):
        graph = 'translator_sv2 v0.8.0 (/source)\ntokio v1.53.3\n'
        for package in ('asic-rs', 'axum', 'prometheus', 'protobuf', 'quinn', 'quinn-proto',
                        'quinn-udp', 'reqwest', 'rustls', 'rustls-webpki', 'webpki-roots',
                        'webpki-root-certs'):
            with self.subTest(package=package):
                self.assertNotEqual(self.check(graph + package + ' v1.0.0\n'), 0)
        self.assertNotEqual(self.check(''), 0)
        self.assertNotEqual(self.check('tokio v1.53.3\n'), 0)


if __name__ == '__main__':
    unittest.main()
