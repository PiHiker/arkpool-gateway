import os
import json
import subprocess
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock
from runtime_packages import check, pending_updates, validate_current_report, MINIMUM
from tor_repository import verify_fingerprint, FINGERPRINT, SOURCE, PREFERENCES


class RuntimePackageTests(unittest.TestCase):
    release = 'ID=debian\nVERSION_ID="13"\n'

    def runner(self, versions):
        def run(args, **kwargs):
            if args[0] == 'dpkg-query':
                return subprocess.CompletedProcess(args, 0, versions[args[-1]])
            return subprocess.run(args, **kwargs)
        return run

    def test_fixed_and_newer_debian_versions(self):
        self.assertEqual(check(self.runner(MINIMUM), self.release), MINIMUM)
        newer = {'tor': '0.4.9.17-1~d13.trixie+1',
                 'libpcre2-8-0': '10.46-1~deb13u4',
                 'openssl': '3.5.7-1~deb13u3',
                 'libssl3t64': '3.5.7-1~deb13u3'}
        self.assertEqual(check(self.runner(newer), self.release), newer)

    def test_old_security_package_fails(self):
        for package, old in [('tor', '0.4.9.13-0+deb13u1'),
                             ('tor', '0.4.9.15-1~d13.trixie+1'),
                             ('tor', '0.4.9.16-1~d13.trixie+1'),
                             ('tor', '0.4.9.17~rc1-1'),
                             ('libpcre2-8-0', '10.46-1~deb13u2'),
                             ('openssl', '3.5.7-1~deb13u2'),
                             ('libssl3t64', '3.5.7-1~deb13u2')]:
            with self.subTest(package=package), self.assertRaises(ValueError):
                check(self.runner(dict(MINIMUM, **{package: old})), self.release)

    def test_missing_or_empty_package_fails(self):
        with self.assertRaises(subprocess.CalledProcessError):
            check(Mock(side_effect=subprocess.CalledProcessError(1, 'dpkg-query')), self.release)
        with self.assertRaises(ValueError):
            check(self.runner(dict(MINIMUM, tor='')), self.release)

    def test_wrong_distribution_fails_before_package_commands(self):
        run = Mock()
        for release in ['ID=debian\nVERSION_ID="12"', 'ID=ubuntu\nVERSION_ID="13"', '']:
            with self.assertRaises(ValueError):
                check(run, release)
        run.assert_not_called()

    def test_security_command_checks_every_container_and_propagates_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copyfile(Path(__file__).with_name('gateway.sh'), root/'gateway.sh')
            shutil.copyfile(Path(__file__).with_name('runtime_packages.py'), root/'runtime_packages.py')
            (root/'.env').touch()
            (root/'upgrade.py').write_text(
                "import pathlib,sys\n"
                "if sys.argv[1:] == ['compose','ps','--services','--status','running']:\n"
                " print('gateway\\ningress\\ntor-a\\ntor-b\\nweb\\nshhark-status'); raise SystemExit(0)\n"
                "assert sys.argv[1:4] == ['compose','exec','-T']\n"
                "assert sys.argv[5:] == ['python3','-']\n"
                "assert sys.stdin.read() == pathlib.Path('runtime_packages.py').read_text()\n"
                "with open('checked','a') as f: f.write(sys.argv[4]+'\\n')\n"
                "raise SystemExit(int(pathlib.Path('fail').exists() and sys.argv[4]=='web'))\n")
            for fail in (False, True):
                if fail:
                    (root/'fail').touch()
                result = subprocess.run(['sh', str(root/'gateway.sh'), 'security-check'], capture_output=True)
                self.assertEqual(result.returncode, int(fail))
                self.assertEqual((root/'checked').read_text().splitlines(),
                                 ['gateway','ingress','shhark-status','tor-a','tor-b','web'])
                (root/'checked').unlink()

    def test_current_security_audit_uses_disposable_deduplicated_images(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copyfile(Path(__file__).with_name('gateway.sh'), root/'gateway.sh')
            shutil.copyfile(Path(__file__).with_name('runtime_packages.py'), root/'runtime_packages.py')
            (root/'.env').touch()
            (root/'upgrade.py').write_text(
                "import sys\n"
                "if sys.argv[1:] == ['compose','ps','--services','--status','running']:\n"
                " print('gateway\\ningress\\ntor-a\\ntor-b\\nweb'); raise SystemExit(0)\n"
                "assert sys.argv[1:4] == ['compose','images','-q']\n"
                "print('sha256:transport' if sys.argv[4] in ('gateway','ingress') else 'sha256:'+('web' if sys.argv[4]=='web' else 'tor'))\n")
            docker = root/'docker'
            docker.write_text(
                "#!/bin/sh\n"
                "cat > \"$AUDIT_STDIN\"\n"
                "printf '%s\\n' \"$*\" >> \"$AUDIT_LOG\"\n"
                "case \"$*\" in *sha256:tor*) test ! -e \"$AUDIT_FAIL\" || exit 1;; esac\n"
                "printf '%s\\n' '{\"security_floors_met\":true,\"pending_updates_checked\":true,\"pending_update_count\":0}'\n")
            docker.chmod(0o700)
            environment = dict(PATH=str(root) + ':' + os.environ['PATH'],
                               AUDIT_LOG=str(root/'audit.log'), AUDIT_FAIL=str(root/'fail'),
                               AUDIT_STDIN=str(root/'audit.stdin'))
            for fail in (False, True):
                if fail:
                    (root/'fail').touch()
                result = subprocess.run(['sh', str(root/'gateway.sh'), 'security-audit'],
                                        cwd=root, env=environment, capture_output=True)
                self.assertEqual(result.returncode, int(fail))
                commands = (root/'audit.log').read_text().splitlines()
                self.assertEqual(len(commands), 3)
                self.assertEqual((root/'audit.stdin').read_text(), (root/'runtime_packages.py').read_text())
                self.assertTrue(all('--pull never' in line and '--network bridge' in line
                                    and '--interactive' in line and 'python3 - --check-upgradable' in line
                                    and '--cap-drop ALL' in line and '--user 0' in line
                                    and '--tmpfs /var/cache/apt:' in line
                                    and 'APT::Sandbox::User=root' in line
                                    and 'APT::Update::Error-Mode=any' in line
                                    and '--mount' not in line and ' -v ' not in line
                                    for line in commands))
                (root/'audit.log').unlink()

    def test_security_inventory_failure_and_invalid_names_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copyfile(Path(__file__).with_name('gateway.sh'), root/'gateway.sh')
            (root/'.env').touch()
            for mode in ('failure', 'invalid'):
                (root/'upgrade.py').write_text(
                    "import sys\n"
                    "assert sys.argv[1:] == ['compose','ps','--services','--status','running']\n"
                    + ("raise SystemExit(1)\n" if mode == 'failure' else "print('gateway\\n*')\n"))
                for command in ('security-check', 'security-audit'):
                    with self.subTest(mode=mode, command=command):
                        result = subprocess.run(['sh', str(root/'gateway.sh'), command],
                                                capture_output=True)
                        self.assertNotEqual(result.returncode, 0)

    def test_missing_core_service_is_still_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copyfile(Path(__file__).with_name('gateway.sh'), root/'gateway.sh')
            shutil.copyfile(Path(__file__).with_name('runtime_packages.py'), root/'runtime_packages.py')
            (root/'.env').touch()
            (root/'upgrade.py').write_text(
                "import sys\n"
                "if sys.argv[1:] == ['compose','ps','--services','--status','running']:\n"
                " print('gateway\\ningress\\ntor-a'); raise SystemExit(0)\n"
                "assert sys.argv[1:4] == ['compose','exec','-T']\n"
                "sys.stdin.read()\n"
                "with open('checked','a') as f: f.write(sys.argv[4]+'\\n')\n"
                "raise SystemExit(int(sys.argv[4]=='tor-b'))\n")
            result = subprocess.run(['sh', str(root/'gateway.sh'), 'security-check'], capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual((root/'checked').read_text().splitlines(), ['gateway','ingress','tor-a','tor-b'])

    def test_current_report_requires_explicit_completed_zero_update_audit(self):
        current = '{"security_floors_met":true,"pending_updates_checked":true,"pending_update_count":0}'
        self.assertTrue(validate_current_report(current)['pending_updates_checked'])
        for report in ('{}',
                       '{"security_floors_met":true}',
                       '{"security_floors_met":true,"pending_updates_checked":false,"pending_update_count":0}',
                       '{"security_floors_met":true,"pending_updates_checked":true,"pending_update_count":1}',
                       'not-json'):
            with self.subTest(report=report), self.assertRaises((ValueError, json.JSONDecodeError)):
                validate_current_report(report)

    def test_official_primary_key_and_subkey(self):
        listing = f'pub:::::::::\nfpr:::::::::{FINGERPRINT}:\nsub:::::::::\nfpr:::::::::OTHER_SUBKEY:\n'
        verify_fingerprint(listing)

    def test_missing_wrong_or_additional_keys_fail(self):
        good = f'pub:::::::::\nfpr:::::::::{FINGERPRINT}:\n'
        for listing in ['', 'pub:::::::::\n', good.replace(FINGERPRINT, '0' * 40),
                        good + good, good + 'pub:::::::::\n',
                        good + 'pub:::::::::\nfpr:::::::::OTHER:\n']:
            with self.subTest(listing=listing), self.assertRaises(ValueError):
                verify_fingerprint(listing)

    def test_repository_trust_is_scoped(self):
        self.assertIn('Signed-By: /usr/share/keyrings/arkpool-tor-archive.gpg', SOURCE)
        self.assertIn('Suites: trixie\n', SOURCE)
        self.assertNotIn('Trusted:', SOURCE)
        self.assertIn('Package: tor tor-geoipdb\n', PREFERENCES)
        self.assertIn('Package: *\nPin: origin deb.torproject.org\nPin-Priority: -1', PREFERENCES)

    def test_pending_update_parser_is_strict(self):
        def runner(output):
            return lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, output)
        self.assertEqual(pending_updates(runner('Listing...\n')), ())
        self.assertEqual(pending_updates(runner(
            'Listing...\nliblzma5/stable-security 5.8 amd64 [upgradable from: 5.7]\n'
            'tor/stable 0.4.9 amd64 [upgradable from: 0.4.8]\n')), ('liblzma5', 'tor'))
        for invalid in ('unexpected output\n', '../escape/stable 1 amd64\n', '/stable 1 amd64\n'):
            with self.subTest(output=invalid), self.assertRaises(ValueError):
                pending_updates(runner(invalid))

    def test_runtime_image_excludes_tests_and_requires_current_packages(self):
        dockerfile = Path(__file__).with_name('Dockerfile').read_text()
        dockerignore = Path(__file__).with_name('.dockerignore').read_text().splitlines()
        self.assertIn('!bounded_http.py', dockerignore)
        self.assertIn('apt-get dist-upgrade -y', dockerfile)
        self.assertIn('apt-get purge -y mount', dockerfile)
        self.assertIn('test ! -e /usr/bin/mount && test ! -e /usr/bin/umount', dockerfile)
        self.assertNotIn('--allow-remove-essential', dockerfile)
        self.assertIn('runtime_packages.py --check-upgradable', dockerfile)
        self.assertEqual(dockerfile.count('APT::Update::Error-Mode=any'), 3)
        self.assertLess(dockerfile.index('runtime_packages.py --check-upgradable'),
                        dockerfile.index('rm -rf /var/lib/apt/lists'))
        self.assertRegex(dockerfile.splitlines()[0],
                         r'^FROM .+@sha256:[0-9a-f]{64} AS tor-repository$')
        self.assertIn('FROM runtime-base AS test', dockerfile)
        self.assertIn('FROM runtime-base AS runtime', dockerfile)
        test_stage, runtime_stage = dockerfile.split('FROM runtime-base AS test', 1)[1].split(
            'FROM runtime-base AS runtime', 1)
        self.assertIn('tests.py tests_tls.py tests_dashboard.py', test_stage)
        self.assertNotIn('tests.py', runtime_stage)


if __name__ == '__main__':
    unittest.main()
