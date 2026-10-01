"""Exercise restore disk use and cancellation with real zip/zstd/tar files."""
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ci_tier_artifacts import restore_handoff
from ci_tier_plan import make_plan


class LocalArtifacts:
    """Replace only the GitHub boundary; restoration and files are real."""
    repository = 'sysown/proxysql'

    def __init__(self, archive, name):
        self.archive = Path(archive)
        self.name = name
        self.scratch = None

    def artifacts(self, run_id):
        return [dict(id=9, name=self.name, expired=False,
                     size_in_bytes=self.archive.stat().st_size)]

    def download(self, path, target, size, **kwargs):
        self.scratch = Path(target).parent
        shutil.copyfile(self.archive, target)


class RestoreDiskTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.runner_temp = self.root / 'runner-temp'
        self.runner_temp.mkdir()
        self.env = patch.dict(os.environ, {'RUNNER_TEMP': str(self.runner_temp)})
        self.env.start()
        self.addCleanup(self.env.stop)
        ctx = dict(repository='sysown/proxysql', sha='a'*40, control_sha='b'*40,
                   trigger_id=1, trigger_attempt=1, build_id=2, build_attempt=1)
        self.plan = make_plan(ctx, dict(tiers=['v30'], mode='asan'), {'consumers': []})
        self.leg = self.plan['legs'][0]
        self.destination = self.root / 'restored'

    def artifact(self, extra=(), corrupt=False):
        metadata = dict(execution_id=self.plan['execution_id'], sha=self.plan['sha'],
                        tier='v30', mode='asan')
        entries = [('src/proxysql', b'#!/bin/sh\necho "ProxySQL version 3.0.12"\n'),
                   ('src/ci-tier.json', json.dumps(metadata).encode()), *extra]
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as archive:
            for name, content in entries:
                member = name if isinstance(name, tarfile.TarInfo) else tarfile.TarInfo(name)
                member.mode = 0o755 if member.name == 'src/proxysql' else 0o644
                if member.isfile():
                    member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        packed = subprocess.check_output(['zstd', '-q', '-c'], input=data.getvalue())
        if corrupt:
            # A valid tar followed by a corrupt zstd frame: stopping at tar EOF
            # without checking the decompressor exit status would accept it.
            packed += b'not a zstd frame'
        target = self.root / 'artifact.zip'
        with zipfile.ZipFile(target, 'w') as archive:
            archive.writestr('cache_full.tar.zst', packed)
        return LocalArtifacts(target, self.leg['artifact_name'])

    def test_restore_fits_without_an_uncompressed_archive_on_disk(self):
        # Every final file fits the 1 MiB per-file limit; a 4 MiB intermediate
        # tar does not. Run the limit in a child so the test runner is unaffected.
        api = self.artifact([(f'test/payload-{i}', b'x' * (1024*1024)) for i in range(4)])
        script = '''
import json, resource, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from test_ci_tier_restore_disk import LocalArtifacts, restore_handoff
plan = json.loads(sys.argv[2]); leg = plan['legs'][0]
resource.setrlimit(resource.RLIMIT_FSIZE, (1024*1024, 1024*1024))
restore_handoff(plan, leg, Path(sys.argv[4]), LocalArtifacts(sys.argv[3], leg['artifact_name']))
'''
        result = subprocess.run([sys.executable, '-c', script, str(Path(__file__).parent),
                                 json.dumps(self.plan), str(api.archive), str(self.destination)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for i in range(4):
            self.assertEqual((self.destination / f'test/payload-{i}').read_bytes(), b'x' * (1024*1024))
        self.assertEqual(list(self.runner_temp.iterdir()), [])

    def test_success_and_download_failure_clean_job_scoped_scratch(self):
        for fail in (False, True):
            with self.subTest(fail=fail):
                api = self.artifact()
                if fail:
                    download = api.download
                    def interrupted(*args, **kwargs):
                        download(*args, **kwargs)
                        raise OSError('download interrupted')
                    api.download = interrupted
                    with self.assertRaisesRegex(OSError, 'download interrupted'):
                        restore_handoff(self.plan, self.leg, self.destination, api)
                else:
                    restore_handoff(self.plan, self.leg, self.destination, api)
                self.assertEqual(api.scratch.parent, self.runner_temp)
                self.assertFalse(api.scratch.exists())

    def test_forced_cancellation_leaves_scratch_in_runner_managed_temp(self):
        api = self.artifact()
        marker = self.root / 'scratch-path'
        script = '''
import json, os, signal, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from test_ci_tier_restore_disk import LocalArtifacts, restore_handoff
plan = json.loads(sys.argv[2]); leg = plan['legs'][0]
class KilledDownload(LocalArtifacts):
    def download(self, path, target, size, **kwargs):
        super().download(path, target, size, **kwargs)
        Path(sys.argv[5]).write_text(str(self.scratch))
        os.kill(os.getpid(), signal.SIGKILL)
restore_handoff(plan, leg, Path(sys.argv[4]), KilledDownload(sys.argv[3], leg['artifact_name']))
'''
        result = subprocess.run([sys.executable, '-c', script, str(Path(__file__).parent),
                                 json.dumps(self.plan), str(api.archive), str(self.destination), str(marker)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
        scratch = Path(marker.read_text())
        # Explicit cleanup also handles the old implementation's /tmp leak
        # when this regression is run against the pre-fix code.
        self.addCleanup(shutil.rmtree, scratch, True)
        self.assertTrue((scratch / 'handoff.zip').is_file())
        self.assertEqual(scratch.parent, self.runner_temp)

    def test_unsafe_member_is_rejected_before_any_files_are_extracted(self):
        api = self.artifact([('../escape', b'bad')])
        with self.assertRaisesRegex(ValueError, 'unsafe handoff'):
            restore_handoff(self.plan, self.leg, self.destination, api)
        self.assertFalse((self.destination / 'src/proxysql').exists())
        self.assertFalse((self.root / 'escape').exists())
        self.assertEqual(list(self.runner_temp.iterdir()), [])

    def test_corrupt_zstd_is_rejected_even_after_tar_end_marker(self):
        api = self.artifact(corrupt=True)
        with self.assertRaises(subprocess.CalledProcessError):
            restore_handoff(self.plan, self.leg, self.destination, api)
        self.assertFalse((self.destination / 'src/proxysql').exists())
        self.assertEqual(list(self.runner_temp.iterdir()), [])

    def test_local_use_without_runner_temp_still_works(self):
        api = self.artifact()
        with patch.dict(os.environ):
            os.environ.pop('RUNNER_TEMP', None)
            restore_handoff(self.plan, self.leg, self.destination, api)
        self.assertTrue((self.destination / 'src/proxysql').is_file())
        self.assertFalse(api.scratch.exists())

    def test_streamed_restore_preserves_in_tree_symlinks_and_hardlinks(self):
        symlink = tarfile.TarInfo('test/nested/link')
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = '../../src/ci-tier.json'
        hardlink = tarfile.TarInfo('test/hardlink')
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = 'src/ci-tier.json'
        api = self.artifact([(symlink, b''), (hardlink, b'')])
        (self.destination / 'test').mkdir(parents=True)
        (self.destination / 'test/hardlink').write_text('preexisting checkout file')
        for attempt in range(2):
            with self.subTest(attempt=attempt):
                restore_handoff(self.plan, self.leg, self.destination, api)
                metadata = self.destination / 'src/ci-tier.json'
                self.assertEqual((self.destination / 'test/nested/link').read_bytes(), metadata.read_bytes())
                self.assertEqual((self.destination / 'test/hardlink').stat().st_ino, metadata.stat().st_ino)

    def test_extraction_failure_stops_decompressor_and_cleans_scratch(self):
        api = self.artifact([('test/large', b'x' * (4*1024*1024))])
        self.destination.mkdir()
        (self.destination / 'src').write_text('cannot extract src/proxysql here')
        script = '''
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from test_ci_tier_restore_disk import LocalArtifacts, restore_handoff
plan = json.loads(sys.argv[2]); leg = plan['legs'][0]
try:
    restore_handoff(plan, leg, Path(sys.argv[4]), LocalArtifacts(sys.argv[3], leg['artifact_name']))
except NotADirectoryError:
    pass
else:
    raise AssertionError('extraction should fail')
'''
        result = subprocess.run([sys.executable, '-c', script, str(Path(__file__).parent),
                                 json.dumps(self.plan), str(api.archive), str(self.destination)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list(self.runner_temp.iterdir()), [])

    def test_hardlink_replacement_validates_paths_before_removing_files(self):
        outside = self.root / 'outside'
        outside.write_text('preserve outside file')
        (self.destination / 'test').mkdir(parents=True)
        link = self.destination / 'test/link'
        target = self.destination / 'test/target'
        member = tarfile.TarInfo('test/link')
        member.type = tarfile.LNKTYPE
        member.linkname = 'test/target'
        api = self.artifact([(member, b'')])
        for escape in ('destination', 'target'):
            with self.subTest(escape=escape):
                for path in (link, target):
                    path.unlink(missing_ok=True)
                if escape == 'destination':
                    link.symlink_to(outside)
                    target.write_text('inside')
                else:
                    link.write_text('preserve existing link destination')
                    target.symlink_to(outside)
                with self.assertRaises(tarfile.FilterError):
                    restore_handoff(self.plan, self.leg, self.destination, api)
                self.assertEqual(outside.read_text(), 'preserve outside file')
                self.assertEqual(link.is_symlink(), escape == 'destination')
                if escape == 'target':
                    self.assertEqual(link.read_text(), 'preserve existing link destination')
                self.assertEqual(list(self.runner_temp.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
