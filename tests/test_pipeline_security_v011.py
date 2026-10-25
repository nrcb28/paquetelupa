"""Regressions for confirmed output-path/privacy and supervisor deadline gaps.

All filesystem cases use synthetic files in a TemporaryDirectory. The blocked
IPC case uses a controlled fake endpoint and releases it even on test failure;
it never leaves a blocked process or an unbounded receiver thread behind.
"""

import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

from paquetelupa import __main__ as cli
from paquetelupa.scanner import Limits


class ReportOutputSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "synthetic-source.zip"
        self.source.write_bytes(b"SYNTHETIC-INPUT-NOT-A-PRODUCTION-FILE")

    @unittest.skipUnless(os.name == "nt", "Windows alternate data stream semantics")
    def test_report_cannot_be_an_alternate_stream_of_input(self):
        destination = Path(str(self.source) + ":hidden-report")
        before = self.source.read_bytes()
        with self.assertRaises(OSError):
            cli.write_reports({}, self.source, json_path=destination)
        self.assertFalse(destination.exists(), "No alternate stream may be created")
        self.assertEqual(self.source.read_bytes(), before)

    @unittest.skipUnless(os.name == "nt", "Windows alternate data stream semantics")
    def test_report_cannot_be_an_alternate_stream_of_other_file(self):
        base = self.root / "synthetic-other-file.txt"
        base.write_bytes(b"SYNTHETIC-OTHER-FILE")
        destination = Path(str(base) + ":hidden-report")
        with self.assertRaises(OSError):
            cli.write_reports({}, self.source, html_path=destination)
        self.assertFalse(destination.exists())
        self.assertEqual(base.read_bytes(), b"SYNTHETIC-OTHER-FILE")

    @unittest.skipUnless(os.name == "nt", "Windows reserved device semantics")
    def test_report_cannot_be_windows_null_device(self):
        # NUL discards writes and is safe to exercise; no serial/console devices.
        for basename in ("NUL", "nul.json"):
            with self.subTest(basename=basename):
                with self.assertRaises(OSError):
                    cli.write_reports({}, self.source, json_path=self.root / basename)

    @unittest.skipUnless(os.name == "posix", "POSIX owner-only file permissions")
    def test_new_reports_are_private_even_with_permissive_umask(self):
        json_path, html_path = self.root / "report.json", self.root / "report.html"
        previous = os.umask(0)
        try:
            cli.write_reports({}, self.source, json_path=json_path, html_path=html_path)
        finally:
            os.umask(previous)
        for destination in (json_path, html_path):
            with self.subTest(destination=destination.name):
                mode = stat.S_IMODE(destination.stat().st_mode)
                self.assertEqual(mode & 0o077, 0, "Report metadata and opt-in names must not be world/group readable")
                self.assertEqual(mode & 0o600, 0o600)


class _BlockedFrameReader:
    """An endpoint with a readable frame prefix but an unfinished payload."""

    def __init__(self):
        self.release = threading.Event()
        self.closed = False

    def poll(self, timeout):
        return True

    def recv_bytes(self, maxlength):
        self.release.wait(6)
        return json.dumps({"report": {"status": "no_findings"}}).encode("ascii")

    def close(self):
        self.closed = True
        self.release.set()


class _Writer:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _Process:
    def __init__(self):
        self.pid = None
        self.alive = False
        self.terminated = False

    def start(self):
        self.pid = 123
        self.alive = True

    def is_alive(self):
        return self.alive

    def terminate(self):
        self.terminated = True
        self.alive = False

    def kill(self):
        self.alive = False

    def join(self, timeout):
        pass


class _Context:
    def __init__(self):
        self.reader = _BlockedFrameReader()
        self.writer = _Writer()
        self.process = _Process()

    def Pipe(self, duplex):
        return self.reader, self.writer

    def Process(self, **kwargs):
        return self.process


class SupervisorDeadlineSecurityTests(unittest.TestCase):
    def test_deadline_covers_receive_after_pipe_first_becomes_readable(self):
        context = _Context()
        result = {}
        errors = []

        def run():
            try:
                result.update(cli.supervised_scan("synthetic-not-opened.zip", Limits(seconds=0.05)))
            except BaseException as error:
                errors.append(error)

        task = threading.Thread(target=run, daemon=True)
        with patch.object(cli.multiprocessing, "get_context", return_value=context):
            task.start()
            try:
                # 0.05 s of analysis + 2 s startup margin, with CI tolerance.
                # The old implementation blocks in recv_bytes after poll=True.
                task.join(2.8)
                finished_within_deadline = not task.is_alive()
            finally:
                context.reader.release.set()
                task.join(2)
        self.assertFalse(task.is_alive(), "The synthetic endpoint must always be released")
        self.assertFalse(errors, str(errors))
        self.assertTrue(finished_within_deadline, "Receiving a partial IPC frame must not defeat the deadline")
        self.assertEqual(result.get("report", {}).get("status"), "incomplete")
        self.assertFalse(context.process.alive)
        self.assertTrue(context.reader.closed)
        self.assertTrue(context.writer.closed)


if __name__ == "__main__":
    unittest.main()
