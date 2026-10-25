"""CLI integration and worker-lifecycle regressions using synthetic inputs."""

import contextlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from paquetelupa import __main__ as cli
from paquetelupa.scanner import Limits


PROJECT = Path(__file__).resolve().parents[1]
SENTINEL = "AKIA" + "ABCDEFGHIJKLMNOP"


class CP437Info(zipfile.ZipInfo):
    def _encodeFilenameFlags(self):
        return self.filename.encode("cp437"), self.flag_bits


class CLIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def fixture(self, content="Small ordinary diagnostic note.\n", member="readme.txt", filename="sample.zip"):
        source = self.root / filename
        with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(member, content)
        return source

    def invoke(self, *arguments):
        result = subprocess.run(
            [sys.executable, "-m", "paquetelupa", *map(str, arguments)],
            cwd=PROJECT, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=10, env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn(SENTINEL, result.stdout)
        self.assertNotIn(SENTINEL, result.stderr)
        return result

    def test_clean_archive_exit_zero(self):
        result = self.invoke(self.fixture())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PAQUETELUPA", result.stdout)
        self.assertFalse(result.stderr)

    def test_credential_archive_exit_one(self):
        source = self.fixture("aws_access_key_id=" + SENTINEL + "\n")
        result = self.invoke(source)
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_invalid_archive_exit_two(self):
        source = self.root / "invalid.zip"
        source.write_bytes(b"synthetic invalid zip")
        result = self.invoke(source)
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_missing_archive_exit_three_and_private_error(self):
        name = "PRIVATE-CUSTOMER-" + SENTINEL + ".zip"
        result = self.invoke(self.root / name)
        self.assertEqual(result.returncode, 3)
        self.assertTrue(result.stderr)
        self.assertNotIn(name, result.stderr)
        self.assertNotIn(str(self.root), result.stderr)

    def test_directory_input_exit_three(self):
        result = self.invoke(self.root)
        self.assertEqual(result.returncode, 3)

    def test_json_and_html_exclude_values_and_paths(self):
        member = "private-customer-document-831.txt"
        source = self.fixture("aws_access_key_id=" + SENTINEL + "\n", member=member)
        original = source.read_bytes()
        json_path, html_path = self.root / "report.json", self.root / "report.html"
        result = self.invoke(source, "--json", json_path, "--html", html_path)
        self.assertEqual(result.returncode, 1, result.stderr)
        json_text, html_text = json_path.read_text("utf-8"), html_path.read_text("utf-8")
        report = json.loads(json_text)
        self.assertEqual(report["status"], "review")
        self.assertIn("<!doctype html>", html_text.lower())
        for output in (result.stdout, json_text, html_text):
            self.assertNotIn(SENTINEL, output)
            self.assertNotIn(member, output)
            self.assertNotIn(str(self.root), output)
        self.assertEqual(source.read_bytes(), original)

    def test_explicit_paths_are_visible(self):
        name = "requested-visible-member.txt"
        source = self.fixture(member=name)
        destination = self.root / "report.json"
        result = self.invoke(source, "--show-paths", "--json", destination)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(name, result.stdout)
        self.assertIn(name, destination.read_text("utf-8"))

    def test_maximum_metadata_does_not_overflow_worker_pipe(self):
        # CP437 names expand sixfold in ensure_ascii JSON. The archive remains
        # below entry-count, per-name and central-directory limits.
        source = self.root / "many-legacy-names.zip"
        prefix = ("\u00e9" * 120 + "/") * 8
        with zipfile.ZipFile(source, "w") as archive:
            for number in range(1900):
                archive.writestr(CP437Info(prefix + str(number) + ".txt"), b"")
        result = self.invoke(source, "--show-paths")
        self.assertIn(result.returncode, (0, 1, 2), result.stderr)

    def test_existing_json_is_preserved(self):
        source = self.fixture()
        destination = self.root / "report.json"
        destination.write_bytes(b"ORIGINAL-REPORT-SENTINEL")
        result = self.invoke(source, "--json", destination)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(destination.read_bytes(), b"ORIGINAL-REPORT-SENTINEL")

    def test_existing_html_is_preserved(self):
        source = self.fixture()
        destination = self.root / "report.html"
        destination.write_bytes(b"ORIGINAL-HTML-SENTINEL")
        result = self.invoke(source, "--html", destination)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(destination.read_bytes(), b"ORIGINAL-HTML-SENTINEL")

    def test_output_cannot_be_input(self):
        for flag in ("--json", "--html"):
            with self.subTest(flag=flag):
                source = self.fixture()
                original = source.read_bytes()
                result = self.invoke(source, flag, source)
                self.assertEqual(result.returncode, 3)
                self.assertEqual(source.read_bytes(), original)

    def test_duplicate_destinations_are_not_created(self):
        source = self.fixture()
        destination = self.root / "shared-report.out"
        result = self.invoke(source, "--json", destination, "--html", destination)
        self.assertEqual(result.returncode, 3)
        self.assertFalse(destination.exists())

    def test_second_output_exists_leaves_no_empty_first_output(self):
        source = self.fixture()
        first, existing = self.root / "new.json", self.root / "existing.html"
        existing.write_bytes(b"EXISTING-REPORT")
        result = self.invoke(source, "--json", first, "--html", existing)
        self.assertEqual(result.returncode, 3)
        self.assertFalse(first.exists())
        self.assertEqual(existing.read_bytes(), b"EXISTING-REPORT")

    def test_missing_output_parent_fails_cleanly(self):
        result = self.invoke(self.fixture(), "--json", self.root / "not-present" / "report.json")
        self.assertEqual(result.returncode, 3)
        self.assertFalse((self.root / "not-present").exists())

    def test_nonfinite_and_out_of_range_timeout_rejected(self):
        source = self.fixture()
        for value in ("nan", "inf", "-inf", "0", "-1", "21"):
            with self.subTest(value=value):
                result = self.invoke(source, "--timeout=" + value)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--timeout", result.stderr)

    def test_version(self):
        result = self.invoke("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("PaqueteLupa", result.stdout)


class FakeReader:
    def __init__(self, ready=True, data=b'{"report": {"status": "no_findings"}}', error=None, interrupt=False):
        self.ready, self.data, self.error, self.interrupt = ready, data, error, interrupt
        self.closed = False

    def poll(self, timeout):
        self.timeout = timeout
        if self.interrupt:
            raise KeyboardInterrupt()
        return self.ready

    def recv_bytes(self, maxlength):
        self.maxlength = maxlength
        if self.error:
            raise self.error
        return self.data

    def close(self):
        self.closed = True


class OutputReservationTests(unittest.TestCase):
    def test_cancellation_during_reservation_removes_owned_empty_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / "new.json", root / "new.html"
            original_open = cli.open_private_output

            def interrupted_open(path, *args, **kwargs):
                if path == second:
                    raise KeyboardInterrupt()
                return original_open(path, *args, **kwargs)

            with patch.object(cli, "open_private_output", interrupted_open):
                with self.assertRaises(KeyboardInterrupt):
                    cli.write_reports({}, root / "source.zip", first, second)
            self.assertFalse(first.exists())
            self.assertFalse(second.exists())


class WorkerConnection:
    def __init__(self):
        self.payload = None
        self.closed = False

    def send_bytes(self, data):
        self.payload = json.loads(data)

    def close(self):
        self.closed = True


class WorkerPrivacyTests(unittest.TestCase):
    def run_worker(self, connection, source):
        from paquetelupa import runtime
        previous_handler = signal.getsignal(signal.SIGINT)
        try:
            runtime.worker(connection, str(source), Limits(), False)
        finally:
            signal.signal(signal.SIGINT, previous_handler)

    def test_scan_with_network_apis_disabled(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "offline.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("readme.txt", "ordinary text")
            connection = WorkerConnection()
            with patch.object(socket, "socket", side_effect=AssertionError("Network attempted")) as create_socket:
                with patch.object(socket, "create_connection", side_effect=AssertionError("Network attempted")) as connect:
                    self.run_worker(connection, source)
            self.assertEqual(connection.payload["report"]["status"], "no_findings")
            self.assertTrue(connection.closed)
            create_socket.assert_not_called()
            connect.assert_not_called()

    def test_worker_operational_and_internal_errors_do_not_disclose_values(self):
        from paquetelupa import runtime
        for error in (OSError(SENTINEL), RuntimeError(SENTINEL)):
            with self.subTest(error=type(error).__name__):
                connection = WorkerConnection()
                with patch.object(runtime, "scan_file", side_effect=error):
                    self.run_worker(connection, "private-" + SENTINEL + ".zip")
                self.assertIn("error", connection.payload)
                self.assertNotIn(SENTINEL, json.dumps(connection.payload))
                self.assertTrue(connection.closed)


class FakeWriter:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self, stubborn=False, start_error=None):
        self.pid = None
        self.alive = False
        self.stubborn, self.start_error = stubborn, start_error
        self.terminated = False
        self.killed = False
        self.joins = []

    def start(self):
        if self.start_error:
            raise self.start_error
        self.pid = 123
        self.alive = True

    def is_alive(self):
        return self.alive

    def terminate(self):
        self.terminated = True
        if not self.stubborn:
            self.alive = False

    def kill(self):
        self.killed = True
        self.alive = False

    def join(self, timeout):
        self.joins.append(timeout)


class FakeContext:
    def __init__(self, reader=None, process=None):
        self.reader = reader or FakeReader()
        self.writer = FakeWriter()
        self.process = process or FakeProcess()

    def Pipe(self, duplex):
        return self.reader, self.writer

    def Process(self, **kwargs):
        return self.process


class SupervisorTests(unittest.TestCase):
    def supervise(self, context):
        with patch.object(cli.multiprocessing, "get_context", return_value=context):
            return cli.supervised_scan("opaque-path.zip", Limits())

    def assert_closed_and_stopped(self, context):
        self.assertTrue(context.reader.closed)
        self.assertTrue(context.writer.closed)
        self.assertFalse(context.process.alive)
        self.assertTrue(context.process.joins)

    def test_timeout_report_and_worker_shutdown(self):
        context = FakeContext(reader=FakeReader(ready=False))
        result = self.supervise(context)
        self.assertEqual(result["report"]["status"], "incomplete")
        self.assertFalse(result["report"]["complete"])
        self.assertTrue(context.process.terminated)
        self.assert_closed_and_stopped(context)

    def test_stubborn_worker_is_killed_and_joined(self):
        context = FakeContext(reader=FakeReader(ready=False), process=FakeProcess(stubborn=True))
        self.supervise(context)
        self.assertTrue(context.process.terminated)
        self.assertTrue(context.process.killed)
        self.assertEqual(len(context.process.joins), 2)
        self.assert_closed_and_stopped(context)

    def test_invalid_json_is_private_error(self):
        context = FakeContext(reader=FakeReader(data=("INVALID-" + SENTINEL).encode()))
        result = self.supervise(context)
        self.assertIn("error", result)
        self.assertNotIn(SENTINEL, json.dumps(result))
        self.assert_closed_and_stopped(context)

    def test_eof_is_clean_error(self):
        context = FakeContext(reader=FakeReader(error=EOFError(SENTINEL)))
        result = self.supervise(context)
        self.assertIn("error", result)
        self.assertNotIn(SENTINEL, json.dumps(result))
        self.assert_closed_and_stopped(context)

    def test_oversized_pipe_payload_is_clean_error(self):
        context = FakeContext(reader=FakeReader(error=OSError(SENTINEL)))
        result = self.supervise(context)
        self.assertIn("error", result)
        self.assert_closed_and_stopped(context)

    def test_keyboard_interrupt_always_stops_worker(self):
        context = FakeContext(reader=FakeReader(interrupt=True))
        with self.assertRaises(KeyboardInterrupt):
            self.supervise(context)
        self.assert_closed_and_stopped(context)

    def test_worker_start_failure_closes_both_pipe_ends(self):
        context = FakeContext(process=FakeProcess(start_error=OSError("Synthetic start failure")))
        with self.assertRaises(OSError):
            self.supervise(context)
        self.assertTrue(context.reader.closed)
        self.assertTrue(context.writer.closed)
        self.assertFalse(context.process.joins)

    def test_main_cancellation_returns_three_without_traceback(self):
        stderr = io.StringIO()
        with patch.object(cli, "supervised_scan", side_effect=KeyboardInterrupt), contextlib.redirect_stderr(stderr):
            code = cli.main(["opaque-path.zip"])
        self.assertEqual(code, 3)
        self.assertIn("cancelado", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
