"""Persistent, private coverage explanations independent of findings limits."""

from dataclasses import replace
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

from paquetelupa import scanner
from paquetelupa.reports import render_html, render_text
from paquetelupa.scanner import Limits, scan_file


def archive_bytes(members, *, compression=zipfile.ZIP_STORED, comment=b""):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as archive:
        for name, contents in members:
            archive.writestr(name, contents)
        archive.comment = comment
    return stream.getvalue()


def field_in_both_headers(data, local_offset, central_offset, value, width=2):
    data = bytearray(data)
    data[local_offset:local_offset + width] = value.to_bytes(width, "little")
    central = data.index(b"PK\x01\x02") + central_offset
    data[central:central + width] = value.to_bytes(width, "little")
    return bytes(data)


class CoverageReasonsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name) / "private-archive-name.zip"

    def scan(self, data, limits=None):
        self.source.write_bytes(data)
        report = scan_file(self.source, limits=limits)
        self.assertEqual(self.source.read_bytes(), data)
        self.assertFalse(report["complete"])
        self.assertEqual(report["status"], "incomplete")
        self.assertTrue(all(entry["state"] != "pending" for entry in report["entries"]))
        self.assertEqual(report["summary"]["skipped_files"],
                         sum(entry["state"] == "skipped" for entry in report["entries"]))
        for entry in report["entries"]:
            if entry["state"] == "skipped":
                self.assertIsInstance(entry["reason_code"], str)
                self.assertTrue(entry["reason"])
        return report

    def test_each_supported_skip_condition_has_a_stable_reason(self):
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        empty_directory_with_data = field_in_both_headers(
            archive_bytes([("folder/", b"abc")]), 22, 24, 0, width=4)
        cases = [
            (archive_bytes([("nested.zip", b"ordinary")]), None, "nested_archive"),
            (archive_bytes([("binary.txt", b"\x00")]), None, "unsupported_content"),
            (archive_bytes([(link, "destination")]), None, "special_file"),
            (archive_bytes([("folder/", b"abc")]), None, "directory_conflict"),
            (empty_directory_with_data, None, "unexpected_directory_data"),
            (field_in_both_headers(archive_bytes([("file.txt", "ordinary")]), 6, 8, 1),
             None, "unsupported_flags"),
            (archive_bytes([("file.txt", "ordinary")], compression=zipfile.ZIP_BZIP2),
             None, "unsupported_compression"),
            (archive_bytes([("file.txt", "ordinary")]), replace(Limits(), entry_bytes=4),
             "entry_size_limit"),
            (archive_bytes([("file.txt", "a" * 2000)], compression=zipfile.ZIP_DEFLATED),
             replace(Limits(), ratio=1), "compression_ratio_limit"),
        ]
        for data, limits, reason_code in cases:
            with self.subTest(reason_code=reason_code):
                report = self.scan(data, limits)
                entry = report["entries"][0]
                self.assertEqual(entry["state"], "skipped")
                self.assertEqual(entry["reason_code"], reason_code)
                self.assertIn(entry["reason"], render_text(report))
                self.assertIn(entry["reason"], render_html(report))

    def test_total_budget_reason_does_not_mark_completed_entries_as_skipped(self):
        report = self.scan(archive_bytes([("first.txt", "abc"), ("second.txt", "def")]),
                           replace(Limits(), total_bytes=4))
        first, second = report["entries"]
        self.assertEqual(first["state"], "scanned")
        self.assertNotIn("reason_code", first)
        self.assertNotIn("reason", first)
        self.assertEqual(second["reason_code"], "total_size_limit")
        self.assertEqual(report["summary"]["scanned_text_files"], 1)

    def test_reasons_survive_findings_truncation_without_disclosing_names_or_content(self):
        path_marker = "PRIVATE_PATH_SENTINEL_4927"
        content_marker = "PRIVATE_CONTENT_SENTINEL_4927"
        data = archive_bytes([("../" + path_marker + ".txt", b"\x00" + content_marker.encode()),
                              (path_marker + ".zip", content_marker)])
        report = self.scan(data, replace(Limits(), findings=1))
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["rule"], "path.unsafe")
        self.assertEqual([entry["reason_code"] for entry in report["entries"]],
                         ["unsupported_content", "nested_archive"])
        for rendered in (json.dumps(report, ensure_ascii=False), render_text(report), render_html(report)):
            self.assertNotIn(path_marker, rendered)
            self.assertNotIn(content_marker, rendered)
            self.assertNotIn(self.source.name, rendered)
            for entry in report["entries"]:
                self.assertIn(entry["reason"], rendered)

    def test_corrupt_payload_explains_failing_and_unvisited_entries(self):
        data = archive_bytes([("binary.txt", b"\x00"), ("broken.txt", b"original"),
                              ("unvisited.txt", b"ordinary")])
        data = data.replace(b"original", b"modified", 1)
        report = self.scan(data, replace(Limits(), findings=1))
        self.assertEqual([entry["reason_code"] for entry in report["entries"]],
                         ["unsupported_content", "archive_rejected", "analysis_aborted"])
        self.assertEqual(report["summary"]["entries"], 3)
        self.assertEqual(report["summary"]["skipped_files"], 3)

    def timeout_when_scanning(self, target, data):
        clock = [0.0]
        original_scan_text = scanner.scan_text

        def delayed_scan_text(text, *args, **kwargs):
            if text == target:
                clock[0] = 21.0
            return original_scan_text(text, *args, **kwargs)

        with patch.object(scanner.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(scanner, "scan_text", side_effect=delayed_scan_text):
            return self.scan(data)

    def test_timeout_during_content_does_not_claim_partial_detection_completed(self):
        target = "delayed ordinary content"
        report = self.timeout_when_scanning(target, archive_bytes([
            ("first.txt", "ordinary"), ("second.txt", target), ("third.txt", "ordinary")]))
        self.assertEqual([entry["state"] for entry in report["entries"]],
                         ["scanned", "skipped", "skipped"])
        self.assertEqual([entry["reason_code"] for entry in report["entries"][1:]],
                         ["analysis_timeout", "analysis_timeout"])
        self.assertEqual(report["summary"]["scanned_text_files"], 1)

    def test_timeout_in_archive_comment_keeps_all_validated_entries(self):
        target = "delayed archive comment"
        report = self.timeout_when_scanning(target, archive_bytes([
            ("first.txt", "ordinary"), ("second.txt", "ordinary")], comment=target.encode()))
        self.assertEqual(len(report["entries"]), 2)
        self.assertEqual([entry["reason_code"] for entry in report["entries"]],
                         ["analysis_timeout", "analysis_timeout"])
        self.assertEqual(report["summary"]["scanned_text_files"], 0)

    def test_library_exception_details_never_become_entry_reasons(self):
        sentinel = "PRIVATE_EXCEPTION_SENTINEL_4927"
        with patch.object(scanner, "_payload", side_effect=zlib.error(sentinel)):
            report = self.scan(archive_bytes([("first.txt", "ordinary"), ("second.txt", "ordinary")]))
        self.assertEqual([entry["reason_code"] for entry in report["entries"]],
                         ["archive_rejected", "analysis_aborted"])
        for rendered in (json.dumps(report), render_text(report), render_html(report)):
            self.assertNotIn(sentinel, rendered)


if __name__ == "__main__":
    unittest.main()
