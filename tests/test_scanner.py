"""Security regression tests built only from small, synthetic archives."""

import io
import json
import stat
import struct
import tempfile
import unittest
import warnings
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from paquetelupa import scanner
from paquetelupa.scanner import Limits, scan_file


def archive_bytes(members=(), compression=zipfile.ZIP_STORED, comment=b""):
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(stream, "w", compression=compression) as archive:
            for name, contents in members:
                archive.writestr(name, contents)
            archive.comment = comment
    return stream.getvalue()


def alter_fields(data, local_offset, central_offset, value, width=2):
    """Change a field in each local and central header of a one-entry fixture."""
    modified = bytearray(data)
    local = modified.index(b"PK\x03\x04")
    central = modified.index(b"PK\x01\x02")
    encoded = value.to_bytes(width, "little")
    modified[local + local_offset : local + local_offset + width] = encoded
    modified[central + central_offset : central + central_offset + width] = encoded
    return bytes(modified)


class NonSeekable(io.BytesIO):
    def seekable(self):
        return False

    def seek(self, *args):
        raise io.UnsupportedOperation("Synthetic non-seekable output")


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.counter = 0

    def scan(self, data, limits=None, show_paths=False, filename=None):
        self.counter += 1
        path = self.root / (filename or f"fixture-{self.counter}.zip")
        path.write_bytes(data)
        report = scan_file(path, limits=limits, show_paths=show_paths)
        self.assertIsInstance(report, dict)
        self.assertIsInstance(report["complete"], bool)
        self.assertIn(report["status"], {"review", "incomplete", "no_findings"})
        for finding in report["findings"]:
            for field in ("rule", "severity", "entry", "line", "message", "remediation"):
                self.assertIn(field, finding)
            self.assertIsInstance(finding["severity"], str)
            self.assertTrue(finding["severity"])
        for entry in report["entries"]:
            self.assertIsInstance(entry["state"], str)
        self.assertEqual(path.read_bytes(), data, "Inspection changed the input")
        return report

    def assert_detected(self, report):
        self.assertTrue(report["findings"], "Unsafe fixture produced no findings")
        self.assertNotEqual(report["status"], "no_findings")

    def assert_incomplete(self, report):
        self.assertFalse(report["complete"])
        self.assertEqual(report["status"], "incomplete")
        self.assertTrue(report["findings"])

    def test_empty_archive(self):
        result = self.scan(archive_bytes())
        self.assertTrue(result["complete"])
        self.assertEqual(result["status"], "no_findings")

    def test_stored_text(self):
        result = self.scan(archive_bytes([("readme.txt", "Small diagnostic file.\n")]))
        self.assertTrue(result["complete"])
        self.assertEqual(result["status"], "no_findings")

    def test_deflated_text(self):
        result = self.scan(archive_bytes([("readme.txt", "A short ordinary note.\n")], zipfile.ZIP_DEFLATED))
        self.assertTrue(result["complete"])
        self.assertEqual(result["status"], "no_findings")

    def test_utf8_and_crlf(self):
        result = self.scan(archive_bytes([("documentacion/niño.txt", "Información útil.\r\nSegunda línea.\r\n")]))
        self.assertTrue(result["complete"])
        self.assertEqual(result["status"], "no_findings")

    def test_explicit_directory(self):
        result = self.scan(archive_bytes([("logs/", b""), ("logs/info.txt", "Ready\n")]))
        self.assertTrue(result["complete"])
        self.assertEqual(result["status"], "no_findings")

    def test_streamed_zip_data_descriptor(self):
        stream = NonSeekable()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("readme.txt", "Short streamed diagnostic file.\n")
        data = stream.getvalue()
        self.assertIn(b"PK\x07\x08", data)
        result = self.scan(data)
        self.assertTrue(result["complete"])
        self.assertEqual(result["status"], "no_findings")

    def test_streamed_descriptor_without_optional_signature(self):
        stream = NonSeekable()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("readme.txt", "Short streamed diagnostic file.\n")
        data = bytearray(stream.getvalue())
        position = data.index(b"PK\x07\x08")
        del data[position : position + 4]
        end = data.index(b"PK\x05\x06")
        central_offset = struct.unpack_from("<I", data, end + 16)[0]
        struct.pack_into("<I", data, end + 16, central_offset - 4)
        result = self.scan(bytes(data))
        self.assertTrue(result["complete"])
        self.assertEqual(result["status"], "no_findings")

    def test_legacy_cp437_filename(self):
        data = archive_bytes([("X.txt", "ordinary\n")]).replace(b"X.txt", b"\x82.txt")
        result = self.scan(data, show_paths=True)
        self.assertTrue(result["complete"])
        self.assertIn("\u00e9.txt", json.dumps(result, ensure_ascii=False))

    def test_input_unchanged_and_no_extraction(self):
        data = archive_bytes([("outside/result.txt", "ordinary\n")])
        self.scan(data)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["fixture-1.zip"])

    def test_parent_traversal_both_separators(self):
        for name in ("../outside.txt", "..\\outside.txt", "safe/../../outside.txt", "safe\\..\\..\\outside.txt"):
            with self.subTest(name=name):
                self.assert_detected(self.scan(archive_bytes([(name, "ordinary\n")])))

    def test_absolute_and_drive_relative_paths(self):
        for name in ("/outside.txt", "\\outside.txt", "C:\\outside.txt", "C:outside.txt", "\\\\server\\share\\file.txt", "\\\\?\\C:\\outside.txt"):
            with self.subTest(name=name):
                self.assert_detected(self.scan(archive_bytes([(name, "ordinary\n")])))

    def test_windows_reserved_devices(self):
        for name in ("CON", "aux.txt", "dir/NUL.log", "COM1", "LPT9.txt", "COM¹.txt"):
            with self.subTest(name=name):
                self.assert_detected(self.scan(archive_bytes([(name, "ordinary\n")])))

    def test_windows_ads_and_forbidden_characters(self):
        for name in ("report.txt:secret", "a<b.txt", "a|b.txt", "a?b.txt", "a*b.txt"):
            with self.subTest(name=name):
                self.assert_detected(self.scan(archive_bytes([(name, "ordinary\n")])))

    def test_trailing_period_and_space(self):
        for name in ("report.txt.", "report.txt ", "directory. /readme.txt"):
            with self.subTest(name=name):
                self.assert_detected(self.scan(archive_bytes([(name, "ordinary\n")])))

    def test_control_characters_in_names(self):
        for name in ("bad\x1b[31m.txt", "bad\nname.txt", "bad\tname.txt"):
            with self.subTest(name=name):
                self.assert_detected(self.scan(archive_bytes([(name, "ordinary\n")])))

    def test_embedded_nul_in_raw_name(self):
        data = archive_bytes([("nulX.txt", "ordinary\n")]).replace(b"nulX.txt", b"nul\x00.txt")
        self.assert_detected(self.scan(data))

    def test_casefold_collision(self):
        self.assert_detected(self.scan(archive_bytes([("A.txt", "first"), ("a.txt", "second")])))

    def test_unicode_nfc_collision(self):
        self.assert_detected(self.scan(archive_bytes([("caf\u00e9.txt", "first"), ("cafe\u0301.txt", "second")])))

    def test_duplicate_name_collision(self):
        self.assert_detected(self.scan(archive_bytes([("same.txt", "first"), ("same.txt", "second")])))

    def test_file_as_ancestor_both_orders(self):
        for members in ([('a', 'first'), ('a/b.txt', 'second')], [('a/b.txt', 'first'), ('a', 'second')]):
            with self.subTest(members=members):
                self.assert_detected(self.scan(archive_bytes(members)))

    def test_separator_collision(self):
        self.assert_detected(self.scan(archive_bytes([("a/b.txt", "first"), ("a\\b.txt", "second")])))

    def test_unix_symbolic_link(self):
        member = zipfile.ZipInfo("link")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.assert_detected(self.scan(archive_bytes([(member, "../../outside")])))

    def test_unix_special_file(self):
        member = zipfile.ZipInfo("named-pipe")
        member.create_system = 3
        member.external_attr = (stat.S_IFIFO | 0o600) << 16
        self.assert_detected(self.scan(archive_bytes([(member, b"")])))

    def test_entry_count_budget(self):
        result = self.scan(archive_bytes([("a.txt", "a"), ("b.txt", "b")]), replace(Limits(), entries=1))
        self.assert_incomplete(result)

    def test_physical_size_budget(self):
        data = archive_bytes([("a.txt", "ordinary")])
        self.assert_incomplete(self.scan(data, replace(Limits(), archive_bytes=len(data) - 1)))

    def test_central_directory_budget(self):
        self.assert_incomplete(self.scan(archive_bytes([("a.txt", "ordinary")]), replace(Limits(), central_bytes=20)))

    def test_entry_uncompressed_budget(self):
        self.assert_incomplete(self.scan(archive_bytes([("a.txt", "x" * 100)]), replace(Limits(), entry_bytes=99)))

    def test_total_uncompressed_budget(self):
        self.assert_incomplete(self.scan(archive_bytes([("a.txt", "a" * 60), ("b.txt", "b" * 60)]), replace(Limits(), total_bytes=100)))

    def test_compression_ratio_budget(self):
        data = archive_bytes([("repeat.txt", "A" * 32768)], zipfile.ZIP_DEFLATED)
        self.assert_incomplete(self.scan(data, replace(Limits(), ratio=10)))

    def test_encrypted_flag(self):
        data = alter_fields(archive_bytes([("a.txt", "ordinary")]), 6, 8, 1)
        self.assert_incomplete(self.scan(data))

    def test_crc_corruption(self):
        data = bytearray(archive_bytes([("a.txt", "ordinary text")]))
        data[data.index(b"ordinary text")] ^= 1
        self.assert_incomplete(self.scan(bytes(data)))

    def test_truncated_archive(self):
        self.assert_incomplete(self.scan(archive_bytes([("a.txt", "ordinary")])[:-12]))

    def test_nonzip_input(self):
        self.assert_incomplete(self.scan(b"This file is not an archive.\n"))

    def test_unsupported_compression(self):
        data = alter_fields(archive_bytes([("a.txt", "ordinary")]), 8, 10, 99)
        self.assert_incomplete(self.scan(data))

    def test_unsupported_compression_on_empty_directory(self):
        data = alter_fields(archive_bytes([("folder/", b"")]), 8, 10, 99)
        self.assert_incomplete(self.scan(data))

    def test_encrypted_empty_directory(self):
        data = alter_fields(archive_bytes([("folder/", b"")]), 6, 8, 1)
        self.assert_incomplete(self.scan(data))

    def test_deflated_empty_directory(self):
        result = self.scan(archive_bytes([("folder/", b"")], zipfile.ZIP_DEFLATED))
        self.assertTrue(result["complete"])
        self.assertEqual(result["status"], "no_findings")

    def test_unrecognized_option_flags(self):
        data = alter_fields(archive_bytes([("a.txt", "ordinary")]), 6, 8, 0x4000)
        self.assert_incomplete(self.scan(data))

    def test_findings_budget_marks_report_incomplete(self):
        result = self.scan(archive_bytes([("../a.txt", "ordinary"), ("../b.txt", "ordinary")]), replace(Limits(), findings=1))
        self.assert_incomplete(result)
        self.assertLessEqual(len(result["findings"]), 1)

    def test_cooperative_time_budget(self):
        with patch.object(scanner.time, "monotonic", side_effect=[0, 100]):
            self.assert_incomplete(self.scan(archive_bytes([("a.txt", "ordinary")])))

    def test_limits_reject_invalid_values(self):
        for values in ({"entries": 0}, {"archive_bytes": -1}, {"findings": True}, {"seconds": float("nan")}, {"seconds": float("inf")}, {"entries": 1.5}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                replace(Limits(), **values)

    def test_missing_input_is_operational_error(self):
        with self.assertRaises(OSError):
            scan_file(self.root / "not-present.zip")

    def test_directory_input_is_operational_error(self):
        with self.assertRaises(OSError):
            scan_file(self.root)

    def test_symlink_input_is_rejected_when_supported(self):
        source = self.root / "source.zip"
        source.write_bytes(archive_bytes())
        link = self.root / "link.zip"
        try:
            link.symlink_to(source)
        except (OSError, NotImplementedError):
            self.skipTest("Creating symlinks is unavailable on this platform/account")
        with self.assertRaises(OSError):
            scan_file(link)

    def test_replacement_between_stat_and_open_is_rejected(self):
        source = self.root / "source.zip"
        replacement = self.root / "replacement.zip"
        source.write_bytes(archive_bytes([("original.txt", "first")]))
        replacement.write_bytes(archive_bytes([("replacement.txt", "second")]))
        original_open = scanner.os.open

        def replace_before_open(path, flags):
            replacement.replace(source)
            return original_open(path, flags)

        with patch.object(scanner.os, "open", side_effect=replace_before_open):
            with self.assertRaises(OSError):
                scan_file(source)

    def test_changed_input_during_scan_is_incomplete(self):
        source = self.root / "source.zip"
        source.write_bytes(archive_bytes([("ordinary.txt", "ordinary")]))
        original_scan_text = scanner.scan_text
        changed = False

        def change_during_scan(*args, **kwargs):
            nonlocal changed
            if not changed:
                with source.open("ab") as changed_file:
                    changed_file.write(b"changed")
                changed = True
            return original_scan_text(*args, **kwargs)

        with patch.object(scanner, "scan_text", side_effect=change_during_scan):
            self.assert_incomplete(scan_file(source))

    def test_nested_zip_by_extension(self):
        inner = archive_bytes([("private.txt", "ordinary")])
        self.assert_incomplete(self.scan(archive_bytes([("inner.zip", inner)])))

    def test_nested_zip_by_magic(self):
        inner = archive_bytes([("private.txt", "ordinary")])
        self.assert_incomplete(self.scan(archive_bytes([("renamed.txt", inner)])))

    def test_binary_content_is_incomplete(self):
        self.assert_incomplete(self.scan(archive_bytes([("payload.bin", b"\x00\x01\x02\xff\x00\xfe")])) )

    def test_secret_value_not_in_report(self):
        secret = "AKIA" + "ABCDEFGHIJKLMNOP"
        result = self.scan(archive_bytes([("config.txt", "aws_access_key_id=" + secret + "\n")]))
        self.assert_detected(result)
        self.assertNotIn(secret, json.dumps(result, ensure_ascii=False))

    def test_filename_hidden_by_default(self):
        name = "private-customer-evidence-7842.txt"
        result = self.scan(archive_bytes([(name, "ordinary\n")]))
        self.assertNotIn(name, json.dumps(result, ensure_ascii=False))

    def test_archive_filename_hidden_by_default(self):
        name = "private-customer-evidence-7842.zip"
        result = self.scan(archive_bytes([("readme.txt", "ordinary\n")]), filename=name)
        self.assertNotIn(name, json.dumps(result, ensure_ascii=False))
        self.assertNotIn(str(self.root), json.dumps(result, ensure_ascii=False))

    def test_paths_can_be_explicitly_requested(self):
        name = "normal-visible-member.txt"
        result = self.scan(archive_bytes([(name, "ordinary\n")]), show_paths=True)
        self.assertIn(name, json.dumps(result, ensure_ascii=False))

    def test_private_key_header(self):
        result = self.scan(archive_bytes([("key.txt", "-----BEGIN PRIVATE KEY-----\nSYNTHETIC-NOT-A-KEY\n-----END PRIVATE KEY-----\n")]))
        self.assert_detected(result)
        self.assertNotIn("SYNTHETIC-NOT-A-KEY", json.dumps(result))

    def test_comment_not_echoed(self):
        comment = b"PRIVATE-COMMENT-SENTINEL-71821"
        result = self.scan(archive_bytes([("readme.txt", "ordinary")], comment=comment))
        self.assertNotIn(comment.decode(), json.dumps(result))

    def test_local_central_filename_mismatch(self):
        data = bytearray(archive_bytes([("a.txt", "ordinary")]))
        data[data.index(b"a.txt")] = ord("b")
        self.assert_incomplete(self.scan(bytes(data)))

    def test_out_of_range_local_offset(self):
        data = bytearray(archive_bytes([("a.txt", "ordinary")]))
        central = data.index(b"PK\x01\x02")
        struct.pack_into("<I", data, central + 42, 0x7FFFFFFF)
        self.assert_incomplete(self.scan(bytes(data)))


if __name__ == "__main__":
    unittest.main()
