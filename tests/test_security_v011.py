"""Parser coverage regressions found during the independent 0.1.1 audit.

All data is synthetic. The UT cases exercise a real distinction between local
and central extended-timestamp layouts, rather than demanding new ZIP features.
"""

import hashlib
import json
import os
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from paquetelupa import scanner
from paquetelupa.scanner import scan_file


def extra(kind, payload):
    return struct.pack("<HH", kind, len(payload)) + payload


def synthetic_zip(*, local_extra=b"", central_extra=b"", data=b"Ordinary diagnostic evidence.\n",
                  archive_comment=b"", file_comment=b"", name=b"evidence.txt", flags=0):
    crc, length = zlib.crc32(data), len(data)
    local = struct.pack("<4s5H3L2H", b"PK\x03\x04", 20, flags, 0, 0, 0,
                        crc, length, length, len(name), len(local_extra))
    local += name + local_extra + data
    central = struct.pack("<4s6H3L5H2L", b"PK\x01\x02", 20, 20, flags, 0, 0, 0,
                          crc, length, length, len(name), len(central_extra),
                          len(file_comment), 0, 0, 0, 0)
    central += name + central_extra + file_comment
    ending = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1,
                         len(central), len(local), len(archive_comment))
    return local + central + ending + archive_comment


class ParserCoverageV011Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name) / "synthetic.zip"

    def scan(self, data):
        self.source.write_bytes(data)
        result = scan_file(self.source)
        self.assertEqual(self.source.read_bytes(), data)
        return result

    def assert_incomplete(self, data):
        result = self.scan(data)
        self.assertFalse(result["complete"], result)
        self.assertEqual(result["status"], "incomplete")
        return result

    def test_ut_local_missing_claimed_timestamps(self):
        for flags in range(1, 8):
            with self.subTest(flags=flags):
                self.assert_incomplete(synthetic_zip(local_extra=extra(0x5455, bytes([flags]))))

    def test_ut_local_extra_bytes_without_flags(self):
        # Flags=0 means no timestamps; these bytes are unclassified data, not
        # structurally validated numeric timestamps exempt from secret scanning.
        sentinel = b"token=ABCDEF"
        result = self.assert_incomplete(synthetic_zip(local_extra=extra(0x5455, b"\x00" + sentinel)))
        self.assertNotIn(sentinel.decode(), json.dumps(result))

    def test_ut_local_surplus_timestamp(self):
        self.assert_incomplete(synthetic_zip(local_extra=extra(0x5455, b"\x01" + b"\x00" * 8)))

    def test_ut_central_missing_required_modification_time(self):
        self.assert_incomplete(synthetic_zip(central_extra=extra(0x5455, b"\x01")))

    def test_ut_central_timestamp_without_modification_flag(self):
        for flags in (0, 2, 4, 6):
            with self.subTest(flags=flags):
                self.assert_incomplete(synthetic_zip(central_extra=extra(0x5455, bytes([flags]) + b"\x00" * 4)))

    def test_ut_central_surplus_access_and_creation_times(self):
        self.assert_incomplete(synthetic_zip(central_extra=extra(0x5455, b"\x07" + b"\x00" * 12)))

    def test_ut_valid_local_flag_combinations(self):
        for flags in range(8):
            with self.subTest(flags=flags):
                local = bytes([flags]) + b"\x00" * (4 * flags.bit_count())
                central = bytes([flags]) + (b"\x00" * 4 if flags & 1 else b"")
                result = self.scan(synthetic_zip(local_extra=extra(0x5455, local), central_extra=extra(0x5455, central)))
                self.assertTrue(result["complete"], result)
                self.assertEqual(result["status"], "no_findings", result)

    def test_ut_reserved_flag_bits_are_not_recognized_as_safe_numeric_metadata(self):
        self.assert_incomplete(synthetic_zip(local_extra=extra(0x5455, b"\x80")))

    def test_fake_empty_eocd_inside_comment_cannot_hide_member(self):
        fake = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0, 0, 0, 0, 0)
        self.assert_incomplete(synthetic_zip(data=b"password=SYNTHETIC_CREDENTIAL\n", archive_comment=fake))

    def test_fake_central_extent_inside_comment_cannot_hide_member(self):
        ordinary = synthetic_zip(data=b"password=SYNTHETIC_CREDENTIAL\n")
        actual_end = len(ordinary) - 22
        central_size, central_offset = struct.unpack_from("<LL", ordinary, actual_end + 12)
        fake = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1,
                           central_size + 22, central_offset, 0)
        self.assert_incomplete(synthetic_zip(data=b"password=SYNTHETIC_CREDENTIAL\n", archive_comment=fake))

    def test_utf8_flag_with_invalid_name_cannot_return_complete(self):
        self.assert_incomplete(synthetic_zip(name=b"invalid-\xff.txt", flags=0x800))

    def test_eocd_entry_count_underreports_actual_directory(self):
        data = bytearray(synthetic_zip())
        end = len(data) - 22
        struct.pack_into("<HH", data, end + 8, 0, 0)
        self.assert_incomplete(bytes(data))

    def test_locator_rejects_same_length_rewrite_even_with_mtime_restored(self):
        original = synthetic_zip(name=b"safe.txt")
        modified = original.replace(b"safe.txt", b"evil.txt")
        self.source.write_bytes(original)
        expected = hashlib.sha256(original).hexdigest()
        real_directory = scanner._directory

        def mutate_after_fingerprint(stream, *args, **kwargs):
            before = os.fstat(stream.fileno())
            self.source.write_bytes(modified)
            os.utime(self.source, ns=(before.st_atime_ns, before.st_mtime_ns))
            return real_directory(stream, *args, **kwargs)

        with patch.object(scanner, "_directory", side_effect=mutate_after_fingerprint):
            with self.assertRaises(OSError):
                scanner.locate_entry(self.source, "entrada-00001", expected_sha256=expected)

    def test_wrong_expected_identity_fails_before_any_directory_interpretation(self):
        self.source.write_bytes(synthetic_zip())
        with patch.object(scanner, "_directory", side_effect=AssertionError("Directory must not be interpreted")):
            with self.assertRaises(scanner.IdentityMismatch):
                scanner.locate_entry(self.source, "entrada-00001", expected_sha256="0" * 64)


if __name__ == "__main__":
    unittest.main()
