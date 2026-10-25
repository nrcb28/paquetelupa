"""Independent parser regression cases; all fixtures are small and synthetic."""

import json
import stat
import struct
import tempfile
import time
import unittest
import zlib
from dataclasses import replace
from pathlib import Path

from paquetelupa.scanner import Limits, scan_file


def one_entry(*, name=b"note.txt", data=b"A brief diagnostic note.\n", method=0,
              flags=0, compressed=None, declared_size=None, declared_crc=None,
              local_values=None, descriptor_signature=True,
              descriptor_values=None, local_extra=b"", central_extra=b"",
              file_comment=b"", archive_comment=b"", made=20, external=0):
    if compressed is None:
        if method == 8:
            compressor = zlib.compressobj(wbits=-15)
            compressed = compressor.compress(data) + compressor.flush()
        else:
            compressed = data
    unpacked = len(data) if declared_size is None else declared_size
    crc = zlib.crc32(data) if declared_crc is None else declared_crc
    sizes = (crc, len(compressed), unpacked)
    local_values = local_values if local_values is not None else ((0, 0, 0) if flags & 8 else sizes)
    local = struct.pack("<4s5H3L2H", b"PK\x03\x04", 20, flags, method, 0, 0,
                        *local_values, len(name), len(local_extra)) + name + local_extra + compressed
    if flags & 8:
        local += (b"PK\x07\x08" if descriptor_signature else b"")
        local += struct.pack("<3L", *(descriptor_values or sizes))
    central = struct.pack("<4s6H3L5H2L", b"PK\x01\x02", made, 20, flags, method,
                          0, 0, *sizes, len(name), len(central_extra), len(file_comment),
                          0, 0, external, 0) + name + central_extra + file_comment
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, len(central),
                      len(local), len(archive_comment)) + archive_comment
    return local + central + end


class AdversarialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "synthetic.zip"

    def scan(self, data, limits=None):
        self.path.write_bytes(data)
        report = scan_file(self.path, limits=limits)
        self.assertEqual(self.path.read_bytes(), data)
        return report

    def rejected(self, data, limits=None):
        report = self.scan(data, limits)
        self.assertFalse(report["complete"])
        self.assertEqual(report["status"], "incomplete")
        return report

    def accepted(self, data, limits=None):
        report = self.scan(data, limits)
        self.assertTrue(report["complete"], report)
        self.assertEqual(report["status"], "no_findings", report)
        return report

    def test_store_exact_entry_and_total_limit(self):
        payload = b"Readable contents."
        self.accepted(one_entry(data=payload), replace(Limits(), entry_bytes=len(payload), total_bytes=len(payload)))

    def test_deflate_exact_entry_and_total_limit(self):
        payload = b"Readable contents with modest compression."
        self.accepted(one_entry(data=payload, method=8), replace(Limits(), entry_bytes=len(payload), total_bytes=len(payload)))

    def test_exact_archive_and_central_limits(self):
        data = one_entry()
        cd_size = struct.unpack_from("<L", data, len(data) - 22 + 12)[0]
        self.accepted(data, replace(Limits(), archive_bytes=len(data), central_bytes=cd_size, entries=1))

    def test_store_exact_ratio_one(self):
        self.accepted(one_entry(), replace(Limits(), ratio=1))

    def test_data_descriptor_all_supported_variants(self):
        for method in (0, 8):
            for signed in (True, False):
                with self.subTest(method=method, signed=signed):
                    self.accepted(one_entry(method=method, flags=8, descriptor_signature=signed))

    def test_data_descriptor_wrong_crc(self):
        self.rejected(one_entry(flags=8, descriptor_values=(1234, 25, 25)))

    def test_data_descriptor_missing(self):
        data = one_entry(flags=8)
        descriptor = data.index(b"PK\x07\x08")
        # Removing just the signature makes this a valid unsigned descriptor.
        modified = data[:descriptor] + data[descriptor+4:]
        end = bytearray(modified)
        struct.pack_into("<L", end, len(end) - 22 + 16, descriptor + 12)
        self.accepted(bytes(end))

    def test_descriptor_conflicting_nonzero_local_sizes(self):
        # Descriptor entries may leave local values zero, but conflicting
        # nonzero local claims must not get an unqualified complete result.
        report = self.scan(one_entry(flags=8, local_values=(1111, 1, 1)))
        self.assertNotEqual(report["status"], "no_findings")

    def test_real_deflate_size_larger_than_declared(self):
        self.rejected(one_entry(data=b"secret=synthetic-credential\n", method=8, declared_size=0))

    def test_real_deflate_expansion_exceeds_budget(self):
        self.rejected(one_entry(data=b"A" * 4096, method=8, declared_size=1), replace(Limits(), entry_bytes=100, total_bytes=100))

    def test_real_deflate_size_smaller_than_declared(self):
        self.rejected(one_entry(data=b"hello", method=8, declared_size=20))

    def test_trailing_data_inside_deflate_payload(self):
        compressor = zlib.compressobj(wbits=-15)
        payload = b"ordinary contents"
        compressed = compressor.compress(payload) + compressor.flush() + b"HIDDEN TRAILING DATA"
        self.rejected(one_entry(data=payload, method=8, compressed=compressed))

    def test_concatenated_deflate_streams(self):
        streams = []
        for content in (b"ordinary", b"password=hidden-synthetic"):
            compressor = zlib.compressobj(wbits=-15)
            streams.append(compressor.compress(content) + compressor.flush())
        self.rejected(one_entry(data=b"ordinary", method=8, compressed=b"".join(streams)))

    def test_truncated_deflate_payload(self):
        compressor = zlib.compressobj(wbits=-15)
        content = b"ordinary contents"
        compressed = compressor.compress(content) + compressor.flush()
        self.rejected(one_entry(data=content, method=8, compressed=compressed[:-1]))

    def test_zero_length_deflate_data_is_not_a_stream(self):
        self.rejected(one_entry(data=b"", method=8, compressed=b""))

    def test_empty_store_and_valid_empty_deflate(self):
        self.accepted(one_entry(data=b""))
        self.accepted(one_entry(data=b"", method=8))

    def test_unsupported_compression_in_empty_directory(self):
        self.rejected(one_entry(name=b"logs/", data=b"", method=99))

    def test_darwin_creator_symbolic_link_is_not_treated_as_plain_text(self):
        report = self.scan(one_entry(name=b"pointer", data=b"../../outside",
                                   made=(19 << 8) | 20,
                                   external=(stat.S_IFLNK | 0o777) << 16))
        self.assertFalse(report["complete"])
        self.assertTrue(any(finding["rule"] == "archive.special" for finding in report["findings"]))

    def test_extra_fields_truncated(self):
        for field in (b"\x01", b"\xfe\xca\x02\x00X"):
            with self.subTest(field=field, location="local"):
                self.rejected(one_entry(local_extra=field))
            with self.subTest(field=field, location="central"):
                self.rejected(one_entry(central_extra=field))

    def test_zip64_and_unicode_alternate_name_fields(self):
        for kind in (0x0001, 0x7075, 0x6375):
            extra = struct.pack("<HH", kind, 0)
            with self.subTest(kind=kind, location="local"):
                self.rejected(one_entry(local_extra=extra))
            with self.subTest(kind=kind, location="central"):
                self.rejected(one_entry(central_extra=extra))

    def test_zip64_eocd_sentinel(self):
        data = bytearray(one_entry())
        struct.pack_into("<L", data, len(data)-22+12, 0xffffffff)
        self.rejected(bytes(data))

    def test_overlapping_referenced_local_entries(self):
        data = one_entry()
        central = data.index(b"PK\x01\x02")
        end_offset = data.index(b"PK\x05\x06")
        record = data[central:end_offset]
        ending = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 2, 2, len(record) * 2, central, 0)
        self.rejected(data[:central] + record + record + ending)

    def test_central_entry_order_may_differ_from_local_entry_order(self):
        first = one_entry(name=b"first.txt", data=b"first contents")
        second = one_entry(name=b"second.txt", data=b"second contents")
        first_cd = first.index(b"PK\x01\x02")
        second_cd = second.index(b"PK\x01\x02")
        first_local, first_record = first[:first_cd], first[first_cd:-22]
        second_local = second[:second_cd]
        second_record = bytearray(second[second_cd:-22])
        struct.pack_into("<L", second_record, 42, len(first_local))
        records = bytes(second_record) + first_record
        locals_data = first_local + second_local
        ending = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 2, 2,
                             len(records), len(locals_data), 0)
        self.accepted(locals_data + records + ending)

    def test_prepend_append_and_hidden_gap(self):
        self.rejected(b"PREFIX" + one_entry())
        self.rejected(one_entry() + b"TRAILING")
        data = one_entry()
        central = data.index(b"PK\x01\x02")
        modified = bytearray(data[:central] + b"GAP" + data[central:])
        struct.pack_into("<L", modified, len(modified)-22+16, central+3)
        self.rejected(bytes(modified))

    def test_archive_comment_secret_cannot_be_unqualified_no_findings(self):
        sentinel = b"password=COMMENT_CREDENTIAL_SYNTHETIC"
        report = self.scan(one_entry(archive_comment=sentinel))
        self.assertNotIn(sentinel.decode(), json.dumps(report))
        self.assertNotEqual(report["status"], "no_findings")
        self.assertTrue(any("credential-assignment" in finding["rule"] for finding in report["findings"]))

    def test_file_comment_secret_cannot_be_unqualified_no_findings(self):
        sentinel = b"password=FILE_COMMENT_CREDENTIAL_SYNTHETIC"
        report = self.scan(one_entry(file_comment=sentinel))
        self.assertNotIn(sentinel.decode(), json.dumps(report))
        self.assertNotEqual(report["status"], "no_findings")
        self.assertTrue(any("credential-assignment" in finding["rule"] for finding in report["findings"]))

    def test_unknown_extra_field_has_explicit_uninspected_coverage(self):
        sentinel = b"password=EXTRA_FIELD_CREDENTIAL_SYNTHETIC"
        extra = struct.pack("<HH", 0xcafe, len(sentinel)) + sentinel
        report = self.scan(one_entry(local_extra=extra, central_extra=extra))
        self.assertNotIn(sentinel.decode(), json.dumps(report))
        self.assertFalse(report["complete"])

    def test_deep_member_path_respects_cooperative_deadline(self):
        data = one_entry(name=(b"a/" * 32_000) + b"note.txt")
        started = time.monotonic()
        report = self.scan(data, replace(Limits(), seconds=0.05))
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.0, "Ancestor matching exceeded the time budget by more than 20x")
        self.assertNotEqual(report["status"], "no_findings")


if __name__ == "__main__":
    unittest.main()
