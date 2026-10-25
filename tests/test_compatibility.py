import json
from pathlib import Path
import stat
import struct
import tempfile
import unittest
import zipfile

from paquetelupa.scanner import scan_file


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "sample.zip"

    def make(self, name="log.txt", content="Servicio listo\n", method=zipfile.ZIP_STORED, mode=None, extra=b""):
        info = zipfile.ZipInfo(name)
        info.compress_type = method
        info.extra = extra
        if mode is not None:
            info.external_attr = mode << 16
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr(info, content)

    def test_deflate_compression_option_flags(self):
        for options in (0, 2, 4, 6):
            with self.subTest(flags=options):
                self.make(method=zipfile.ZIP_DEFLATED)
                blob = bytearray(self.path.read_bytes())
                central = blob.index(b"PK\x01\x02")
                struct.pack_into("<H", blob, 6, options)
                struct.pack_into("<H", blob, central+8, options)
                self.path.write_bytes(blob)
                self.assertEqual(scan_file(self.path)["status"], "no_findings")

    def test_store_does_not_accept_deflate_option_flags(self):
        self.make()
        blob = bytearray(self.path.read_bytes())
        central = blob.index(b"PK\x01\x02")
        struct.pack_into("<H", blob, 6, 2)
        struct.pack_into("<H", blob, central+8, 2)
        self.path.write_bytes(blob)
        self.assertFalse(scan_file(self.path)["complete"])

    def test_directory_with_payload_is_not_complete(self):
        self.make("logs/", "Hidden payload\n")
        self.assertFalse(scan_file(self.path)["complete"])

    def test_windows_device_spaces_before_extension(self):
        for name in ("NUL .txt", "COM1 .log", "CON .cfg", "aux    .data", "folder/LPT² .log"):
            with self.subTest(name=name):
                self.make(name)
                report = scan_file(self.path)
                self.assertEqual(report["status"], "review")
                self.assertTrue(any(hit["rule"] == "path.unsafe" for hit in report["findings"]))

    def test_explicit_regular_file_mode_on_directory(self):
        self.make("logs/", "", mode=stat.S_IFREG | 0o600)
        self.assertFalse(scan_file(self.path)["complete"])

    def test_directory_mode_without_slash(self):
        self.make("logs", "", mode=stat.S_IFDIR | 0o755)
        self.assertFalse(scan_file(self.path)["complete"])

    def test_recognized_extended_timestamp(self):
        self.make(extra=struct.pack("<HHBL", 0x5455, 5, 1, 1700000000))
        self.assertTrue(scan_file(self.path)["complete"])

    def test_recognized_ntfs_timestamp(self):
        self.make(extra=struct.pack("<HH", 0x000a, 32) + bytes(4) + struct.pack("<HH3Q", 1, 24, 0, 0, 0))
        self.assertTrue(scan_file(self.path)["complete"])

    def test_recognized_unix_uid_gid(self):
        self.make(extra=struct.pack("<HH", 0x7875, 5) + b"\x01\x01\x64\x01\x64")
        self.assertTrue(scan_file(self.path)["complete"])

    def test_unknown_extra_never_exposes_contents(self):
        sentinel = "password=OpaqueMetadataSentinel123!"
        payload = sentinel.encode()
        self.make(extra=struct.pack("<HH", 0xfefe, len(payload)) + payload)
        report = scan_file(self.path)
        self.assertFalse(report["complete"])
        self.assertNotIn(sentinel, json.dumps(report))

    def test_malformed_known_extra_rejected(self):
        for kind, payload in ((0x5455, b"\xff"), (0x000a, b"\x00"), (0x7875, b"\x01\x10\x00\x00\x00")):
            with self.subTest(kind=kind):
                self.make(extra=struct.pack("<HH", kind, len(payload)) + payload)
                self.assertFalse(scan_file(self.path)["complete"])


if __name__ == "__main__":
    unittest.main()
