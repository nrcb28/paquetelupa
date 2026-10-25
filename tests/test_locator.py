import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from paquetelupa.scanner import scan_file, locate_entry, IdentityMismatch, SelectionNotFound, Rejected

PROJECT = Path(__file__).resolve().parents[1]


class LocatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "support.zip"
        with zipfile.ZipFile(self.source, "w") as archive:
            archive.writestr("first-secret-filename.txt", "password=PayloadSentinelNeverExpose123!\n")
            archive.writestr("second-private-filename.txt", "ordinary note\n")

    def invoke(self, *args):
        return subprocess.run([sys.executable,"-m","paquetelupa",str(self.source),*map(str,args)], cwd=PROJECT,
                              capture_output=True,text=True,encoding="utf-8",timeout=10)

    def test_report_identity_matches_actual_bytes(self):
        report = scan_file(self.source)
        self.assertEqual(report["archive"]["sha256"], hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertEqual(report["archive"]["size_bytes"], self.source.stat().st_size)
        self.assertNotIn("first-secret-filename", json.dumps(report))

    def test_locates_only_requested_name(self):
        identity = scan_file(self.source)["archive"]["sha256"]
        result = locate_entry(self.source,"entrada-00002",expected_sha256=identity.upper())
        text = json.dumps(result)
        self.assertEqual(result["operation"],"locate")
        self.assertEqual(result["entry"]["path"],"second-private-filename.txt")
        self.assertNotIn("first-secret-filename",text)
        self.assertNotIn("PayloadSentinelNeverExpose",text)
        self.assertNotIn("complete",result)
        self.assertNotIn("status",result)

    def test_different_archive_identity_rejected(self):
        with self.assertRaises(IdentityMismatch):
            locate_entry(self.source,"entrada-00001",expected_sha256="0"*64)
        with self.assertRaises(IdentityMismatch):
            scan_file(self.source,expected_sha256="0"*64)

    def test_mutation_after_report_rejected(self):
        fingerprint = scan_file(self.source)["archive"]["sha256"]
        with zipfile.ZipFile(self.source,"a") as archive:
            archive.comment = b"changed without modifying member contents"
        with self.assertRaises(IdentityMismatch):
            locate_entry(self.source,"entrada-00001",expected_sha256=fingerprint)

    def test_bad_and_missing_id_rejected(self):
        for entry in ("../escape", "entrada-1", "entrada-00001\x1b"):
            with self.subTest(length=len(entry)), self.assertRaises(ValueError):
                locate_entry(self.source,entry)
        with self.assertRaises(SelectionNotFound):
            locate_entry(self.source,"entrada-00003")

    def test_invalid_zip_has_no_locator(self):
        self.source.write_bytes(b"not a ZIP")
        with self.assertRaises(Rejected):
            locate_entry(self.source,"entrada-00001")

    def test_locator_does_not_modify_or_extract(self):
        original = self.source.read_bytes()
        members = set(self.root.iterdir())
        locate_entry(self.source,"entrada-00001")
        self.assertEqual(self.source.read_bytes(),original)
        self.assertEqual(set(self.root.iterdir()),members)

    def test_locator_does_not_claim_payload_inspection(self):
        data = bytearray(self.source.read_bytes())
        data[data.index(b"password=")] ^= 1
        self.source.write_bytes(data)
        result = locate_entry(self.source,"entrada-00001")
        self.assertEqual(result["operation"],"locate")
        self.assertTrue(any("no se inspecciona" in note for note in result["notes"]))
        self.assertFalse(scan_file(self.source)["complete"])

    def test_cli_locator_and_exclusive_json(self):
        output = self.root/"location.json"
        result = self.invoke("--locate","entrada-00002","--json",output)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout),json.loads(output.read_text("utf-8")))
        self.assertNotIn("first-secret-filename",result.stdout)
        self.assertEqual(self.invoke("--locate","entrada-00002","--json",output).returncode,3)

    def test_cli_wrong_fingerprint_is_private_failure(self):
        result = self.invoke("--locate","entrada-00001","--expect-sha256","0"*64)
        self.assertEqual(result.returncode,3)
        self.assertIn("no coincide",result.stderr)
        self.assertNotIn("first-secret-filename",result.stdout+result.stderr)
        self.assertNotIn("PayloadSentinel",result.stdout+result.stderr)

    def test_cli_missing_id_and_bad_options(self):
        self.assertEqual(self.invoke("--locate","entrada-00003").returncode,3)
        self.assertEqual(self.invoke("--locate","entrada-00001","--show-paths").returncode,2)
        self.assertEqual(self.invoke("--locate","entrada-00001","--html",self.root/"report.html").returncode,2)
        self.assertEqual(self.invoke("--locate","entrada-00001","--expect-sha256","invalid").returncode,2)

    def test_terminal_control_in_selected_name_is_inert_json(self):
        with zipfile.ZipFile(self.source,"w") as archive:
            archive.writestr("selected-\x1b[31m\u202e.txt", "note")
        result = self.invoke("--locate","entrada-00001")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn("\x1b",result.stdout)
        self.assertNotIn("\u202e",result.stdout)
        self.assertIn("\\u001b",result.stdout)


if __name__ == "__main__":
    unittest.main()
