import importlib.util
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

script = Path(__file__).resolve().parents[1]/"tools"/"build_release.py"
spec = importlib.util.spec_from_file_location("release_builder",script)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ReleasePrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base/"project"
        self.root.mkdir()
        (self.root/"paquetelupa").mkdir()
        (self.root/"paquetelupa"/"__init__.py").write_text("# synthetic package",encoding="utf-8")
        (self.root/"README.md").write_text("synthetic readme",encoding="utf-8")

    def manifest(self,names):
        (self.root/".release-manifest.json").write_text(json.dumps({"files":names}),encoding="utf-8")

    def test_unlisted_reports_archives_and_modules_never_ship(self):
        self.manifest(["README.md","paquetelupa/__init__.py"])
        for name in ("customer-report.json","production.zip","CONTINUITY.md","paquetelupa/private.py"):
            (self.root/name).write_text("PRIVATE-RELEASE-SENTINEL",encoding="utf-8")
        with patch.object(builder,"ROOT",self.root),patch.object(builder,"OUTPUT",self.base),contextlib.redirect_stdout(io.StringIO()):
            builder.main()
        for name in (f"PaqueteLupa-{builder.VERSION}.pyz",f"PaqueteLupa-{builder.VERSION}-fuentes.zip"):
            with zipfile.ZipFile(self.base/name) as archive:
                for info in archive.infolist():
                    self.assertNotIn(b"PRIVATE-RELEASE-SENTINEL",archive.read(info))
                    self.assertNotIn("production.zip",info.filename)

    def test_manifest_cannot_escape_or_use_windows_streams(self):
        for name in ("../outside.txt","/absolute.txt","C:/file.txt","README.md:hidden","paquetelupa\\private.py",".git/config","./README.md"):
            with self.subTest(name=name):
                self.manifest([name])
                with self.assertRaises(ValueError):
                    builder.source_files(self.root)

    def test_missing_and_duplicate_manifest_entries_fail_closed(self):
        for names in (["missing.txt"],["README.md","README.md"],[],[1]):
            with self.subTest(names=names):
                self.manifest(names)
                with self.assertRaises(ValueError):
                    builder.source_files(self.root)

    def test_symlink_source_is_rejected_without_following_it(self):
        self.manifest(["README.md"])
        with patch.object(Path,"is_symlink",return_value=True):
            with self.assertRaises(ValueError):
                builder.source_files(self.root)


if __name__ == "__main__":
    unittest.main()
