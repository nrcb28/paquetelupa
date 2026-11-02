"""The fuzz oracle must detect semantic regressions, not only parser failures."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.fuzz_smoke import _check, _detection_corpus, _InvariantFailure
from paquetelupa.scanner import scan_file


class DetectionCorpusTests(unittest.TestCase):
    def test_positive_and_negative_zip_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.zip"
            for label, data, expected in _detection_corpus():
                with self.subTest(case=label):
                    _check(path, data, expected_findings=expected)

    def test_oracle_rejects_a_silenced_detector(self):
        _, data, expected = next(case for case in _detection_corpus() if case[0] == "assignment")
        with tempfile.TemporaryDirectory() as directory:
            with patch("paquetelupa.scanner.scan_text", return_value=[]):
                with self.assertRaises(_InvariantFailure) as raised:
                    _check(Path(directory) / "fixture.zip", data, expected_findings=expected)
        self.assertEqual(raised.exception.invariant, "detection_corpus_findings")

    def test_oracle_rejects_a_false_positive(self):
        _, data, expected = next(case for case in _detection_corpus() if case[0] == "ordinary_text")
        false_positive = {"rule": "credential-assignment", "severity": "medium",
                          "entry": "entrada-00001", "line": 1,
                          "message": "Synthetic finding.", "remediation": "Synthetic advice."}
        with tempfile.TemporaryDirectory() as directory:
            with patch("paquetelupa.scanner.scan_text", return_value=[false_positive]):
                with self.assertRaises(_InvariantFailure) as raised:
                    _check(Path(directory) / "fixture.zip", data, expected_findings=expected)
        self.assertEqual(raised.exception.invariant, "detection_corpus_findings")

    def test_oracle_rejects_incomplete_coverage(self):
        _, data, expected = next(case for case in _detection_corpus() if case[0] == "ordinary_text")

        def incomplete(path):
            report = scan_file(path)
            report.update(complete=False, status="incomplete")
            return report

        with tempfile.TemporaryDirectory() as directory:
            with patch("tools.fuzz_smoke.scan_file", side_effect=incomplete):
                with self.assertRaises(_InvariantFailure) as raised:
                    _check(Path(directory) / "fixture.zip", data, expected_findings=expected)
        self.assertEqual(raised.exception.invariant, "detection_corpus_complete")


if __name__ == "__main__":
    unittest.main()
