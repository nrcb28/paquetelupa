"""Security regression tests for inert reports and readable terminal output."""

import copy
from html.parser import HTMLParser
import unittest

from paquetelupa.reports import MAX_FIELD, MAX_ROWS, render_html, render_text


def report_fixture():
    return {
        "schema_version": "1.0",
        "tool": {"name": "PaqueteLupa", "version": "0.1.0"},
        "status": "review",
        "complete": True,
        "summary": {"entries": 1, "scanned_text_files": 1, "skipped_files": 0, "bytes_read": 32, "findings": 1},
        "limits": {"max_entry_bytes": 1048576},
        "findings": [{"rule": "secret.generic", "severity": "high", "entry": "E0001", "line": 2,
                      "message": "Credencial potencial.", "remediation": "Revisa y rota la credencial."}],
        "entries": [{"id": "E0001", "size": 32, "compressed_size": 30, "state": "scanned_text"}],
        "notes": ["El análisis usa patrones; puede haber falsos positivos."],
    }


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attrs = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.extend(attrs)


class ReportsTests(unittest.TestCase):
    def test_three_states(self):
        for status, complete, expected in [
            ("review", True, "Requiere revisión"),
            ("incomplete", False, "Análisis incompleto"),
            ("no_findings", True, "Sin coincidencias en lo revisado"),
        ]:
            with self.subTest(status=status):
                report = report_fixture()
                report.update(status=status, complete=complete)
                self.assertIn(expected, render_text(report))
                self.assertIn(expected, render_html(report))

    def test_incomplete_cannot_claim_no_findings(self):
        report = report_fixture()
        report.update(status="no_findings", complete=False)
        self.assertIn("Resultado: Análisis incompleto", render_text(report))
        self.assertIn('class="badge incomplete"', render_html(report))

    def test_html_escapes_all_dynamic_fields(self):
        payload = '\"><script>alert(1)</script><img src=x onerror=alert(2)>&\' '
        report = report_fixture()
        report["schema_version"] = payload
        report["tool"]["version"] = payload
        report["summary"] = {key: payload for key in report["summary"]}
        report["limits"] = {payload: payload}
        report["findings"] = [{key: payload for key in report["findings"][0]}]
        report["entries"] = [{key: payload for key in report["entries"][0]} | {"path": payload}]
        report["notes"] = [payload]
        document = render_html(report)
        parsed = Tags()
        parsed.feed(document)
        self.assertNotIn("script", parsed.tags)
        self.assertNotIn("img", parsed.tags)
        self.assertNotIn("iframe", parsed.tags)
        self.assertFalse(any(key.startswith("on") for key, _ in parsed.attrs))
        self.assertIn("&lt;script&gt;", document)
        self.assertIn("&quot;", document)
        self.assertIn("&#x27;", document)
        self.assertIn("&amp;", document)

    def test_terminal_controls_and_bidi_are_inert_everywhere(self):
        payload = "first\x1b[2J\x00\x7f\x9b31m\nforged\r\t\u202eexe\u2066\u2028\ud800last"
        report = report_fixture()
        report["schema_version"] = payload
        report["tool"]["version"] = payload
        report["summary"] = {key: payload for key in report["summary"]}
        report["limits"] = {payload: payload}
        report["findings"] = [{key: payload for key in report["findings"][0]}]
        report["entries"] = [{key: payload for key in report["entries"][0]} | {"path": payload}]
        report["notes"] = [payload]
        text = render_text(report)
        for char in "\x1b\x00\x7f\x9b\r\t\u202e\u2066\u2028\ud800":
            self.assertNotIn(char, text)
        self.assertNotIn("\nforged", text)
        self.assertIn("\\u001b", text)
        self.assertIn("\\u202e", text)
        self.assertIn("\\ud800", text)
        self.assertIn("Revisión", text)

    def test_csp_and_no_external_dependencies(self):
        document = render_html(report_fixture())
        self.assertIn("default-src 'none'", document)
        self.assertIn("style-src 'unsafe-inline'", document)
        self.assertIn("base-uri 'none'", document)
        self.assertIn("form-action 'none'", document)
        self.assertIn("img-src 'none'", document)
        parsed = Tags()
        parsed.feed(document)
        self.assertFalse({"script", "link", "img", "iframe", "object", "embed", "form", "base"} & set(parsed.tags))
        self.assertFalse(any(key in {"src", "href"} for key, _ in parsed.attrs))

    def test_paths_opt_in(self):
        report = report_fixture()
        self.assertNotIn("Ruta solicitada", render_html(report))
        self.assertNotIn("ruta: ", render_text(report))
        report["entries"][0]["path"] = "conf/settings.xml"
        self.assertIn("conf/settings.xml", render_html(report))
        self.assertIn("conf/settings.xml", render_text(report))

    def test_fields_and_rows_are_bounded(self):
        report = report_fixture()
        report["notes"] = ["A" * (MAX_FIELD + 100)]
        report["entries"] *= MAX_ROWS + 1
        for rendered in (render_html(report), render_text(report)):
            self.assertNotIn("A" * (MAX_FIELD + 1), rendered)
            self.assertIn("[truncado]", rendered)
            self.assertIn("límite de presentación", rendered)

    def test_no_mutation(self):
        report = report_fixture()
        original = copy.deepcopy(report)
        render_html(report)
        render_text(report)
        self.assertEqual(report, original)

    def test_ignores_unknown_evidence_fields(self):
        report = report_fixture()
        report["secret"] = "MUST_NOT_APPEAR_4927"
        report["findings"][0]["evidence"] = "MUST_NOT_APPEAR_4927"
        report["entries"][0]["content"] = "MUST_NOT_APPEAR_4927"
        for rendered in (render_html(report), render_text(report)):
            self.assertNotIn("MUST_NOT_APPEAR_4927", rendered)

    def test_malformed_optional_fields_fail_closed(self):
        report = report_fixture()
        report["status"] = []
        report["findings"][0]["severity"] = []
        report["notes"] = None
        report["limits"] = None
        report["entries"].append(None)
        self.assertIn("Análisis incompleto", render_text(report))
        self.assertIn("Análisis incompleto", render_html(report))

    def test_no_findings_still_explains_limits(self):
        report = report_fixture()
        report.update(status="no_findings", findings=[])
        report["summary"]["findings"] = 0
        for rendered in (render_html(report), render_text(report)):
            self.assertIn("no es un certificado", rendered)
            self.assertIn("no garantiza", rendered)
            self.assertIn("No se registraron coincidencias", rendered)


if __name__ == "__main__":
    unittest.main()
