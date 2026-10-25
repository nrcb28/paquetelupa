"""Synthetic regression cases for plausible credential leakage in logs."""

import json
import time
import tracemalloc
import unittest

from paquetelupa.detectors import decode_text, scan_text


class DetectorSecurityV011Tests(unittest.TestCase):
    def assert_rule(self, text, rule):
        findings = scan_text(text, "entrada-00001")
        self.assertTrue(any(item["rule"] == rule for item in findings), rule)
        return findings

    def test_quoted_passwords_with_short_first_word_and_spaces(self):
        for text in ('"password": "two words plus synthetic 789"',
                     "password='my synthetic passphrase 456'",
                     'api_key="a b c d synthetic"'):
            with self.subTest(text=text):
                self.assert_rule(text, "credential-assignment")

    def test_common_environment_credential_names(self):
        for name in ("DB_PASSWORD", "DATABASE_PASSWORD", "AWS_SECRET_ACCESS_KEY",
                     "SERVICE_AUTH_TOKEN", "SECRET_KEY"):
            with self.subTest(name=name):
                self.assert_rule(name + "=syntheticCredential987", "credential-assignment")

    def test_quoted_long_passphrase_does_not_disappear_at_capture_limit(self):
        self.assert_rule('password="two ' + "synthetic " * 40 + '"', "credential-assignment")

    def test_escaped_quotes_inside_quoted_passphrase(self):
        self.assert_rule(r'password="a \"b\" synthetic phrase 789"', "credential-assignment")

    def test_encrypted_pkcs8_private_key_header(self):
        self.assert_rule("-----BEGIN ENCRYPTED PRIVATE KEY-----\nSYNTHETIC\n-----END ENCRYPTED PRIVATE KEY-----", "private-key")

    def test_cr_only_and_mixed_line_numbers(self):
        findings = scan_text("ordinary\rpassword=syntheticOne9\rordinary\rsecret=syntheticTwo8", "entrada-00001")
        self.assertEqual([item["line"] for item in findings], [2, 4])
        findings = scan_text("ordinary\r\npassword=syntheticOne9\nordinary\rsecret=syntheticTwo8", "entrada-00001")
        self.assertEqual([item["line"] for item in findings], [2, 4])

    def test_ansi_colours_inside_key_and_provider_token(self):
        self.assert_rule("pass\x1b[31mword\x1b[0m=syntheticCredential9", "credential-assignment")
        self.assert_rule("ghp_" + "aB7z" * 4 + "\x1b[0m" + "aB7z" * 5, "github-token")

    def test_control_and_zero_width_characters_inside_key(self):
        for text in ("pass\bword=syntheticCredential9", "pass\u200bword=syntheticCredential9",
                     "pass\u2060word=syntheticCredential9"):
            with self.subTest(text=text):
                self.assert_rule(text, "credential-assignment")

    def test_fullwidth_compatibility_key_and_separator(self):
        self.assert_rule("ｐａｓｓｗｏｒｄ：syntheticCredential9", "credential-assignment")

    def test_escaped_json_authorization_header(self):
        self.assert_rule(r'{\"Authorization\":\"Bearer syntheticCredential987\"}', "http-authorization")

    def test_escaped_json_password_key_and_value(self):
        self.assert_rule(r'{\"password\":\"two words synthetic 678\"}', "credential-assignment")
        self.assert_rule(r'{"pass\u0077ord":"two words synthetic 678"}', "credential-assignment")

    def test_escaped_database_url(self):
        self.assert_rule(r'postgresql:\/\/user:syntheticCredential9@db.invalid\/db', "database-url-password")

    def test_literal_password_starting_angle_bracket_is_not_placeholder(self):
        self.assert_rule('password="<SyntheticallySensitive9>"', "credential-assignment")

    def test_environment_default_value_is_not_an_empty_reference(self):
        self.assert_rule("password=${PASSWORD:-syntheticCredential9}", "credential-assignment")

    def test_normalized_findings_never_include_source_or_secret(self):
        sentinel = "SYNTHETIC_PRIVATE_PHRASE_7842"
        texts = [f'"password": "two words {sentinel}"',
                 "pass\x1b[31mword=" + sentinel,
                 r'{\"password\":\"' + sentinel + r'\"}']
        for text in texts:
            with self.subTest(text=text):
                findings = self.assert_rule(text, "credential-assignment")
                serialized = json.dumps(findings, ensure_ascii=True)
                self.assertNotIn(sentinel, serialized)
                self.assertNotIn(text, serialized)
                self.assertTrue(all(set(item) == {"rule", "severity", "entry", "line", "message", "remediation"} for item in findings))

    def test_existing_placeholders_remain_ignored(self):
        for value in ('"<password>"', '"${PASSWORD}"', '"REDACTED"', '"********"'):
            with self.subTest(value=value):
                self.assertEqual(scan_text("password=" + value, "entrada-00001"), [])

    def test_non_ascii_ordinary_text_is_not_a_credential(self):
        self.assertEqual(scan_text("Información sintética en español. contraseña de ejemplo sin asignación.", "entrada-00001"), [])

    def test_escaped_control_text_remains_bounded(self):
        # A fixed-size regression workload catches accidental nested repetition;
        # this does not claim a universal performance guarantee.
        text = (r'\u200b\"' + "x" * 32) * 10000
        started = time.monotonic()
        self.assertEqual(scan_text(text, "entrada-00001"), [])
        self.assertLess(time.monotonic() - started, 5)

    def test_decoded_ansi_log_can_be_inspected(self):
        text = decode_text(b"pass\x1b[31mword=syntheticCredential9\x1b[0m")
        self.assertIsNotNone(text)
        self.assert_rule(text, "credential-assignment")

    def test_normalization_does_not_erase_original_detection(self):
        self.assert_rule('password="ＲＥＤＡＣＴＥＤ"', "credential-assignment")

    def test_unterminated_osc_prefixes_remain_bounded(self):
        text = "\x1b]" * 50_000
        started = time.monotonic()
        self.assertEqual(scan_text(text, "entrada-00001"), [])
        self.assertLess(time.monotonic() - started, 5)

    def test_unicode_compatibility_expansion_does_not_materialize_large_lists(self):
        text = "\ufdfa" * 100_000
        tracemalloc.start()
        try:
            self.assertEqual(scan_text(text, "entrada-00001"), [])
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 8 * 1024 * 1024)

    def test_optional_cooperative_callback(self):
        calls = []
        scan_text("ordinary\rpassword=syntheticCredential9", "entrada-00001", check=lambda: calls.append(True))
        self.assertGreaterEqual(len(calls), 2)
        class BudgetExpired(Exception):
            pass
        def expired():
            raise BudgetExpired()
        with self.assertRaises(BudgetExpired):
            scan_text("password=syntheticCredential9", "entrada-00001", check=expired)


if __name__ == "__main__":
    unittest.main()
