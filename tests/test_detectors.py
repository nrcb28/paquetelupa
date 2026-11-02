import json
import time
import unittest

from paquetelupa.detectors import decode_text, scan_text


class DetectorTests(unittest.TestCase):
    def rules(self, text):
        return {finding["rule"] for finding in scan_text(text, "entry-00001")}

    def test_known_formats(self):
        cases = {
            "private-key": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "aws-access-id": "AKIA1234567890ABCDEF",
            "github-token": "ghp_" + "aB7z" * 9,
            "stripe-live-secret": "sk_live_" + "aB7z" * 8,
            "credential-assignment": '"password": "s3cretvalue"',
            "http-authorization": "Authorization: Bearer " + "aB7z" * 8,
            "database-url-password": "postgresql://admin:s3cretvalue@db.example/db",
            "jwt-shaped-value": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefgh12345678",
        }
        for rule, value in cases.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, self.rules(value))

    def test_no_secret_material_in_findings(self):
        secret = "uniquely_sensitive_value_Q7Jq"
        findings = scan_text("password=" + secret, "entry-00001")
        self.assertTrue(findings)
        serialized = json.dumps(findings)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("uniquely_sensitive", serialized)
        self.assertEqual(set(findings[0]), {"rule", "severity", "entry", "line", "message", "remediation"})

    def test_line_numbers_and_repeated_values(self):
        findings = scan_text("ok\r\npassword=abcd1234 password=efgh5678\n\nsecret=QRST1234", "entry-00002")
        self.assertEqual([finding["line"] for finding in findings], [2, 4])
        self.assertTrue(all(finding["entry"] == "entry-00002" for finding in findings))

    def test_placeholders_and_environment_references(self):
        for value in ["changeme", "REDACTED", "*********", "${DB_PASSWORD}", "$PASSWORD", "%PASSWORD%", "process.env.PASSWORD", "os.getenv('PASSWORD')", "null", "<password>",
                      "$env:PASSWORD", "$Env:PASSWORD", "$ENV:PASSWORD", 'process.env["PASSWORD"]', "os.environ['PASSWORD']",
                      'os.environ.get("PASSWORD")', 'getenv("PASSWORD")', "env('PASSWORD')"]:
            with self.subTest(value=value):
                self.assertNotIn("credential-assignment", self.rules("password=" + value))
        self.assertNotIn("aws-access-id", self.rules("AKIAIOSFODNN7EXAMPLE"))

    def test_environment_references_in_containers_and_with_comments(self):
        for text in ('{"password": os.getenv("PASSWORD")}',
                     "connect(password=os.environ['PASSWORD'])",
                     "password=process.env.PASSWORD;", "password=$env:PASSWORD # environment"):
            with self.subTest(text=text):
                self.assertEqual(self.rules(text), set())

    def test_redis_urls_require_a_password_but_not_a_username(self):
        for scheme in ("redis", "rediss"):
            with self.subTest(scheme=scheme):
                self.assertIn("database-url-password", self.rules(scheme + "://:syntheticCredential9@cache.invalid/0"))
                self.assertIn("database-url-password", self.rules(scheme + "://default:syntheticCredential9@cache.invalid/0"))
                self.assertEqual(self.rules(scheme + "://cache.invalid/0"), set())
                self.assertEqual(self.rules(scheme + "://default:@cache.invalid/0"), set())
                self.assertEqual(self.rules(scheme + "://:@cache.invalid/0"), set())

    def test_test_prefix_is_not_automatically_ignored(self):
        self.assertIn("credential-assignment", self.rules("password=test_abcd1234"))

    def test_non_secret_text(self):
        self.assertEqual(scan_text("No credentials here.\npassword policy requires 12 characters", "entry-00001"), [])
        self.assertEqual(scan_text("Basic information about a bearer instrument", "entry-00001"), [])

    def test_token_boundaries(self):
        self.assertNotIn("aws-access-id", self.rules("XAKIA1234567890ABCDEF"))
        self.assertNotIn("github-token", self.rules("ghp_" + "a" * 37))

    def test_limit_and_validation(self):
        text = "password=abcd1234\n" * 20
        self.assertEqual(len(scan_text(text, "entry-00001", limit=3)), 3)
        self.assertEqual(scan_text(text, "entry-00001", limit=0), [])
        for limit in [-1, 10_001, True, "10"]:
            with self.assertRaises(ValueError):
                scan_text(text, "entry-00001", limit=limit)

    def test_basic_and_bearer(self):
        self.assertIn("http-authorization", self.rules("Authorization: Basic dXNlcjpwYXNzd29yZA=="))
        self.assertNotIn("http-authorization", self.rules("Authorization: Bearer REDACTED"))

    def test_pathological_input_is_bounded(self):
        # No matching credential: bound long inputs to catch accidental nested
        # quantifiers/backtracking without requiring a microbenchmark threshold.
        text = '"' * 100_000 + " " + "a" * 100_000 + " " + "eyJ" + "a" * 100_000
        started = time.monotonic()
        self.assertEqual(scan_text(text, "entry-00001"), [])
        self.assertLess(time.monotonic() - started, 5.0)

    def test_decode_supported_text(self):
        self.assertEqual(decode_text(b""), "")
        self.assertEqual(decode_text("contraseña=abcd1234".encode()), "contraseña=abcd1234")
        self.assertEqual(decode_text("password=abcd1234".encode("utf-16")), "password=abcd1234")
        self.assertEqual(decode_text(b"\xef\xbb\xbfhello"), "hello")
        self.assertEqual(decode_text(b"\x1b[31mred\x1b[0m"), "\x1b[31mred\x1b[0m")

    def test_decode_binary_and_unsupported(self):
        for data in [b"\x00", b"\xff\xfeA", b"\x89PNG\r\n\x1a\n", "text".encode("utf-32"), b"a\x01\x02\x03b"]:
            with self.subTest(data=data):
                self.assertIsNone(decode_text(data))


if __name__ == "__main__":
    unittest.main()
