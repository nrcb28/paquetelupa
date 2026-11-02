from contextlib import redirect_stderr
import io
import unittest

from paquetelupa.__main__ import _parser, main


class ArgumentPrivacyTests(unittest.TestCase):
    def test_invalid_arguments_never_echo_values_or_controls(self):
        sentinel = "ArgumentSentinelSecret123\x1b[31m\u202e"
        for arguments in (("demo.zip", "--" + sentinel), ("demo.zip", "--timeout", sentinel),
                          ("demo.zip", "--format", sentinel)):
            with self.subTest(arguments_count=len(arguments)):
                output = io.StringIO()
                with redirect_stderr(output), self.assertRaises(SystemExit) as raised:
                    _parser().parse_args(arguments)
                self.assertEqual(raised.exception.code, 2)
                self.assertNotIn("ArgumentSentinelSecret", output.getvalue())
                self.assertNotIn("\x1b", output.getvalue())
                self.assertNotIn("\u202e", output.getvalue())

    def test_dash_prefixed_filename_can_be_explicit(self):
        self.assertEqual(_parser().parse_args(["--", "-soporte.zip"]).archive, "-soporte.zip")

    def test_safe_validation_messages_explain_the_problem_without_echoing_values(self):
        sentinel = "ArgumentSentinelSecret123\x1b[31m\u202e"
        for arguments, expected in (
            (["--locate", "entrada-00001", "--html", sentinel], "La localización no admite HTML"),
            (["--locate", sentinel], "Usa el formato entrada-00001"),
            (["--expect-sha256", sentinel], "64 caracteres hexadecimales"),
        ):
            with self.subTest(expected=expected):
                output = io.StringIO()
                with redirect_stderr(output), self.assertRaises(SystemExit) as raised:
                    main(["private-" + sentinel + ".zip", *arguments])
                self.assertEqual(raised.exception.code, 2)
                self.assertIn(expected, output.getvalue())
                self.assertNotIn("ArgumentSentinelSecret", output.getvalue())
                self.assertNotIn("\x1b", output.getvalue())
                self.assertNotIn("\u202e", output.getvalue())


if __name__ == "__main__":
    unittest.main()
