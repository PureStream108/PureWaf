import os
import sys
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from PureWaf import utils


class UtilsTests(unittest.TestCase):
    def test_strip_regex_delimiters(self):
        self.assertEqual(utils._strip_regex_delimiters("/abc/"), "abc")
        self.assertEqual(utils._strip_regex_delimiters("/abc/i"), "abc")
        self.assertEqual(utils._strip_regex_delimiters("id/i"), "id")
        self.assertEqual(utils._strip_regex_delimiters("plain"), "plain")

    def test_parse_regex_flags(self):
        flags = utils._parse_regex_flags("im")
        self.assertTrue(flags & utils.re.IGNORECASE)
        self.assertTrue(flags & utils.re.MULTILINE)

    def test_parse_waf_words(self):
        result = utils.parse_waf_words("wget|cat|id/i")
        self.assertEqual(result, ["wget", "cat", "id"])

    def test_parse_waf_chars(self):
        chars = utils.parse_waf_chars("*\\{}%[]!?\'\".")
        for ch in ["*", "\\", "{", "}", "%", "[", "]", "!", "?", "'", "\"", "."]:
            self.assertIn(ch, chars)

    def test_parse_waf_regex(self):
        regex = utils.parse_waf_regex("/[A-Za-z0-9_]/i")
        self.assertIsNotNone(regex)
        self.assertTrue(regex.search("A"))
        self.assertIsNone(utils.parse_waf_regex("[A-Z"))

    def test_dedupe_preserve_order(self):
        items = ["a", "b", "a", "c", "b"]
        self.assertEqual(utils.dedupe_preserve_order(items), ["a", "b", "c"])

    def test_is_payload_allowed(self):
        words = ["cat"]
        chars = {"$"}
        regex = utils.re.compile("flag")
        self.assertFalse(utils.is_payload_allowed("cat /f", words, chars, regex, 10))
        self.assertFalse(utils.is_payload_allowed("ls $", words, chars, regex, 10))
        self.assertFalse(utils.is_payload_allowed("show flag", words, chars, regex, 10))
        self.assertFalse(utils.is_payload_allowed("okay", words, chars, regex, 3))
        self.assertTrue(utils.is_payload_allowed("okay", words, chars, regex, 10))

    def test_url_encode(self):
        self.assertEqual(utils.url_encode("a b"), "a%20b")

    def test_double_url_encode(self):
        self.assertEqual(utils.double_url_encode("a b"), "a%2520b")

    def test_unicode_escape_encode(self):
        self.assertEqual(utils.unicode_escape_encode("Ab"), "\\u0041\\u0062")

    def test_hex_escape_encode(self):
        self.assertEqual(utils.hex_escape_encode("Ab"), "\\x41\\x62")

    def test_octal_escape_encode(self):
        self.assertEqual(utils.octal_escape_encode("Ab"), "\\101\\142")

    def test_base64_encode(self):
        self.assertEqual(utils.base64_encode("test"), "dGVzdA==")

    def test_get_encoding_strategies(self):
        strategies = utils.get_encoding_strategies()
        self.assertEqual(strategies[0][0], "url")
        self.assertEqual(strategies[-1][0], "raw")


if __name__ == "__main__":
    unittest.main()
