import os
import shutil
import subprocess
import sys
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIXTURE_DIR = os.path.join(ROOT, "tests", "fixtures", "filter_bypass")
sys.path.insert(0, ROOT)

from PureWaf import bypass
from PureWaf import utils
from PureWaf.auto import analyze_php_auto
from PureWaf.auto import resolve_auto_parameters


def _read_fixture(name):
    with open(os.path.join(FIXTURE_DIR, name), "r", encoding="utf-8") as handle:
        return handle.read()


class FilterBypassFixtureTests(unittest.TestCase):
    def test_fixture_inventory(self):
        fixtures = sorted(name for name in os.listdir(FIXTURE_DIR) if name.endswith(".php"))

        self.assertEqual(
            fixtures,
            [
                "blacklist_words.php",
                "escapeshellcmd.php",
                "eval_no_alnum.php",
                "fixed_file_prefix.php",
                "no_slash.php",
                "no_space.php",
                "upload_filter.php",
            ],
        )

    def test_fixtures_are_php_lint_clean_when_php_exists(self):
        php_bin = shutil.which("php")
        if not php_bin:
            self.skipTest("php CLI not found")

        for name in sorted(os.listdir(FIXTURE_DIR)):
            if not name.endswith(".php"):
                continue
            with self.subTest(name=name):
                proc = subprocess.run(
                    [php_bin, "-l", os.path.join(FIXTURE_DIR, name)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout.decode("utf-8", "replace"))

    def test_no_space_fixture_generates_space_tamper_candidates(self):
        result = analyze_php_auto(_read_fixture("no_space.php"))
        self.assertEqual(result.error, "")
        self.assertEqual(result.waf_regex, "/ /")

        regex = utils.parse_waf_regex(result.waf_regex)
        candidates = bypass._build_targeted_candidates(
            ["cat /flag"],
            [],
            set(),
            regex,
            payload_context=result.payload_context,
        )
        passed = bypass.filter_payloads(candidates, [], set(), regex, 999999, show_progress=False)

        self.assertIn("cat${IFS}/flag", passed)
        self.assertIn("cat\t/flag", passed)

    def test_no_slash_fixture_generates_slash_tamper_candidates(self):
        result = analyze_php_auto(_read_fixture("no_slash.php"))
        self.assertEqual(result.error, "")
        self.assertEqual(result.waf_regex, r"/\//")

        regex = utils.parse_waf_regex(result.waf_regex)
        candidates = bypass._build_targeted_candidates(
            ["cat /flag"],
            [],
            set(),
            regex,
            payload_context=result.payload_context,
        )
        passed = bypass.filter_payloads(candidates, [], set(), regex, 999999, show_progress=False)

        self.assertIn("cat ${PWD:0:1}flag", passed)

    def test_blacklist_fixture_generates_word_split_candidates(self):
        result = analyze_php_auto(_read_fixture("blacklist_words.php"))
        self.assertEqual(result.error, "")
        self.assertEqual(result.waf_regex, "/cat|flag/i")

        regex = utils.parse_waf_regex(result.waf_regex)
        candidates = bypass._build_targeted_candidates(
            ["cat /flag"],
            [],
            set(),
            regex,
            payload_context=result.payload_context,
        )
        passed = bypass.filter_payloads(candidates, [], set(), regex, 999999, show_progress=False)

        self.assertIn("c''a''t /f''l''a''g", passed)
        self.assertIn('c""a""t /f""l""a""g', passed)
        self.assertIn(
            "c${PUREWAF_X}a${PUREWAF_X}t /f${PUREWAF_X}l${PUREWAF_X}a${PUREWAF_X}g",
            passed,
        )
        self.assertNotIn("c\\a\\t /f\\l\\a\\g", passed)

    def test_auto_fixture_strategies(self):
        upload = analyze_php_auto(_read_fixture("upload_filter.php"))
        self.assertEqual(upload.error, "")
        self.assertEqual(upload.sink_kind, "file_write_upload")

        fixed = analyze_php_auto(_read_fixture("fixed_file_prefix.php"))
        self.assertEqual(fixed.error, "")
        self.assertEqual(fixed.fixed_command_prefix, "file")

        escaped = resolve_auto_parameters(_read_fixture("escapeshellcmd.php"))
        self.assertEqual(escaped.error, "")
        self.assertIn("escapeshellcmd", escaped.sanitizers)

        no_alnum = resolve_auto_parameters(_read_fixture("eval_no_alnum.php"))
        self.assertEqual(no_alnum.error, "")
        self.assertEqual(no_alnum.payload_context, "php_code")
        self.assertEqual(no_alnum.waf_regex, "/[A-Za-z0-9]/")


if __name__ == "__main__":
    unittest.main()
