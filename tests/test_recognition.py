import dataclasses
import json
import os
import unittest
from pathlib import Path

from PureWaf import recognition
from PureWaf.sast import available as sast_available


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "recognition"


def load_fixtures():
    cases = []
    for case_dir in sorted(FIXTURES.iterdir()):
        if not case_dir.is_dir():
            continue
        source = (case_dir / "source.php").read_text(encoding="utf-8")
        expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
        cases.append((case_dir.name, source, expected))
    return cases


class RecognitionModelTests(unittest.TestCase):
    def test_dataclasses_serialize(self):
        finding = recognition.RecognitionFinding(
            engine="sast",
            sink=recognition.SinkFinding(kind="command_exec", function="system"),
            sources=[recognition.SourceRef("GET", "c")],
            filters=[recognition.FilterRule(kind="word", params={"needle": "cat"})],
            confidence=0.9,
        )
        payload = dataclasses.asdict(finding)
        self.assertEqual(payload["engine"], "sast")
        self.assertEqual(payload["sources"][0]["key"], "c")
        self.assertEqual(payload["filters"][0]["params"]["needle"], "cat")

    def test_engine_from_env(self):
        previous = os.environ.get(recognition.ENGINE_ENV_VAR)
        try:
            os.environ[recognition.ENGINE_ENV_VAR] = "both"
            self.assertEqual(recognition.engine_from_env(), "both")
            os.environ[recognition.ENGINE_ENV_VAR] = "bogus"
            self.assertEqual(recognition.engine_from_env("sast"), "sast")
        finally:
            if previous is None:
                os.environ.pop(recognition.ENGINE_ENV_VAR, None)
            else:
                os.environ[recognition.ENGINE_ENV_VAR] = previous

    def test_heuristic_engine_matches_auto(self):
        from PureWaf import auto

        source = (FIXTURES / "02-preg-blacklist" / "source.php").read_text(encoding="utf-8")
        analysis = auto.resolve_auto_parameters(source)
        result = recognition.recognize(source, "heuristic")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].sink.kind, analysis.sink_kind)
        self.assertEqual(result.findings[0].sink.function, analysis.sink_function)


@unittest.skipUnless(sast_available(), "tree-sitter sast extra is not installed")
class SastRecognitionTests(unittest.TestCase):
    def test_fixtures_find_expected_sink(self):
        for name, source, expected in load_fixtures():
            with self.subTest(case=name):
                result = recognition.recognize(source, "sast")
                if expected.get("expect_sink") is False:
                    self.assertEqual(result.findings, [], f"{name}: expected no sink")
                    continue
                self.assertTrue(result.findings, f"{name}: no sast finding")
                kinds = {(item.sink.kind, item.sink.function) for item in result.findings}
                wanted = (expected["sink"]["kind"], expected["sink"]["function"])
                self.assertIn(wanted, kinds)

    def test_constant_overwrite_kills_taint(self):
        source = (FIXTURES / "10-constant-overwrite" / "source.php").read_text(encoding="utf-8")
        result = recognition.recognize(source, "sast")
        self.assertEqual(result.findings, [])

    def test_early_return_guard(self):
        source = (FIXTURES / "11-early-return" / "source.php").read_text(encoding="utf-8")
        result = recognition.recognize(source, "sast")
        self.assertTrue(result.findings)
        conditions = result.findings[0].path_conditions
        self.assertTrue(conditions)
        self.assertEqual(conditions[-1].polarity, "true")
        self.assertEqual(conditions[-1].guard.params.get("pattern"), "/flag/")

    def test_switch_case_guard(self):
        source = (FIXTURES / "12-switch-case" / "source.php").read_text(encoding="utf-8")
        result = recognition.recognize(source, "sast")
        self.assertTrue(result.findings)
        self.assertTrue(result.findings[0].path_conditions)
        self.assertIn("==", str(result.findings[0].path_conditions[0].guard.params.get("text")))

    def test_match_arm_guard(self):
        source = (FIXTURES / "13-match-arm" / "source.php").read_text(encoding="utf-8")
        result = recognition.recognize(source, "sast")
        self.assertTrue(result.findings)
        self.assertTrue(result.findings[0].path_conditions)

    def test_cross_function_taint(self):
        source = (FIXTURES / "14-cross-function" / "source.php").read_text(encoding="utf-8")
        result = recognition.recognize(source, "sast")
        self.assertTrue(result.findings)
        self.assertEqual(result.findings[0].sources[0].superglobal, "GET")
        self.assertEqual(result.findings[0].sources[0].key, "c")

    def test_try_catch_guard(self):
        source = (FIXTURES / "15-try-catch" / "source.php").read_text(encoding="utf-8")
        result = recognition.recognize(source, "sast")
        self.assertTrue(result.findings)
        texts = [
            str(condition.guard.params.get("text"))
            for condition in result.findings[0].path_conditions
        ]
        self.assertTrue(any("catch" in text for text in texts), texts)

    def test_project_include(self):
        files = {
            "index.php": "<?php\ninclude 'check.php';\n",
            "check.php": "<?php\nsystem($_GET['c']);\n",
        }
        result = recognition.recognize_project(files, "index.php", "sast")
        self.assertTrue(result.findings)
        self.assertTrue(
            any("file=check.php" in note for finding in result.findings for note in finding.notes)
        )

    def test_complex_regex_is_captured(self):
        source = (FIXTURES / "09-complex-regex" / "source.php").read_text(encoding="utf-8")
        result = recognition.recognize(source, "sast")
        patterns = [
            str(item.params.get("pattern"))
            for finding in result.findings
            for item in finding.filters
        ]
        self.assertTrue(any("(proc|dev|bin|usr|var).{15,}" in pattern for pattern in patterns), patterns)

    def test_constant_regex_is_folded(self):
        source = (FIXTURES / "03-const-regex" / "source.php").read_text(encoding="utf-8")
        result = recognition.recognize(source, "sast")
        patterns = [
            str(item.params.get("pattern"))
            for finding in result.findings
            for item in finding.filters
        ]
        self.assertIn("/flag/i", patterns)

    def test_heredoc_is_not_code(self):
        source = (FIXTURES / "06-heredoc-html" / "source.php").read_text(encoding="utf-8")
        result = recognition.recognize(source, "sast")
        targets = [item.sink.target_expr for item in result.findings]
        self.assertFalse(any("fake" in target for target in targets), targets)
        self.assertTrue(any("real" in target for target in targets), targets)

    def test_dead_branch_sink_is_dropped(self):
        source = (FIXTURES / "05-dead-code" / "source.php").read_text(encoding="utf-8")
        result = recognition.recognize(source, "sast")
        targets = [item.sink.target_expr for item in result.findings]
        self.assertFalse(any("dead" in target for target in targets), targets)

    def test_else_branch_polarity_is_false(self):
        from PureWaf import sast
        from PureWaf.sast import cfg, sinks as sast_sinks

        source = (FIXTURES / "04-branch-polarity" / "source.php").read_text(encoding="utf-8")
        parsed = sast.parse(source)
        assignments = cfg.collect_assignments(parsed)
        sink = sast_sinks.find_sinks(parsed, assignments)[0]
        node = recognition._node_at(parsed, sink.span)
        guards = cfg.guard_conditions(parsed, node)
        self.assertEqual(guards[-1][1], "false")


@unittest.skipUnless(sast_available(), "tree-sitter sast extra is not installed")
class ParserTests(unittest.TestCase):
    def test_parser_unavailable_raises(self):
        from unittest.mock import patch

        from PureWaf.sast import parser as sast_parser

        old_parser, old_language = sast_parser._PARSER, sast_parser._LANGUAGE
        sast_parser._PARSER = None
        sast_parser._LANGUAGE = None
        try:
            with patch("builtins.__import__", side_effect=ImportError("missing")):
                with self.assertRaises(sast_parser.SastUnavailable):
                    sast_parser._ensure_parser()
            with patch.object(
                sast_parser, "_ensure_parser", side_effect=sast_parser.SastUnavailable("x")
            ):
                self.assertFalse(sast_parser.available())
        finally:
            sast_parser._PARSER, sast_parser._LANGUAGE = old_parser, old_language

    def test_parse_reports_syntax_error(self):
        from PureWaf import sast

        parsed = sast.parse("<?php if (")
        self.assertTrue(parsed.has_error)
        self.assertTrue(parsed.errors)

    def test_parse_cache_returns_equivalent_tree(self):
        from PureWaf import sast

        first = sast.parse("<?php system($_GET['c']);")
        second = sast.parse("<?php system($_GET['c']);")
        self.assertEqual(first.source_bytes, second.source_bytes)
        self.assertIs(first.tree, second.tree)

    def test_span_and_text(self):
        from PureWaf import sast

        parsed = sast.parse("<?php\nsystem($_GET['c']);")
        call = next(
            node
            for node in sast.parser.walk(parsed.root)
            if node.type == "function_call_expression"
        )
        self.assertIn("system", parsed.text(call))
        span = parsed.span(call)
        self.assertEqual(span.start_line, 2)

    def test_available_and_call_helpers(self):
        from PureWaf import sast

        self.assertTrue(sast.available())
        parsed = sast.parse("<?php system((('cat')));")
        call = next(
            node
            for node in sast.parser.walk(parsed.root)
            if node.type == "function_call_expression"
        )
        self.assertEqual(sast.parser.call_name(call), "system")
        self.assertEqual(len(sast.parser.arguments_of(call)), 1)
        self.assertEqual(
            sast.parser.unwrap_parentheses(sast.parser.arguments_of(call)[0]).type,
            "string",
        )

    def test_string_literal_escapes(self):
        from PureWaf import sast

        parsed = sast.parse("<?php $a = 'it\\'s'; $b = \"plain\";")
        literals = [
            sast.parser.string_literal(node)
            for node in sast.parser.walk(parsed.root)
            if node.type in {"string", "encapsed_string"}
        ]
        self.assertIn("it's", literals)
        self.assertIn("plain", literals)


@unittest.skipUnless(sast_available(), "tree-sitter sast extra is not installed")
class SastExtractionTests(unittest.TestCase):
    def _filters(self, source):
        from PureWaf import sast
        from PureWaf.sast import filters as sast_filters

        parsed = sast.parse(source)
        return sast_filters.find_filters(parsed)

    def _sinks(self, source):
        from PureWaf import sast
        from PureWaf.sast import cfg, sinks as sast_sinks

        parsed = sast.parse(source)
        return sast_sinks.find_sinks(parsed, cfg.collect_assignments(parsed))

    def test_mb_ereg_filter(self):
        filters = self._filters("<?php mb_ereg('flag|cat', $_GET['c']);")
        self.assertEqual(filters[0].kind, "regex")
        self.assertEqual(filters[0].params["pattern"], "flag|cat")

    def test_in_array_filter(self):
        filters = self._filters("<?php in_array($_GET['c'], ['ls', 'cat']);")
        self.assertEqual(filters[0].kind, "in_array")
        self.assertEqual(filters[0].params["values"], ["ls", "cat"])

    def test_str_replace_filter(self):
        filters = self._filters("<?php str_replace('cat', '', $_GET['c']);")
        self.assertEqual(filters[0].kind, "word")
        self.assertEqual(filters[0].params["needle"], "cat")

    def test_strlen_filter(self):
        filters = self._filters("<?php if (strlen($_GET['c']) > 20) { die(); }")
        self.assertEqual(filters[0].kind, "length")

    def test_sanitizer_filter(self):
        filters = self._filters("<?php $x = escapeshellarg($_GET['c']);")
        self.assertEqual(filters[0].kind, "sanitizer")
        self.assertEqual(filters[0].params["name"], "escapeshellarg")

    def test_file_read_sink(self):
        sinks = self._sinks("<?php readfile($_GET['f']);")
        self.assertEqual(sinks[0].kind, "file_read_path")
        self.assertEqual(sinks[0].function, "readfile")

    def test_file_write_sink(self):
        sinks = self._sinks("<?php file_put_contents($_GET['f'], $_POST['c']);")
        self.assertEqual(sinks[0].kind, "file_write_upload")

    def test_backtick_sink(self):
        sinks = self._sinks("<?php `cat $_GET['f']`;")
        self.assertEqual(sinks[0].kind, "command_exec")
        self.assertEqual(sinks[0].function, "backtick")

    def test_callback_sink(self):
        sinks = self._sinks("<?php ob_start($_GET['fn']);")
        self.assertEqual(sinks[0].kind, "command_exec")
        self.assertEqual(sinks[0].payload_context, "php_code")


class ArbitrationTests(unittest.TestCase):
    def test_both_engines_agree_on_direct_eval(self):
        source = (FIXTURES / "01-direct-eval" / "source.php").read_text(encoding="utf-8")
        result = recognition.recognize(source, "both")
        self.assertTrue(result.findings)
        self.assertGreaterEqual(result.findings[0].confidence, 0.9)
        self.assertEqual(result.findings[0].engine, "both")

    def test_conflicts_are_reported(self):
        heuristic = recognition.RecognitionFinding(
            engine="heuristic",
            sink=recognition.SinkFinding(kind="command_exec", function="system"),
            filters=[recognition.FilterRule(kind="word", params={"needle": "cat"})],
        )
        sast = recognition.RecognitionFinding(
            engine="sast",
            sink=recognition.SinkFinding(kind="command_exec", function="system"),
            filters=[recognition.FilterRule(kind="regex", params={"pattern": "/cat/i"})],
        )
        merged = recognition.arbitrate([heuristic, sast])
        self.assertEqual(len(merged.findings), 1)
        self.assertEqual(merged.conflicts[0]["type"], "conflict_filter")


if __name__ == "__main__":
    unittest.main()
