import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from PureWaf.agent import PureWafLlmSinkAgent
from PureWaf.agent import PureWafProjectAgent
from PureWaf.agent import MAX_PROJECT_FILE_BYTES


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
        self.assertIn("fallback_payload", prompt)


if __name__ == "__main__":
    unittest.main()
