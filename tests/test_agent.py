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

    def test_prompt_contains_purewaf_guide_and_safety_bounds(self):
        agent = PureWafLlmSinkAgent()
        messages = agent.build_messages("<?php system($_GET['x']);")
        prompt = "\n".join(message["content"] for message in messages)

        self.assertIn("PureWaf is a CTF", prompt)
        self.assertIn("AUTO mode analyzes one PHP source file", prompt)
        self.assertIn("Allowed sink kinds are only", prompt)
        self.assertIn("command_exec", prompt)
        self.assertIn("file_read_path", prompt)
        self.assertIn("file_write_upload", prompt)
        self.assertIn("Allowed payload_context values are only", prompt)
        self.assertIn("Do not generate payloads", prompt)
        self.assertIn("PureWaf tool usage guide from skills/SKILL.md", prompt)
        self.assertIn("# PureWaf LLM AUTO", prompt)
        self.assertNotIn("## Troubleshooting", prompt)
        self.assertNotIn("LLM skipped", prompt)

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


if __name__ == "__main__":
    unittest.main()
