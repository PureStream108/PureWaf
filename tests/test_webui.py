import json
import io
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from PureWaf import bypass
from PureWaf.PureWaf import _execute_purewaf
from PureWaf.PureWaf import purewaf
from PureWaf.PureWaf import PureWafConfig
from PureWaf.PureWaf import PureWafExecutionResult
from PureWaf.auto import AutoAnalysisResult
from PureWaf.agent import ProjectSourceBundle
from PureWaf.agent import ProjectSourceFile
from PureWaf.agent import LlmPayloadReview

try:
    from PureWaf.webui import _build_result_text
    from PureWaf.webui import _build_runtime_config
    from PureWaf.webui import create_app
    from PureWaf.webui import STREAM_LINE_BATCH_SIZE
except Exception:
    create_app = None
    _build_result_text = None
    _build_runtime_config = None
    STREAM_LINE_BATCH_SIZE = None


class WebUiTests(unittest.TestCase):
    def _extract_sse_payloads(self, body):
        payloads = []
        for chunk in body.split("\n\n"):
            if not chunk.startswith("data: "):
                continue
            payloads.append(json.loads(chunk[6:]))
        return payloads

    @unittest.skipIf(create_app is None, "Flask webui module not available")
    def test_create_app_serves_full_page(self):
        app = create_app(PureWafConfig(webui=True))
        client = app.test_client()

        response = client.get("/")

        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        #self.assertIn("PureWaf Web UI", body)
        self.assertIn("payload stream", body)
        self.assertIn("result summary", body)
        self.assertIn('id="result_output"', body)
        self.assertIn('id="mode_filter"', body)
        self.assertIn('id="mode_auto"', body)
        self.assertIn('id="panel_filter"', body)
        self.assertIn('id="panel_auto"', body)
        self.assertIn('id="auto_prompt"', body)
        self.assertIn('id="auto_zip"', body)
        self.assertIn('id="upload_project"', body)
        self.assertIn('id="agent_toggle"', body)
        self.assertIn("AGENT OFF", body)
        self.assertIn("未开始agent功能", body)
        self.assertIn("waf_words", body)
        self.assertNotIn('id="root_result"', body)
        self.assertNotIn('id="flag_result"', body)
        self.assertNotIn('id="tips_result"', body)
        self.assertIn("body{min-height:100vh;overflow:auto", body)
        self.assertIn(".app{height:100vh;min-height:0", body)
        self.assertIn(".main{min-width:0;height:100vh;min-height:0", body)
        self.assertIn("grid-template-rows:auto minmax(0,1.95fr) minmax(0,.95fr)", body)
        self.assertNotIn("html,body{margin:0;height:100%;overflow:hidden", body)
        self.assertIn("PROCESS_PLAYBACK_LINES_PER_TICK = 80", body)

    @unittest.skipIf(STREAM_LINE_BATCH_SIZE is None, "Flask webui module not available")
    def test_webui_streams_larger_server_batches(self):
        self.assertGreaterEqual(STREAM_LINE_BATCH_SIZE, 120)

    @unittest.skipIf(_build_result_text is None, "Flask webui module not available")
    def test_build_result_text_omits_banner_and_keeps_result_tail(self):
        result = PureWafExecutionResult(
            shortest_root="ls /",
            shortest_flag="vi /flag",
            root_passed_payloads=["ls /"],
            flag_passed_payloads=["vi /flag"],
            tips_text="Example:\nfoo",
            log_text=(
                "banner line\n"
                "config line\n"
                "----------------------------------------\n"
                "[+] Final Payload: vi /flag\n"
                "----------------------------------------\n"
                "\n"
                "Example:\n"
                "foo"
            ),
        )

        text = _build_result_text(result)

        self.assertFalse(text.startswith("banner line"))
        self.assertTrue(text.startswith("[+] Final Payload: vi /flag"))
        self.assertIn("Example:\nfoo", text)

    def test_webui_false_keeps_default_path(self):
        with (
            patch("PureWaf.PureWaf._launch_webui") as launch_mock,
            patch("PureWaf.PureWaf._configure_logger", return_value=(None, False)),
            patch("PureWaf.PureWaf._execute_purewaf") as execute_mock,
        ):
            execute_mock.return_value.shortest_flag = "flag-ok"
            result = purewaf(webui=False, log_level="INFO")

        self.assertEqual(result, "flag-ok")
        launch_mock.assert_not_called()
        execute_mock.assert_called_once()

    def test_webui_true_launches_ui_with_prefilled_config(self):
        with (
            patch("PureWaf.PureWaf._launch_webui") as launch_mock,
            patch("PureWaf.PureWaf.bypass.generate_candidates") as generate_mock,
        ):
            result = purewaf(
                waf_regex="/flag/i",
                payload_context="php_code",
                flagfile="/etc/passwd",
                read_env=True,
                reflect_shell=True,
                ip="10.10.10.10",
                port=9090,
                phpinfo=True,
                upload=True,
                log_level="DEBUG",
                total_payload=True,
                phpv=8.3,
                webui=True,
                agent=True,
            )

        self.assertIsNone(result)
        generate_mock.assert_not_called()
        launch_mock.assert_called_once()
        config = launch_mock.call_args.args[0]
        self.assertEqual(config.waf_regex, "/flag/i")
        self.assertEqual(config.payload_context, "php_code")
        self.assertEqual(config.flagfile, "/etc/passwd")
        self.assertTrue(config.read_env)
        self.assertTrue(config.reflect_shell)
        self.assertEqual(config.ip, "10.10.10.10")
        self.assertEqual(config.port, 9090)
        self.assertTrue(config.phpinfo)
        self.assertTrue(config.upload)
        self.assertEqual(config.log_level, "DEBUG")
        self.assertTrue(config.total_payload)
        self.assertEqual(config.phpv, 8.3)
        self.assertFalse(config.auto)
        self.assertTrue(config.webui)
        self.assertTrue(config.agent)

    def test_auto_requires_webui(self):
        with self.assertRaises(RuntimeError) as ctx:
            purewaf(auto=True, webui=False)

        self.assertIn("auto=True can only be used together with webui=True or agent=True", str(ctx.exception))

    def test_agent_auto_missing_env_or_pure_returns_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("PureWaf.PureWaf.Path.cwd", return_value=Path(tmp)):
                result = purewaf(auto=True, agent=True, webui=False)

        self.assertEqual(result, ".env/pure Not FOUND")

    def test_webui_missing_flask_shows_install_hint(self):
        err = ModuleNotFoundError("No module named 'flask'")
        err.name = "flask"

        with patch("PureWaf.PureWaf.importlib.import_module", side_effect=err):
            with self.assertRaises(RuntimeError) as ctx:
                purewaf(webui=True)

        self.assertIn('pip install "flask>=3.1,<4"', str(ctx.exception))

    def test_webui_python_version_below_39_is_rejected(self):
        with (
            patch("PureWaf.PureWaf.sys.version_info", (3, 8, 18)),
            patch("PureWaf.PureWaf.importlib.import_module") as import_mock,
        ):
            with self.assertRaises(RuntimeError) as ctx:
                purewaf(webui=True)

        self.assertIn("Web UI requires Python 3.9+", str(ctx.exception))
        self.assertIn("current Python is 3.8.18", str(ctx.exception))
        import_mock.assert_not_called()

    @unittest.skipIf(create_app is None, "Flask webui module not available")
    def test_webui_events_endpoint_replays_completed_result_after_reconnect(self):
        app = create_app(PureWafConfig(webui=True))
        client = app.test_client()
        fake_result = PureWafExecutionResult(
            shortest_root="root-ok",
            shortest_flag="flag-ok",
            root_passed_payloads=["root-ok"],
            flag_passed_payloads=["flag-ok"],
            tips_text="TIPS: demo",
            log_text="[+] done",
        )

        with patch("PureWaf.webui._execute_purewaf", return_value=fake_result):
            run_response = client.post("/api/run", json={})
            self.assertEqual(run_response.status_code, 200)
            job_id = run_response.get_json()["job_id"]

            first_stream = client.get(f"/api/events/{job_id}")
            self.assertEqual(first_stream.status_code, 200)
            first_body = first_stream.get_data(as_text=True)

            second_stream = client.get(f"/api/events/{job_id}")
            self.assertEqual(second_stream.status_code, 200)
        second_body = second_stream.get_data(as_text=True)

        self.assertIn('"kind": "result"', first_body)
        self.assertIn('"kind": "result"', second_body)

        first_payload = next(
            payload for payload in self._extract_sse_payloads(first_body) if payload["kind"] == "result"
        )
        second_payload = next(
            payload for payload in self._extract_sse_payloads(second_body) if payload["kind"] == "result"
        )

        self.assertEqual(first_payload["result"]["shortest_flag"], "flag-ok")
        self.assertEqual(second_payload["result"]["shortest_flag"], "flag-ok")

    @unittest.skipIf(_build_runtime_config is None, "Flask webui module not available")
    def test_build_runtime_config_auto_mode_uses_fixed_defaults(self):
        config = _build_runtime_config(
            {"mode": "auto", "auto_prompt": "<?php system($_GET['x']); ?>", "phpv": 8.3},
            PureWafConfig(
                waf_regex="/flag/i",
                read_env=True,
                reflect_shell=True,
                phpinfo=True,
                upload=True,
                log_level="DEBUG",
                total_payload=True,
                phpv=8.3,
                webui=True,
            ),
        )

        self.assertTrue(config.auto)
        self.assertTrue(config.webui)
        self.assertFalse(config.agent)
        self.assertEqual(config.flagfile, "/flag")
        self.assertEqual(config.phpv, 7.0)
        self.assertEqual(config.log_level, "INFO")
        self.assertFalse(config.read_env)
        self.assertFalse(config.reflect_shell)
        self.assertFalse(config.phpinfo)
        self.assertFalse(config.upload)
        self.assertFalse(config.total_payload)

    @unittest.skipIf(_build_runtime_config is None, "Flask webui module not available")
    def test_build_runtime_config_auto_mode_uses_payload_agent_toggle(self):
        config = _build_runtime_config(
            {"mode": "auto", "agent": True},
            PureWafConfig(webui=True, agent=False),
        )

        self.assertTrue(config.auto)
        self.assertTrue(config.agent)

    @unittest.skipIf(create_app is None, "Flask webui module not available")
    def test_webui_agent_upload_zip_returns_upload_id(self):
        app = create_app(PureWafConfig(webui=True, auto=True, agent=False))
        client = app.test_client()
        zip_bytes = io.BytesIO()
        with zipfile.ZipFile(zip_bytes, "w") as archive:
            archive.writestr("index.php", "<?php system($_GET['x']);")
        zip_bytes.seek(0)

        response = client.post(
            "/api/upload",
            data={"project_zip": (zip_bytes, "project.zip"), "agent": "true"},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("upload_id", payload)
        self.assertEqual(payload["php_file_count"], 1)
        self.assertEqual(payload["files"], ["index.php"])

    @unittest.skipIf(create_app is None, "Flask webui module not available")
    def test_webui_upload_disabled_when_agent_not_enabled(self):
        app = create_app(PureWafConfig(webui=True, auto=True, agent=False))
        client = app.test_client()

        response = client.post("/api/upload", data={}, content_type="multipart/form-data")

        self.assertEqual(response.status_code, 400)
        self.assertIn("agent disabled", response.get_data(as_text=True))

    @unittest.skipIf(create_app is None, "Flask webui module not available")
    def test_webui_upload_rejects_zip_path_traversal(self):
        app = create_app(PureWafConfig(webui=True, auto=True, agent=False))
        client = app.test_client()
        zip_bytes = io.BytesIO()
        with zipfile.ZipFile(zip_bytes, "w") as archive:
            archive.writestr("../evil.php", "<?php system($_GET['x']);")
        zip_bytes.seek(0)

        response = client.post(
            "/api/upload",
            data={"project_zip": (zip_bytes, "project.zip"), "agent": "true"},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("path traversal", response.get_data(as_text=True))

    @unittest.skipIf(create_app is None, "Flask webui module not available")
    def test_webui_upload_rejects_zip_without_php_files(self):
        app = create_app(PureWafConfig(webui=True, auto=True, agent=False))
        client = app.test_client()
        zip_bytes = io.BytesIO()
        with zipfile.ZipFile(zip_bytes, "w") as archive:
            archive.writestr("README.txt", "no php")
        zip_bytes.seek(0)

        response = client.post(
            "/api/upload",
            data={"project_zip": (zip_bytes, "project.zip"), "agent": "true"},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("no PHP files", response.get_data(as_text=True))

    @unittest.skipIf(create_app is None, "Flask webui module not available")
    def test_webui_auto_mode_streams_analysis_before_result(self):
        app = create_app(PureWafConfig(webui=True))
        client = app.test_client()
        fake_result = PureWafExecutionResult(
            shortest_root="root-ok",
            shortest_flag="flag-ok",
            root_passed_payloads=["root-ok"],
            flag_passed_payloads=["flag-ok"],
            tips_text="",
            log_text="[+] Final Payload: flag-ok",
        )
        fake_analysis = AutoAnalysisResult(
            sink_kind="command_exec",
            payload_context="php_code",
            waf_regex="/[A-Za-z0-9_$]/",
            limit_length=30,
            read_env=True,
            upload=False,
            analysis_lines=[
                "[*] AUTO: analyzing PHP source",
                "[*] AUTO: detected sink => command_exec",
                "[*] AUTO: extracted waf_regex => /[A-Za-z0-9_$]/",
                "[*] AUTO: extracted limit_length => 30",
                "[*] AUTO: strategy probe => read_env=True",
                "[*] AUTO: selected strategy => read_env=True upload=False",
            ],
        )

        with (
            patch("PureWaf.webui.resolve_auto_parameters", return_value=fake_analysis) as resolve_mock,
            patch("PureWaf.webui._execute_purewaf", return_value=fake_result) as execute_mock,
        ):
            run_response = client.post(
                "/api/run",
                json={"mode": "auto", "auto_prompt": "<?php system($_GET['x']); ?>"},
            )
            self.assertEqual(run_response.status_code, 200)
            job_id = run_response.get_json()["job_id"]

            stream_response = client.get(f"/api/events/{job_id}")
            self.assertEqual(stream_response.status_code, 200)
            body = stream_response.get_data(as_text=True)

        payloads = self._extract_sse_payloads(body)
        resolve_mock.assert_called_once_with("<?php system($_GET['x']); ?>", use_llm=True)
        self.assertGreaterEqual(len(payloads), 2)
        self.assertEqual(payloads[0]["kind"], "lines")
        self.assertIn("[*] AUTO: analyzing PHP source", payloads[0]["lines"])
        self.assertEqual(payloads[-1]["kind"], "result")

        called_config = execute_mock.call_args.args[0]
        self.assertTrue(called_config.auto)
        self.assertTrue(called_config.read_env)
        self.assertFalse(called_config.upload)
        self.assertEqual(called_config.payload_context, "php_code")
        self.assertEqual(called_config.waf_regex, "/[A-Za-z0-9_$]/")
        self.assertEqual(called_config.limit_length, 30)

    @unittest.skipIf(create_app is None, "Flask webui module not available")
    def test_webui_agent_auto_uses_uploaded_project_bundle(self):
        app = create_app(PureWafConfig(webui=True, auto=True, agent=False))
        client = app.test_client()
        zip_bytes = io.BytesIO()
        with zipfile.ZipFile(zip_bytes, "w") as archive:
            archive.writestr("index.php", "<?php run_cmd($_GET['x']);")
        zip_bytes.seek(0)
        upload_response = client.post(
            "/api/upload",
            data={"project_zip": (zip_bytes, "project.zip"), "agent": "true"},
            content_type="multipart/form-data",
        )
        upload_id = upload_response.get_json()["upload_id"]
        fake_analysis = AutoAnalysisResult(
            sink_kind="command_exec",
            payload_context="shell_command",
            waf_regex="/cat|flag/i",
            analysis_lines=["[*] AUTO: analyzing uploaded bundle"],
        )
        fake_result = PureWafExecutionResult(
            shortest_root="root-ok",
            shortest_flag="flag-ok",
            root_passed_payloads=["root-ok"],
            flag_passed_payloads=["flag-ok"],
            tips_text="",
            log_text="[+] Final Payload: flag-ok",
        )
        fake_bundle = ProjectSourceBundle(
            root=Path("project"),
            files=[ProjectSourceFile("index.php", "<?php run_cmd($_GET['x']);", 24)],
            selected_paths=["index.php"],
            source="/* BEGIN_FILE: index.php */\n<?php run_cmd($_GET['x']);",
            analysis_lines=["[*] AGENT: selected PHP files => 1"],
        )

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text("API_KEY=x\nBASE_URL=http://x\nMODEL=x\n", encoding="utf-8")
            with (
                patch("PureWaf.webui.Path.cwd", return_value=Path(tmp)),
                patch("PureWaf.webui.PureWafProjectAgent.build_project_source", return_value=fake_bundle),
                patch("PureWaf.webui.PureWafProjectAgent.review_payloads") as review_mock,
                patch("PureWaf.webui.resolve_auto_parameters", return_value=fake_analysis) as resolve_mock,
                patch("PureWaf.webui._execute_purewaf", return_value=fake_result),
            ):
                review_mock.return_value = LlmPayloadReview()
                run_response = client.post(
                    "/api/run",
                    json={"mode": "auto", "upload_id": upload_id, "auto_prompt": "", "agent": True},
                )
                self.assertEqual(run_response.status_code, 200)
                job_id = run_response.get_json()["job_id"]
                body = client.get(f"/api/events/{job_id}").get_data(as_text=True)

        resolve_mock.assert_called_once_with(fake_bundle.source, use_llm=True)
        payloads = self._extract_sse_payloads(body)
        first_lines = payloads[0]["lines"]
        self.assertIn("[*] AGENT: selected PHP files => 1", first_lines)

    @unittest.skipIf(create_app is None, "Flask webui module not available")
    def test_webui_agent_auto_stops_when_sink_llm_fails(self):
        app = create_app(PureWafConfig(webui=True))
        client = app.test_client()
        fake_analysis = AutoAnalysisResult(
            analysis_lines=[
                "[*] AUTO: analyzing PHP source",
                "[*] AUTO: LLM request failed: timeout",
            ],
            llm_error="LLM request failed: timeout",
        )

        with (
            patch("PureWaf.webui.resolve_auto_parameters", return_value=fake_analysis),
            patch("PureWaf.webui._execute_purewaf") as execute_mock,
        ):
            run_response = client.post(
                "/api/run",
                json={"mode": "auto", "auto_prompt": "<?php system($_GET['x']); ?>", "agent": True},
            )
            self.assertEqual(run_response.status_code, 200)
            job_id = run_response.get_json()["job_id"]
            body = client.get(f"/api/events/{job_id}").get_data(as_text=True)

        execute_mock.assert_not_called()
        payloads = self._extract_sse_payloads(body)
        self.assertEqual(payloads[-1]["kind"], "error")
        self.assertIn("LLM调用失败", payloads[-1]["error"])
        self.assertIn("timeout", payloads[-1]["error"])
        self.assertTrue(all(item["kind"] != "result" for item in payloads))

    @unittest.skipIf(create_app is None, "Flask webui module not available")
    def test_webui_agent_auto_stops_when_project_selection_llm_fails(self):
        app = create_app(PureWafConfig(webui=True, auto=True, agent=False))
        client = app.test_client()
        zip_bytes = io.BytesIO()
        with zipfile.ZipFile(zip_bytes, "w") as archive:
            archive.writestr("index.php", "<?php system($_GET['x']);")
        zip_bytes.seek(0)
        upload_response = client.post(
            "/api/upload",
            data={"project_zip": (zip_bytes, "project.zip"), "agent": "true"},
            content_type="multipart/form-data",
        )
        upload_id = upload_response.get_json()["upload_id"]
        fake_bundle = ProjectSourceBundle(
            root=Path("project"),
            files=[ProjectSourceFile("index.php", "<?php system($_GET['x']);", 24)],
            selected_paths=["index.php"],
            source="/* BEGIN_FILE: index.php */\n<?php system($_GET['x']);",
            analysis_lines=["[*] AGENT: file selection fallback => LLM request failed: timeout"],
            selection_error="LLM request failed: timeout",
        )

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text("API_KEY=x\nBASE_URL=http://x\nMODEL=x\n", encoding="utf-8")
            with (
                patch("PureWaf.webui.Path.cwd", return_value=Path(tmp)),
                patch("PureWaf.webui.PureWafProjectAgent.build_project_source", return_value=fake_bundle),
                patch("PureWaf.webui.resolve_auto_parameters") as resolve_mock,
                patch("PureWaf.webui._execute_purewaf") as execute_mock,
            ):
                run_response = client.post(
                    "/api/run",
                    json={"mode": "auto", "upload_id": upload_id, "agent": True},
                )
                self.assertEqual(run_response.status_code, 200)
                job_id = run_response.get_json()["job_id"]
                body = client.get(f"/api/events/{job_id}").get_data(as_text=True)

        resolve_mock.assert_not_called()
        execute_mock.assert_not_called()
        payloads = self._extract_sse_payloads(body)
        self.assertEqual(payloads[-1]["kind"], "error")
        self.assertIn("LLM调用失败", payloads[-1]["error"])
        self.assertIn("timeout", payloads[-1]["error"])

    @unittest.skipIf(create_app is None, "Flask webui module not available")
    def test_webui_agent_auto_stops_when_payload_review_llm_fails(self):
        app = create_app(PureWafConfig(webui=True))
        client = app.test_client()
        fake_analysis = AutoAnalysisResult(
            sink_kind="command_exec",
            payload_context="shell_command",
            analysis_lines=["[*] AUTO: selected strategy => baseline"],
        )
        fake_result = PureWafExecutionResult(
            shortest_root="root-ok",
            shortest_flag="flag-ok",
            root_passed_payloads=["root-ok"],
            flag_passed_payloads=["flag-ok"],
            tips_text="",
            log_text="[+] Final Payload: flag-ok",
        )

        with (
            patch("PureWaf.webui.resolve_auto_parameters", return_value=fake_analysis),
            patch("PureWaf.webui._execute_purewaf", return_value=fake_result) as execute_mock,
            patch(
                "PureWaf.webui.PureWafProjectAgent.review_payloads",
                return_value=LlmPayloadReview(used=True, error="LLM request failed: timeout"),
            ),
        ):
            run_response = client.post(
                "/api/run",
                json={"mode": "auto", "auto_prompt": "<?php system($_GET['x']); ?>", "agent": True},
            )
            self.assertEqual(run_response.status_code, 200)
            job_id = run_response.get_json()["job_id"]
            body = client.get(f"/api/events/{job_id}").get_data(as_text=True)

        execute_mock.assert_called_once()
        payloads = self._extract_sse_payloads(body)
        self.assertEqual(payloads[-1]["kind"], "error")
        self.assertIn("LLM调用失败", payloads[-1]["error"])
        self.assertIn("timeout", payloads[-1]["error"])
        self.assertTrue(all(item["kind"] != "result" for item in payloads))

    @unittest.skipIf(create_app is None, "Flask webui module not available")
    def test_webui_rejects_invalid_mode(self):
        app = create_app(PureWafConfig(webui=True))
        client = app.test_client()

        response = client.post("/api/run", json={"mode": "wat"})

        self.assertEqual(response.status_code, 400)

    def test_execute_purewaf_returns_structured_result(self):
        config = PureWafConfig(
            waf_regex="/safe/",
            total_payload=True,
        )

        with (
            patch("PureWaf.PureWaf.bypass.generate_candidates", side_effect=[["root-seed"], ["flag-seed"]]),
            patch("PureWaf.PureWaf.bypass._build_targeted_candidates", side_effect=[["root-targeted"], ["flag-targeted"]]),
            patch("PureWaf.PureWaf.bypass.apply_encodings", side_effect=lambda payloads, _strategies: payloads),
            patch(
                "PureWaf.PureWaf.bypass.filter_payloads",
                side_effect=[["root-pass"], ["eval(next(getallheaders()));"]],
            ),
        ):
            result = _execute_purewaf(
                config,
                output_logger=None,
                show_progress=False,
                sleep_before_run=False,
            )

        self.assertEqual(result.shortest_root, "root-pass")
        self.assertEqual(result.shortest_flag, "eval(next(getallheaders()));")
        self.assertEqual(result.root_passed_payloads, ["root-pass"])
        self.assertEqual(result.flag_passed_payloads, ["eval(next(getallheaders()));"])
        self.assertIn("TIPS: User-Agent: 1=system('id');", result.tips_text)
        self.assertIn("[+] Final Payload: eval(next(getallheaders()));", result.log_text)

    def test_execute_purewaf_emits_stage_events_for_encoded_fallback(self):
        config = PureWafConfig()
        events = []

        with (
            patch("PureWaf.PureWaf.bypass.generate_candidates", side_effect=[["root-seed"], ["flag-seed"]]),
            patch("PureWaf.PureWaf.bypass._build_targeted_candidates", side_effect=[["root-targeted"], ["flag-targeted"]]),
            patch("PureWaf.PureWaf.bypass.apply_encodings", side_effect=lambda payloads, _strategies: payloads),
            patch(
                "PureWaf.PureWaf.bypass.filter_payloads",
                side_effect=[[], ["root-fallback"], [], ["flag-fallback"]],
            ),
        ):
            result = _execute_purewaf(
                config,
                output_logger=None,
                show_progress=False,
                sleep_before_run=False,
                event_callback=events.append,
            )

        self.assertEqual(result.shortest_flag, "flag-fallback")
        self.assertTrue(
            any(
                event.get("type") == "stage"
                and event.get("scope") == "root"
                and event.get("phase") == "encoded_fallback"
                for event in events
            )
        )
        self.assertTrue(
            any(
                event.get("type") == "stage"
                and event.get("scope") == "flag"
                and event.get("phase") == "encoded_fallback"
                for event in events
            )
        )

    def test_execute_purewaf_emits_candidate_and_filter_trace_events(self):
        config = PureWafConfig()
        events = []

        with (
            patch("PureWaf.PureWaf.bypass.generate_candidates", side_effect=[["root-seed"], ["flag-seed"]]),
            patch("PureWaf.PureWaf.bypass._build_targeted_candidates", side_effect=[["root-targeted"], ["flag-targeted"]]),
            patch("PureWaf.PureWaf.bypass.apply_encodings", side_effect=lambda payloads, _strategies: payloads),
        ):
            _execute_purewaf(
                config,
                output_logger=None,
                show_progress=False,
                sleep_before_run=False,
                event_callback=events.append,
            )

        self.assertTrue(
            any(
                event.get("type") == "candidate"
                and event.get("scope") == "root"
                and event.get("phase") == "base"
                and event.get("payload") == "root-seed"
                for event in events
            )
        )
        self.assertTrue(
            any(
                event.get("type") == "candidate"
                and event.get("scope") == "flag"
                and event.get("phase") == "targeted"
                and event.get("payload") == "flag-targeted"
                for event in events
            )
        )
        self.assertTrue(
            any(
                event.get("type") == "filter"
                and event.get("scope") == "root"
                and event.get("phase") == "targeted"
                and event.get("payload") == "root-targeted"
                and event.get("allowed") is True
                for event in events
            )
        )

    def test_filter_payloads_emits_progress_and_pass_events(self):
        events = []
        payloads = [f"payload-{idx}" for idx in range(205)]

        passed = bypass.filter_payloads(
            payloads,
            [],
            set(),
            None,
            999999,
            show_progress=False,
            verbose=True,
            progress_callback=events.append,
        )

        progress_events = [event for event in events if event["type"] == "progress"]
        pass_events = [event for event in events if event["type"] == "pass"]

        self.assertEqual(len(passed), 205)
        self.assertEqual([event["current"] for event in progress_events], [1, 100, 200, 205])
        self.assertEqual(len(pass_events), 205)
        self.assertEqual(pass_events[0]["payload"], "payload-0")
        self.assertEqual(pass_events[-1]["payload"], "payload-204")

    def test_filter_payloads_trace_callback_reports_blocked_payloads(self):
        events = []

        bypass.filter_payloads(
            ["safe", "flag", "toolong"],
            ["flag"],
            set(),
            None,
            4,
            show_progress=False,
            verbose=False,
            trace_callback=events.append,
        )

        self.assertEqual([event["type"] for event in events], ["filter", "filter", "filter"])
        self.assertTrue(events[0]["allowed"])
        self.assertFalse(events[1]["allowed"])
        self.assertEqual(events[1]["blocked"]["blocked_words"], ["flag"])
        self.assertFalse(events[2]["allowed"])
        self.assertEqual(events[2]["blocked"]["limit_length"], 4)


if __name__ == "__main__":
    unittest.main()
