import json
import socket
import threading
import time
import uuid
import webbrowser
from dataclasses import asdict

from flask import Flask
from flask import Response
from flask import jsonify
from flask import render_template_string
from flask import request
from flask import stream_with_context

from .PureWaf import PureWafConfig
from .PureWaf import _execute_purewaf
from .PureWaf import version

STREAM_LINE_BATCH_SIZE = 40


PAGE_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PureWaf Web UI</title>
  <style>
    :root{--bg:#090909;--bg-2:#111111;--side:#171717;--line:#2a2a2a;--line-2:#383838;--text:#f2f2f2;--muted:#868686;--green:#39d353;--blue:#58a6ff;--white:#f8f8f8}
    *{box-sizing:border-box}
    html,body{margin:0;height:100%;overflow:hidden;background:#0b0b0b;color:var(--text);font-family:"Segoe UI","Noto Sans SC",sans-serif}
    body{background:
      radial-gradient(circle at 0% 0%,rgba(88,166,255,.08),transparent 24%),
      radial-gradient(circle at 100% 100%,rgba(57,211,83,.06),transparent 22%),
      linear-gradient(180deg,#0b0b0b 0%,#111 100%)}
    .app{height:100vh;display:grid;grid-template-columns:420px minmax(0,1fr);overflow:hidden}
    .side{min-height:0;display:flex;flex-direction:column;overflow:hidden;background:linear-gradient(180deg,#171717 0%,#141414 100%);border-right:1px solid var(--line)}
    .side-top{padding:20px 22px 14px;border-bottom:1px solid var(--line)}
    .brand{font:700 31px/1 "Bahnschrift","Segoe UI",sans-serif;letter-spacing:.06em}
    .brand small{font-size:13px;color:var(--muted);font-weight:500;margin-left:10px}
    .doc-link{display:inline-block;margin-left:8px;color:var(--blue);font-size:12px;text-decoration:none}
    .form{padding:14px 18px 16px;display:grid;gap:12px;overflow:hidden;min-height:0}
    .group{padding-bottom:8px;border-bottom:1px solid #202020}
    .group:last-of-type{border-bottom:0;padding-bottom:0}
    .group-title{margin:0 0 9px;font:700 12px/1 "Cascadia Code","JetBrains Mono",monospace;color:#7e7e7e;letter-spacing:.08em}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
    .row.three{grid-template-columns:1fr 1fr 1fr}
    .field{display:grid;gap:6px;margin-bottom:8px}
    label{font:600 11px/1 "Cascadia Code","JetBrains Mono",monospace;color:#9a9a9a;letter-spacing:.06em}
    input,textarea,select{width:100%;padding:10px 11px;border:1px solid var(--line-2);border-radius:6px;background:#e9eef8;color:#101010;outline:none;box-shadow:inset 0 1px 0 rgba(255,255,255,.2)}
    textarea{min-height:60px;resize:none}
    input:focus,textarea:focus,select:focus{border-color:#8cb4ff}
    input:disabled{opacity:.45;cursor:not-allowed}
    .checks{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px}
    .check{display:flex;align-items:center;gap:8px;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:#1a1a1a;color:#d4d4d4;font-size:13px}
    .check input{width:14px;height:14px;margin:0}
    .actions{display:flex;align-items:center;gap:10px}
    .btn{border:1px solid transparent;border-radius:6px;padding:11px 14px;font:700 13px/1 "Cascadia Code","JetBrains Mono",monospace;cursor:pointer}
    .btn.run{background:#ececec;color:#0b0b0b}
    .btn.reset{background:#1c1c1c;color:#d8d8d8;border-color:var(--line)}
    .btn:disabled{opacity:.5;cursor:wait}
    .status{display:flex;align-items:center;gap:10px;margin-top:2px;color:var(--muted);font:500 12px/1.4 "Cascadia Code","JetBrains Mono",monospace}
    .dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 0 6px rgba(57,211,83,.08)}
    .main{min-width:0;min-height:0;padding:18px;display:grid;grid-template-rows:auto minmax(0,1.95fr) minmax(220px,.95fr);gap:14px;overflow:hidden}
    .topbar{display:flex;align-items:center;justify-content:flex-end;gap:10px}
    .panel{min-height:0;display:flex;flex-direction:column;overflow:hidden;border:1px solid var(--line);border-radius:10px;background:rgba(0,0,0,.72)}
    .toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 14px;border-bottom:1px solid var(--line);background:#161616}
    .toolbar-left{display:flex;align-items:center;gap:12px;min-width:0}
    .toolbar-title{font:700 12px/1 "Cascadia Code","JetBrains Mono",monospace;color:#d6d6d6;letter-spacing:.08em;text-transform:uppercase}
    .toolbar-meta{font:500 12px/1.4 "Cascadia Code","JetBrains Mono",monospace;color:#6f6f6f}
    .toolbar-actions{display:flex;align-items:center;gap:8px}
    .pill{padding:5px 8px;border:1px solid var(--line);border-radius:999px;font:600 11px/1 "Cascadia Code","JetBrains Mono",monospace;color:#9b9b9b;background:#111}
    pre{margin:0;white-space:pre-wrap;word-break:break-word}
    .console-wrap{position:relative;flex:1 1 auto;min-height:0;background:
      linear-gradient(180deg,rgba(255,255,255,.03),transparent 18%),
      repeating-linear-gradient(180deg,rgba(255,255,255,.02) 0,rgba(255,255,255,.02) 1px,transparent 1px,transparent 22px),
      linear-gradient(180deg,#050505 0%,#0a0a0a 100%)}
    .console-wrap::after{content:"";position:absolute;inset:0;background:
      radial-gradient(circle at 65% 44%,rgba(88,166,255,.08),transparent 18%),
      radial-gradient(circle at 77% 72%,rgba(57,211,83,.06),transparent 16%);
      pointer-events:none}
    .console{position:relative;z-index:1;height:100%;min-height:0;overflow:auto;padding:16px 18px 18px;color:var(--blue);font:13px/1.6 "Cascadia Code","JetBrains Mono",monospace}
    .result-wrap{flex:1 1 auto;min-height:0;overflow:hidden;padding:14px;background:#0d0d0d}
    .result-console-wrap{position:relative;height:100%;min-height:0;overflow:hidden;border:1px solid #232323;border-radius:8px;background:
      linear-gradient(180deg,rgba(255,255,255,.03),transparent 18%),
      linear-gradient(180deg,#050505 0%,#0a0a0a 100%)}
    .result-console-wrap::after{content:"";position:absolute;inset:0;background:
      radial-gradient(circle at 22% 24%,rgba(57,211,83,.08),transparent 18%),
      radial-gradient(circle at 76% 68%,rgba(88,166,255,.06),transparent 20%);
      pointer-events:none}
    .result-console{position:relative;z-index:1;height:100%;min-height:0;overflow:auto;padding:14px 16px;color:var(--green);font:13px/1.6 "Cascadia Code","JetBrains Mono",monospace}
    @media (max-width:1200px){.app{grid-template-columns:390px minmax(0,1fr)}}
    @media (max-width:1100px){.app{grid-template-columns:1fr;grid-template-rows:auto minmax(0,1fr)}.side{overflow:auto}.form{overflow:visible}.main{grid-template-rows:auto minmax(0,1.7fr) minmax(220px,1fr)}}
    @media (max-width:760px){.main,.side-top,.form{padding-left:14px;padding-right:14px}.row,.row.three,.checks{grid-template-columns:1fr}.main{padding:14px;grid-template-rows:auto minmax(0,1.5fr) minmax(220px,1fr)}}
  </style>
</head>
<body>
  <div class="app">
    <aside class="side">
      <div class="side-top">
        <div class="brand">PUREWAF <small>v{{ version }}</small><a class="doc-link" href="https://github.com/PureStream108/PureWaf" target="_blank" rel="noreferrer">docs</a></div>
      </div>

      <form id="form" class="form">
        <section class="group">
          <h3 class="group-title">FILTER</h3>
          <div class="field"><label for="waf_words">waf_words</label><textarea id="waf_words"></textarea></div>
          <div class="field"><label for="waf_regex">waf_regex</label><textarea id="waf_regex"></textarea></div>
          <div class="row">
            <div class="field"><label for="waf_chars">waf_chars</label><input id="waf_chars" type="text"></div>
            <div class="field"><label for="limit_length">limit_length</label><input id="limit_length" type="number" step="1"></div>
          </div>
        </section>

        <section class="group">
          <h3 class="group-title">TARGET</h3>
          <div class="row three">
            <div class="field"><label for="flagfile">flagfile</label><input id="flagfile" type="text"></div>
            <div class="field"><label for="phpv">phpv</label><input id="phpv" type="number" step="0.1"></div>
            <div class="field"><label for="log_level">log_level</label><select id="log_level"><option>INFO</option><option>DEBUG</option><option>QUIET</option></select></div>
          </div>
        </section>

        <section class="group">
          <h3 class="group-title">FLAGS</h3>
          <div class="checks">
            <label class="check"><input id="read_env" type="checkbox">read_env</label>
            <label class="check"><input id="reflect_shell" type="checkbox">reflect_shell</label>
            <label class="check"><input id="phpinfo" type="checkbox">phpinfo</label>
            <label class="check"><input id="upload" type="checkbox">upload</label>
            <label class="check"><input id="total_payload" type="checkbox">total_payload</label>
          </div>
        </section>

        <section class="group">
          <h3 class="group-title">NETWORK</h3>
          <div class="row">
            <div class="field"><label for="ip">ip</label><input id="ip" type="text"></div>
            <div class="field"><label for="port">port</label><input id="port" type="number" step="1"></div>
          </div>
        </section>

        <div class="status"><span class="dot"></span><span id="status">idle</span></div>
      </form>
    </aside>

    <main class="main">
      <div class="topbar">
        <button id="reset" class="btn reset" type="button">RESET</button>
        <button id="run" class="btn run" type="submit" form="form">RUN</button>
      </div>
      <section class="panel">
        <div class="toolbar">
          <div class="toolbar-left">
            <span class="toolbar-title">payload stream</span>
            <span class="toolbar-meta">realtime process / local flask ui</span>
          </div>
          <div class="toolbar-actions">
            <span class="pill">local only</span>
            <span class="pill">sse log</span>
          </div>
        </div>
        <div class="console-wrap">
          <pre id="process" class="console">[*] idle</pre>
        </div>
      </section>

      <section class="panel">
        <div class="toolbar">
          <div class="toolbar-left">
            <span class="toolbar-title">result summary</span>
            <span class="toolbar-meta">terminal-style summary / tips / examples</span>
          </div>
          <div class="toolbar-actions">
            <span class="pill">summary</span>
            <span class="pill">scrollable</span>
          </div>
        </div>
        <div class="result-wrap">
          <div class="result-console-wrap">
            <pre id="result_output" class="result-console">[*] 点击 Run 后，这里会显示结果</pre>
          </div>
        </div>
      </section>
    </main>
  </div>

  <script>
    const INITIAL_CONFIG = {{ initial_config | tojson }};
    const ids = ["waf_words","waf_chars","waf_regex","limit_length","flagfile","read_env","reflect_shell","ip","port","phpinfo","upload","log_level","total_payload","phpv"];
    const processEl = document.getElementById("process");
    const resultEl = document.getElementById("result_output");
    const statusEl = document.getElementById("status");
    const runButton = document.getElementById("run");
    const resetButton = document.getElementById("reset");
    const processTextNode = document.createTextNode("");
    const PROCESS_PLAYBACK_INTERVAL_MS = 40;
    const PROCESS_PLAYBACK_LINES_PER_TICK = 12;
    let stream = null;
    let reconnectTimer = null;
    let terminalEventReceived = false;
    let processLineQueue = [];
    let processPlaybackTimer = null;
    let pendingResult = null;
    let pendingError = null;

    processEl.textContent = "";
    processEl.appendChild(processTextNode);

    function $(id){return document.getElementById(id)}
    function getProcessText(){
      return processTextNode.data || "";
    }
    function clearProcessPlayback(){
      if(processPlaybackTimer !== null){
        clearTimeout(processPlaybackTimer);
        processPlaybackTimer = null;
      }
    }
    function setProcessText(text){
      clearProcessPlayback();
      processLineQueue = [];
      pendingResult = null;
      pendingError = null;
      processTextNode.data = text;
      processEl.scrollTop = 0;
    }
    function appendProcessChunk(lines){
      if(!lines.length) return;
      const chunk = lines.join("\\n");
      const current = getProcessText();
      if(current === "[*] Running"){
        processTextNode.appendData(`\\n${chunk}`);
      }else if(current === "[*] 还没有运行任务。" || current === "[*] idle" || !current){
        processTextNode.data = chunk;
      }else{
        processTextNode.appendData(`\\n${chunk}`);
      }
      processEl.scrollTop = processEl.scrollHeight;
    }
    function finalizePendingOutcome(){
      if(processLineQueue.length) return;
      if(pendingError){
        setResultText(`[!] ${pendingError}`);
        statusEl.textContent = "运行失败";
        runButton.disabled = false;
        pendingError = null;
        return;
      }
      if(pendingResult){
        setResultText(buildResultSummary(pendingResult));
        statusEl.textContent = "运行完成";
        runButton.disabled = false;
        pendingResult = null;
      }
    }
    function drainProcessLines(forceAll=false){
      clearProcessPlayback();
      if(!processLineQueue.length) return;
      const count = forceAll ? processLineQueue.length : Math.min(processLineQueue.length, PROCESS_PLAYBACK_LINES_PER_TICK);
      const lines = processLineQueue.splice(0, count);
      appendProcessChunk(lines);
      if(processLineQueue.length){
        scheduleProcessPlayback();
      }else{
        finalizePendingOutcome();
      }
    }
    function scheduleProcessPlayback(){
      if(processPlaybackTimer !== null || !processLineQueue.length) return;
      processPlaybackTimer = setTimeout(() => drainProcessLines(false), PROCESS_PLAYBACK_INTERVAL_MS);
    }
    function setResultText(text){
      resultEl.textContent = text;
      resultEl.scrollTop = 0;
    }
    function clearReconnectTimer(){
      if(reconnectTimer){
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
    }
    function formatBlockedReasons(blocked){
      if(!blocked) return "";
      const parts = [];
      if(blocked.limit_length){
        parts.push(`len>${blocked.limit_length}`);
      }
      if(blocked.blocked_words && blocked.blocked_words.length){
        parts.push(`words:${blocked.blocked_words.join(",")}`);
      }
      if(blocked.blocked_chars && blocked.blocked_chars.length){
        parts.push(`chars:${blocked.blocked_chars.join("")}`);
      }
      if(blocked.regex_match){
        parts.push(`regex:${blocked.regex_match}`);
      }
      return parts.length ? ` // ${parts.join(" | ")}` : "";
    }
    function buildResultSummary(result){
      const resultText = (result.result_text || "").trim();
      if(resultText){
        return resultText;
      }
      const lines = [
        `[+] Shortest Root Payload : ${result.shortest_root || "N/A"}`,
        `[+] Shortest Flag Payload : ${result.shortest_flag || "N/A"}`
      ];
      const tipsText = (result.tips_text || "").trim();
      if(tipsText){
        lines.push("", tipsText);
      }
      return lines.join("\\n");
    }
    function setConfig(cfg){
      $("waf_words").value = cfg.waf_words || "";
      $("waf_chars").value = cfg.waf_chars || "";
      $("waf_regex").value = cfg.waf_regex || "";
      $("limit_length").value = cfg.limit_length ?? 999999;
      $("flagfile").value = cfg.flagfile || "/flag";
      $("read_env").checked = !!cfg.read_env;
      $("reflect_shell").checked = !!cfg.reflect_shell;
      $("ip").value = cfg.ip || "127.0.0.1";
      $("port").value = cfg.port ?? 8080;
      $("phpinfo").checked = !!cfg.phpinfo;
      $("upload").checked = !!cfg.upload;
      $("log_level").value = cfg.log_level || "INFO";
      $("total_payload").checked = !!cfg.total_payload;
      $("phpv").value = cfg.phpv ?? 7.0;
      syncReflect();
    }
    function syncReflect(){
      const on = $("reflect_shell").checked;
      $("ip").disabled = !on;
      $("port").disabled = !on;
    }
    function clearOutput(){
      terminalEventReceived = false;
      clearReconnectTimer();
      setProcessText("[*] Running");
      setResultText("[*] 等待结果摘要...");
    }
    function resetOutput(){
      terminalEventReceived = false;
      clearReconnectTimer();
      setProcessText("[*] 还没有运行任务。");
      setResultText("[*] 点击 Run 后，这里会显示终端式结果");
    }
    function appendLine(text){
      appendLines([text]);
    }
    function appendLines(lines){
      const normalized = (lines || []).filter(Boolean);
      if(!normalized.length) return;
      processLineQueue.push(...normalized);
      if(processLineQueue.length >= PROCESS_PLAYBACK_LINES_PER_TICK * 3){
        drainProcessLines(false);
        return;
      }
      scheduleProcessPlayback();
    }
    function buildPayload(){
      return {
        waf_words: $("waf_words").value,
        waf_chars: $("waf_chars").value,
        waf_regex: $("waf_regex").value,
        limit_length: Number($("limit_length").value || 999999),
        flagfile: $("flagfile").value,
        read_env: $("read_env").checked,
        reflect_shell: $("reflect_shell").checked,
        ip: $("ip").value,
        port: Number($("port").value || 8080),
        phpinfo: $("phpinfo").checked,
        upload: $("upload").checked,
        log_level: $("log_level").value,
        total_payload: $("total_payload").checked,
        phpv: Number($("phpv").value || 7.0)
      };
    }
    function closeStream(){
      clearReconnectTimer();
      if(stream){
        stream.close();
        stream = null;
      }
    }
    function formatEvent(item){
      if(item.kind !== "event") return "";
      const e = item.event || {};
      if(e.type === "log" || e.type === "stage") return e.message || "";
      if(e.type === "candidate") return `[${e.scope}:${e.phase}:GEN ${e.current}/${e.total}] ${e.payload}`;
      if(e.type === "filter"){
        const verdict = e.allowed ? "PASS" : "BLOCK";
        return `[${e.scope}:${e.phase}:${verdict} ${e.current}/${e.total}] ${e.payload}${e.allowed ? "" : formatBlockedReasons(e.blocked)}`;
      }
      if(e.type === "progress") return `[${e.scope}:${e.phase}] ${e.current}/${e.total} passed:${e.passed}`;
      if(e.type === "pass") return "";
      return "";
    }
    async function startRun(payload){
      const res = await fetch("/api/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
      if(!res.ok) throw new Error(await res.text() || "启动失败");
      return await res.json();
    }
    function attach(jobId){
      closeStream();
      terminalEventReceived = false;
      stream = new EventSource(`/api/events/${jobId}`);
      stream.onopen = () => {
        clearReconnectTimer();
        if(!terminalEventReceived){
          statusEl.textContent = "正在运行";
        }
      };
      stream.onmessage = (message) => {
        clearReconnectTimer();
        const payload = JSON.parse(message.data);
        if(payload.kind === "lines"){
          appendLines(payload.lines || []);
          return;
        }
        if(payload.kind === "result"){
          terminalEventReceived = true;
          pendingResult = payload.result;
          pendingError = null;
          appendLine("[+] 任务完成。");
          statusEl.textContent = "整理输出";
          closeStream();
          finalizePendingOutcome();
          return;
        }
        if(payload.kind === "error"){
          terminalEventReceived = true;
          pendingResult = null;
          pendingError = payload.error;
          appendLine(`[!] ${payload.error}`);
          statusEl.textContent = "整理输出";
          closeStream();
          finalizePendingOutcome();
          return;
        }
        appendLine(formatEvent(payload));
      };
      stream.onerror = () => {
        if(!stream || terminalEventReceived){
          closeStream();
          return;
        }
        statusEl.textContent = "连接重试中";
        clearReconnectTimer();
        reconnectTimer = setTimeout(() => {
          if(!stream || terminalEventReceived) return;
          appendLine("[!] 实时连接已断开。");
          statusEl.textContent = "连接中断";
          runButton.disabled = false;
          closeStream();
        }, 4000);
      };
    }

    $("reflect_shell").addEventListener("change", syncReflect);
    resetButton.addEventListener("click", () => {
      closeStream();
      setConfig(INITIAL_CONFIG);
      resetOutput();
      statusEl.textContent = "已恢复初始参数";
      runButton.disabled = false;
    });
    $("form").addEventListener("submit", async (event) => {
      event.preventDefault();
      runButton.disabled = true;
      statusEl.textContent = "正在运行";
      clearOutput();
      try{
        const data = await startRun(buildPayload());
        attach(data.job_id);
      }catch(err){
        appendLine(`[!] ${err.message}`);
        statusEl.textContent = "启动失败";
        runButton.disabled = false;
      }
    });

    setConfig(INITIAL_CONFIG);
    resetOutput();
  </script>
</body>
</html>
"""


class _JobStore:
    def __init__(self, retention_seconds=45):
        self.jobs = {}
        self.lock = threading.Lock()
        self.retention_seconds = retention_seconds

    def _cleanup_expired_locked(self):
        now = time.monotonic()
        expired_job_ids = [
            job_id
            for job_id, job in self.jobs.items()
            if job.get("done")
            and job.get("finished_at") is not None
            and now - job["finished_at"] > self.retention_seconds
        ]
        for job_id in expired_job_ids:
            self.jobs.pop(job_id, None)

    def create(self):
        job_id = uuid.uuid4().hex
        job = {
            "events": [],
            "done": False,
            "finished_at": None,
            "condition": threading.Condition(),
        }
        with self.lock:
            self._cleanup_expired_locked()
            self.jobs[job_id] = job
        return job_id, job

    def get(self, job_id):
        with self.lock:
            self._cleanup_expired_locked()
            return self.jobs.get(job_id)

    def pop(self, job_id):
        with self.lock:
            return self.jobs.pop(job_id, None)


def _coerce_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _coerce_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _coerce_float(value, default):
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _build_runtime_config(payload, base_config: PureWafConfig):
    return PureWafConfig(
        waf_words=str(payload.get("waf_words", base_config.waf_words) or ""),
        waf_chars=str(payload.get("waf_chars", base_config.waf_chars) or ""),
        waf_regex=str(payload.get("waf_regex", base_config.waf_regex) or ""),
        limit_length=_coerce_int(payload.get("limit_length"), base_config.limit_length),
        flagfile=str(payload.get("flagfile", base_config.flagfile) or "/flag"),
        read_env=_coerce_bool(payload.get("read_env", base_config.read_env)),
        reflect_shell=_coerce_bool(payload.get("reflect_shell", base_config.reflect_shell)),
        port=_coerce_int(payload.get("port"), base_config.port),
        ip=str(payload.get("ip", base_config.ip) or "127.0.0.1"),
        phpinfo=_coerce_bool(payload.get("phpinfo", base_config.phpinfo)),
        upload=_coerce_bool(payload.get("upload", base_config.upload)),
        log_level=str(payload.get("log_level", base_config.log_level) or "INFO").upper(),
        total_payload=_coerce_bool(payload.get("total_payload", base_config.total_payload)),
        phpv=_coerce_float(payload.get("phpv"), base_config.phpv),
        webui=True,
    )


def _serialize_result(result):
    return {
        "shortest_root": result.shortest_root,
        "shortest_flag": result.shortest_flag,
        "root_passed_payloads": result.root_passed_payloads,
        "flag_passed_payloads": result.flag_passed_payloads,
        "tips_text": result.tips_text,
        "log_text": result.log_text,
        "result_text": _build_result_text(result),
    }


def _build_result_text(result):
    log_text = (result.log_text or "").strip()
    if log_text:
        lines = log_text.splitlines()
        for idx, line in enumerate(lines):
            if line.startswith("[+] Shortest Root Payload :"):
                return "\n".join(lines[idx:]).strip()
        return log_text

    lines = [
        f"[+] Shortest Root Payload : {result.shortest_root or 'N/A'}",
        f"[+] Shortest Flag Payload : {result.shortest_flag or 'N/A'}",
    ]
    if result.tips_text:
        lines.extend(["", result.tips_text.strip()])
    return "\n".join(lines).strip()


def _should_forward_event(event, log_level):
    if log_level != "QUIET":
        return True
    return event.get("type") == "log" and event.get("level") in {"warning", "error"}


def _format_blocked_reason_text(blocked):
    if not blocked:
        return ""

    parts = []
    limit_length = blocked.get("limit_length")
    if limit_length:
        parts.append(f"len>{limit_length}")

    blocked_words = blocked.get("blocked_words") or []
    if blocked_words:
        parts.append("words:" + ",".join(blocked_words))

    blocked_chars = blocked.get("blocked_chars") or []
    if blocked_chars:
        parts.append("chars:" + "".join(blocked_chars))

    regex_match = blocked.get("regex_match")
    if regex_match:
        parts.append(f"regex:{regex_match}")

    if not parts:
        return ""
    return " // " + " | ".join(parts)


def _format_stream_line(event):
    event_type = event.get("type")
    if event_type in {"log", "stage"}:
        return event.get("message") or ""
    if event_type == "progress":
        return (
            f"[{event.get('scope')}:{event.get('phase')}] "
            f"{event.get('current')}/{event.get('total')} "
            f"passed:{event.get('passed')}"
        )
    if event_type == "candidate":
        return (
            f"[{event.get('scope')}:{event.get('phase')}:GEN "
            f"{event.get('current')}/{event.get('total')}] {event.get('payload')}"
        )
    if event_type == "filter":
        verdict = "PASS" if event.get("allowed") else "BLOCK"
        return (
            f"[{event.get('scope')}:{event.get('phase')}:{verdict} "
            f"{event.get('current')}/{event.get('total')}] {event.get('payload')}"
            f"{_format_blocked_reason_text(event.get('blocked'))}"
        )
    return ""


def _run_job(job, config: PureWafConfig):
    def publish(item):
        with job["condition"]:
            job["events"].append(item)
            job["condition"].notify_all()

    line_buffer = []

    def flush_lines():
        nonlocal line_buffer
        if not line_buffer:
            return
        publish({"kind": "lines", "lines": line_buffer})
        line_buffer = []

    def event_callback(event):
        if _should_forward_event(event, config.log_level):
            line = _format_stream_line(event)
            if line:
                line_buffer.append(line)
            if len(line_buffer) >= STREAM_LINE_BATCH_SIZE:
                flush_lines()

    try:
        result = _execute_purewaf(
            config,
            output_logger=None,
            show_progress=False,
            sleep_before_run=False,
            event_callback=event_callback,
        )
        flush_lines()
        publish({"kind": "result", "result": _serialize_result(result)})
    except Exception as exc:
        flush_lines()
        publish({"kind": "error", "error": str(exc)})
    finally:
        flush_lines()
        with job["condition"]:
            job["done"] = True
            job["finished_at"] = time.monotonic()
            job["condition"].notify_all()


def create_app(initial_config: PureWafConfig):
    app = Flask(__name__)
    job_store = _JobStore()

    @app.get("/")
    def index():
        public_config = asdict(initial_config)
        public_config.pop("webui", None)
        return render_template_string(PAGE_TEMPLATE, initial_config=public_config, version=version)

    @app.post("/api/run")
    def run_job():
        payload = request.get_json(silent=True) or {}
        config = _build_runtime_config(payload, initial_config)
        job_id, job = job_store.create()
        threading.Thread(target=_run_job, args=(job, config), daemon=True).start()
        return jsonify({"job_id": job_id})

    @app.get("/api/events/<job_id>")
    def stream_events(job_id):
        job = job_store.get(job_id)
        if job is None:
            return jsonify({"error": "job not found"}), 404

        @stream_with_context
        def generate():
            next_index = 0
            while True:
                with job["condition"]:
                    while next_index >= len(job["events"]) and not job["done"]:
                        notified = job["condition"].wait(timeout=15)
                        if not notified and next_index >= len(job["events"]) and not job["done"]:
                            break
                    pending_events = list(job["events"][next_index:])
                    is_done = job["done"]

                if pending_events:
                    for item in pending_events:
                        next_index += 1
                        yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
                    if is_done and next_index >= len(job["events"]):
                        break
                    continue

                if is_done:
                    break

                yield ": keepalive\n\n"

        return Response(
            generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    return app


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        return sock.getsockname()[1]


def launch_webui(initial_config: PureWafConfig):
    app = create_app(initial_config)
    port = _find_free_port()
    url = f"http://127.0.0.1:{port}"
    opener = threading.Timer(0.8, lambda: webbrowser.open(url))
    opener.daemon = True
    opener.start()
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False, threaded=True)
