import base64
import glob
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

PHP_ENV_VAR = "PUREWAF_PHP"
SANDBOX_ROOT_ENV_VAR = "PUREWAF_SANDBOX_ROOT"
FLAG_MARKER = "PUREWAF_PHP_ORACLE_FLAG_OK"
DEFAULT_TIMEOUT = 5.0
MAX_OUTPUT_BYTES = 64 * 1024

_WINDOWS_GLOBS = (
    r"C:\php\php.exe",
    r"C:\php8\php.exe",
    r"C:\php*\php.exe",
    r"C:\xampp\php\php.exe",
    r"C:\wamp64\bin\php\php*\php.exe",
    r"C:\wamp\bin\php\php*\php.exe",
    r"C:\laragon\bin\php\php*\php.exe",
    r"C:\tools\php*\php.exe",
    r"C:\ProgramData\chocolatey\bin\php.exe",
    r"C:\ProgramData\chocolatey\lib\php\tools\php.exe",
)

_POSIX_GLOBS = (
    "/usr/bin/php",
    "/usr/local/bin/php",
    "/opt/homebrew/bin/php",
    "/opt/php*/bin/php",
)

_probe_cache: Dict[str, Tuple[str, Tuple[str, ...]]] = {}


@dataclass
class PhpRunResult:
    attempted: bool = False
    passed: bool = False
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    output_truncated: bool = False
    reason: str = ""
    command: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "attempted": self.attempted,
            "passed": self.passed,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "output_truncated": self.output_truncated,
            "reason": self.reason,
            "stdout": self.stdout[:MAX_OUTPUT_BYTES],
            "stderr": self.stderr[:MAX_OUTPUT_BYTES],
        }


@dataclass
class PhpVerification:
    payload: str = ""
    placement: str = ""
    passed: bool = False
    attempts: List[PhpRunResult] = field(default_factory=list)
    php_path: str = ""
    php_version: str = ""
    reason: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "payload": self.payload,
            "placement": self.placement,
            "passed": self.passed,
            "php_path": self.php_path,
            "php_version": self.php_version,
            "reason": self.reason,
            "attempts": [item.as_dict() for item in self.attempts],
        }


def _candidate_paths(explicit: Optional[str] = None) -> Iterable[str]:
    if explicit:
        path = Path(explicit).expanduser()
        if path.is_dir():
            for name in ("php.exe", "php"):
                candidate = path / name
                if candidate.exists():
                    yield str(candidate)
        elif path.exists():
            yield str(path)

    env_value = os.environ.get(PHP_ENV_VAR, "").strip()
    if env_value:
        path = Path(env_value).expanduser()
        if path.is_dir():
            for name in ("php.exe", "php"):
                candidate = path / name
                if candidate.exists():
                    yield str(candidate)
        elif path.exists():
            yield str(path)

    found = shutil.which("php")
    if found:
        yield found

    package_root = Path(__file__).resolve().parent
    bundled_roots = [
        package_root / "vendor" / "php",
        Path.cwd() / ".purewaf-php",
    ]
    for root in bundled_roots:
        if not root.is_dir():
            continue
        direct = [root / "php.exe", root / "php"]
        for candidate in direct:
            if candidate.exists():
                yield str(candidate)
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            for name in ("php.exe", "php"):
                candidate = child / name
                if candidate.exists():
                    yield str(candidate)

    patterns = _WINDOWS_GLOBS if sys.platform.startswith("win") else _POSIX_GLOBS
    for pattern in patterns:
        for match in sorted(glob.glob(pattern)):
            if os.path.isfile(match):
                yield match


def probe_php(php_bin: str) -> Tuple[str, Tuple[str, ...]]:
    key = str(php_bin)
    if key in _probe_cache:
        return _probe_cache[key]
    version = ""
    extensions: Tuple[str, ...] = ()
    try:
        proc = subprocess.run(
            [php_bin, "-n", "-r", "echo PHP_VERSION, PHP_EOL, implode(',', get_loaded_extensions());"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
        )
        text = proc.stdout.decode("utf-8", "replace").strip()
        if proc.returncode == 0 and text:
            parts = text.splitlines()
            version = parts[0].strip()
            if len(parts) > 1:
                extensions = tuple(item for item in parts[1].split(",") if item)
    except Exception:
        version = ""
    _probe_cache[key] = (version, extensions)
    return _probe_cache[key]


def find_php_binary(explicit: Optional[str] = None) -> Optional[str]:
    for candidate in _candidate_paths(explicit):
        version, _extensions = probe_php(candidate)
        if version:
            return candidate
    return None


def php_version(php_bin: Optional[str] = None) -> str:
    binary = php_bin or find_php_binary()
    if not binary:
        return ""
    return probe_php(binary)[0]


def _write_runtime_ini(
    php_bin: str,
    target_dir: Path,
    open_basedir_paths: Sequence[str] = (),
    profile: str = "trusted",
) -> Path:
    settings = _profile_settings(profile)
    php_dir = Path(php_bin).resolve().parent
    ext_dir = php_dir / "ext"
    sessions = target_dir / "sessions"
    sessions.mkdir(parents=True, exist_ok=True)
    lines = [
        "display_errors=0",
        "display_startup_errors=0",
        "log_errors=0",
        "error_reporting=0",
        f"allow_url_fopen={settings['allow_url_fopen']}",
        f"allow_url_include={settings['allow_url_include']}",
        "short_open_tag=1",
        "zend.assertions=1",
        "memory_limit=64M",
        "max_execution_time=5",
        "max_input_time=5",
        "post_max_size=1M",
        "upload_max_filesize=1M",
        "max_file_uploads=1",
        "expose_php=0",
        "phar.readonly=1",
        "ffi.enable=0",
        "opcache.enable=0",
        f'session.save_path="{sessions.as_posix()}"',
        f'sys_temp_dir="{target_dir.as_posix()}"',
        f'upload_tmp_dir="{target_dir.as_posix()}"',
        f'error_log="{(target_dir / "php-error.log").as_posix()}"',
    ]
    if settings["disable_functions"]:
        lines.append(f'disable_functions="{settings["disable_functions"]}"')
    if settings["disable_classes"]:
        lines.append(f'disable_classes="{settings["disable_classes"]}"')
    if ext_dir.is_dir():
        lines.append(f'extension_dir="{ext_dir.as_posix()}"')
        for name in ("mbstring", "iconv", "openssl", "phar", "zip"):
            if (ext_dir / f"php_{name}.dll").exists() or (ext_dir / f"{name}.so").exists():
                lines.append(f"extension={name}")
    allowed = [str(item) for item in open_basedir_paths if item]
    if allowed:
        lines.append('open_basedir="' + os.pathsep.join(dict.fromkeys(allowed)) + '"')
    ini_path = target_dir / "purewaf-php.ini"
    ini_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return ini_path


def _rewrite_flag_paths(source: str, flagfile: str, sandbox_flag: Path) -> str:
    configured = str(flagfile or "/flag")
    replacement = sandbox_flag.as_posix()
    if configured and configured != replacement:
        source = source.replace(configured, replacement)
    return source


def _safe_relpath(name: str) -> str:
    text = str(name or "").replace("\\", "/").strip()
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if not parts or text.startswith("/") or any(part == ".." for part in parts):
        raise ValueError(f"unsafe project path: {name}")
    if ":" in parts[0]:
        raise ValueError(f"unsafe project path: {name}")
    return "/".join(parts)


def _build_runner(request: Dict[str, object], entry: str = "source.php") -> str:
    safe_entry = _safe_relpath(entry)
    entry_literal = json.dumps(safe_entry)
    return (
        "<?php\n"
        "error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING);\n"
        "ini_set('display_errors', '0');\n"
        "$__spec = json_decode(file_get_contents(__DIR__ . '/request.json'), true);\n"
        "if (!is_array($__spec)) { $__spec = array(); }\n"
        "$__decode = function ($__arr) {\n"
        "    $__out = array();\n"
        "    if (!is_array($__arr)) { return $__out; }\n"
        "    foreach ($__arr as $__k => $__v) {\n"
        "        if (is_array($__v) && isset($__v['__b64'])) { $__v = base64_decode($__v['__b64']); }\n"
        "        if (substr($__k, -2) === '[]') { $__out[substr($__k, 0, -2)][] = $__v; }\n"
        "        else { $__out[$__k] = $__v; }\n"
        "    }\n"
        "    return $__out;\n"
        "};\n"
        "$_GET = $__decode(isset($__spec['get']) ? $__spec['get'] : array());\n"
        "$_POST = $__decode(isset($__spec['post']) ? $__spec['post'] : array());\n"
        "$_COOKIE = $__decode(isset($__spec['cookie']) ? $__spec['cookie'] : array());\n"
        "$_REQUEST = array_merge($_GET, $_POST, $_COOKIE);\n"
        "$_SERVER = array_merge($_SERVER, isset($__spec['server']) ? $__spec['server'] : array());\n"
        "$GLOBALS['__PUREWAF_HEADERS'] = isset($__spec['headers']) ? $__spec['headers'] : array();\n"
        "if (!function_exists('getallheaders')) { function getallheaders() { return $GLOBALS['__PUREWAF_HEADERS']; } }\n"
        "if (!function_exists('apache_request_headers')) { function apache_request_headers() { return $GLOBALS['__PUREWAF_HEADERS']; } }\n"
        "$__entry = __DIR__ . '/' . " + entry_literal + ";\n"
        "chdir(dirname($__entry));\n"
        "require $__entry;\n"
    )




SANDBOX_PROFILES = ("trusted", "strict")

STRICT_DISABLE_FUNCTIONS = ",".join(
    [
        "exec",
        "shell_exec",
        "system",
        "passthru",
        "popen",
        "proc_open",
        "pcntl_exec",
        "pcntl_fork",
        "putenv",
        "mail",
        "dl",
        "curl_exec",
        "curl_multi_exec",
        "fsockopen",
        "pfsockopen",
        "stream_socket_client",
        "socket_create",
        "socket_connect",
    ]
)
STRICT_DISABLE_CLASSES = "FFI,PDO,SoapClient,Imagick"


def _profile_settings(profile: str) -> Dict[str, str]:
    normalized = str(profile or "trusted").strip().lower()
    if normalized not in SANDBOX_PROFILES:
        normalized = "trusted"
    if normalized == "strict":
        return {
            "name": "strict",
            "allow_url_fopen": "0",
            "allow_url_include": "0",
            "disable_functions": STRICT_DISABLE_FUNCTIONS,
            "disable_classes": STRICT_DISABLE_CLASSES,
        }
    return {
        "name": "trusted",
        "allow_url_fopen": "1",
        "allow_url_include": "1",
        "disable_functions": "",
        "disable_classes": "",
    }


def _sandbox_env(home: Path) -> Dict[str, str]:
    keep = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL", "TZ")
    env = {key: os.environ[key] for key in keep if key in os.environ}
    home.mkdir(parents=True, exist_ok=True)
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "TEMP": str(home),
            "TMP": str(home),
            "TMPDIR": str(home),
            "PUREWAF_SANDBOX": "1",
        }
    )
    return env


def _kill_tree(proc: "subprocess.Popen") -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except Exception:
            pass
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _read_capped(pipe, limit: int, sink: List[bytes], state: Dict[str, bool]) -> None:
    total = 0
    try:
        while True:
            chunk = pipe.read(8192)
            if not chunk:
                break
            total += len(chunk)
            buffered = sum(len(item) for item in sink)
            if buffered < limit:
                sink.append(chunk[: limit - buffered])
        if total > limit:
            state["truncated"] = True
    except Exception:
        pass
    finally:
        try:
            pipe.close()
        except Exception:
            pass


def _run_command(
    command: List[str],
    cwd: Optional[str],
    stdin_data: bytes,
    timeout: float,
    env: Optional[Dict[str, str]],
    max_output: int,
    docker_name: str = "",
) -> Tuple[bytes, bytes, Optional[int], bool, bool]:
    creationflags = 0
    start_new_session = False
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        start_new_session = True

    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=env,
        creationflags=creationflags,
        start_new_session=start_new_session,
    )
    out: List[bytes] = []
    err: List[bytes] = []
    state = {"truncated": False}
    readers = [
        threading.Thread(target=_read_capped, args=(proc.stdout, max_output, out, state), daemon=True),
        threading.Thread(target=_read_capped, args=(proc.stderr, max_output, err, state), daemon=True),
    ]
    for reader in readers:
        reader.start()

    try:
        if stdin_data:
            proc.stdin.write(stdin_data)
    except Exception:
        pass
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if docker_name:
            try:
                subprocess.run(
                    ["docker", "kill", docker_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
            except Exception:
                pass
        _kill_tree(proc)
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

    for reader in readers:
        reader.join(timeout=2)
    return b"".join(out), b"".join(err), proc.returncode, timed_out, bool(state["truncated"])


def _docker_command(
    sandbox: Path,
    image: str,
    network: bool,
    name: str,
) -> List[str]:
    command = [
        "docker",
        "run",
        "--rm",
        "--init",
        "--name",
        name,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "256m",
        "--memory-swap",
        "256m",
        "--cpus",
        "0.5",
        "--ulimit",
        "nofile=64:64",
        "--stop-timeout",
        "1",
    ]
    if not network:
        command.extend(["--network", "none"])
    command.extend(["-v", f"{sandbox}:/work", "-w", "/work"])
    if os.name != "nt":
        try:
            command.extend(["--user", f"{os.getuid()}:{os.getgid()}"])
        except AttributeError:
            pass
    command.extend([image, "php", "-c", "/work/purewaf-php.ini", "/work/runner.php"])
    return command


DOCKER_IMAGE = "php:8.3-cli"
_docker_cache: Dict[str, bool] = {}


def docker_available(image: str = DOCKER_IMAGE) -> bool:
    if image in _docker_cache:
        return _docker_cache[image]
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
        ok = proc.returncode == 0
    except Exception:
        ok = False
    _docker_cache[image] = ok
    return ok


def _write_docker_ini(target_dir: Path, profile: str = "trusted") -> Path:
    settings = _profile_settings(profile)
    lines = [
        "display_errors=0",
        "display_startup_errors=0",
        "log_errors=0",
        "error_reporting=0",
        f"allow_url_fopen={settings['allow_url_fopen']}",
        f"allow_url_include={settings['allow_url_include']}",
        "short_open_tag=1",
        "zend.assertions=1",
        "memory_limit=64M",
        "max_execution_time=5",
        "max_input_time=5",
        "post_max_size=1M",
        "upload_max_filesize=1M",
        "max_file_uploads=1",
        "expose_php=0",
        "phar.readonly=1",
        "ffi.enable=0",
        "opcache.enable=0",
        'session.save_path="/work/sessions"',
        'sys_temp_dir="/work"',
        'upload_tmp_dir="/work"',
        'error_log="/work/php-error.log"',
    ]
    if settings["disable_functions"]:
        lines.append(f'disable_functions="{settings["disable_functions"]}"')
    if settings["disable_classes"]:
        lines.append(f'disable_classes="{settings["disable_classes"]}"')
    lines.append('open_basedir="/work"')
    ini_path = target_dir / "purewaf-php.ini"
    ini_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return ini_path


def sandbox_parent() -> Optional[str]:
    explicit = str(os.environ.get(SANDBOX_ROOT_ENV_VAR, "") or "").strip()
    if not explicit:
        return None
    path = Path(explicit)
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def _has_lone_surrogate(text: str) -> bool:
    return any(0xDC80 <= ord(ch) <= 0xDCFF for ch in str(text or ""))


def _serialize_request(request: Dict[str, object]) -> Dict[str, object]:
    serialized: Dict[str, object] = {}
    for bucket, values in (request or {}).items():
        if not isinstance(values, dict):
            continue
        clean: Dict[str, object] = {}
        for key, value in values.items():
            text = str(value)
            if _has_lone_surrogate(text):
                raw = text.encode("utf-8", "surrogateescape")
                clean[str(key)] = {"__b64": base64.b64encode(raw).decode("ascii")}
            else:
                clean[str(key)] = text
        serialized[str(bucket)] = clean
    return serialized


def run_source(
    source: str,
    request: Optional[Dict[str, Dict[str, str]]] = None,
    php_bin: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    flagfile: str = "/flag",
    flag_marker: str = FLAG_MARKER,
    stdin_data: str = "",
    rewrite_flag: bool = True,
    open_basedir: bool = True,
    flag_path: Optional[str] = None,
    runtime: str = "native",
    docker_image: str = DOCKER_IMAGE,
    docker_network: bool = False,
    profile: str = "trusted",
    project_files: Optional[Dict[str, str]] = None,
    entry: str = "source.php",
) -> PhpRunResult:
    request = request or {}
    use_docker = str(runtime or "native").strip().lower() == "docker"
    _settings = _profile_settings(profile)

    if use_docker:
        if not docker_available(docker_image):
            return PhpRunResult(
                attempted=False,
                reason=f"docker runtime unavailable (image {docker_image} not found)",
            )
        binary = ""
    else:
        binary = php_bin or find_php_binary()
        if not binary or not probe_php(binary)[0]:
            return PhpRunResult(attempted=False, reason="php CLI not found")

    with tempfile.TemporaryDirectory(
        prefix="purewaf-oracle-", dir=sandbox_parent()
    ) as tmp:
        sandbox = Path(tmp)
        home = sandbox / "home"
        home.mkdir(parents=True, exist_ok=True)
        (sandbox / "sessions").mkdir(parents=True, exist_ok=True)

        flag_basename = Path(str(flagfile or "/flag")).name or "flag"
        if use_docker:
            sandbox_flag = Path("/work") / flag_basename
            (sandbox / flag_basename).write_text(flag_marker, encoding="utf-8")
        elif flag_path:
            sandbox_flag = Path(flag_path)
            sandbox_flag.parent.mkdir(parents=True, exist_ok=True)
            sandbox_flag.write_text(flag_marker, encoding="utf-8")
        else:
            sandbox_flag = sandbox / flag_basename
            sandbox_flag.write_text(flag_marker, encoding="utf-8")

        if project_files:
            files = {
                _safe_relpath(name): content
                for name, content in project_files.items()
            }
            entry_rel = _safe_relpath(entry or next(iter(files)))
            if entry_rel not in files:
                raise ValueError(f"entry file not found in project: {entry_rel}")
        else:
            files = {"source.php": source}
            entry_rel = "source.php"

        for name, content in files.items():
            target = sandbox / Path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            rendered = (
                _rewrite_flag_paths(content, flagfile, sandbox_flag)
                if rewrite_flag
                else content
            )
            target.write_text(rendered, encoding="utf-8")
        (sandbox / "request.json").write_text(
            json.dumps(_serialize_request(request), ensure_ascii=False), encoding="utf-8"
        )
        (sandbox / "runner.php").write_text(
            _build_runner(request, entry_rel), encoding="utf-8"
        )

        docker_name = ""
        if use_docker:
            _write_docker_ini(sandbox, profile)
            docker_name = "purewaf-" + uuid.uuid4().hex[:12]
            command = _docker_command(sandbox, docker_image, docker_network, docker_name)
            run_cwd = None
            child_env = None
        else:
            allowed: List[str] = []
            if open_basedir:
                allowed = [
                    sandbox.as_posix(),
                    Path(binary).resolve().parent.as_posix(),
                    Path(sandbox_flag).resolve().parent.as_posix(),
                ]
            ini_path = _write_runtime_ini(binary, sandbox, allowed, profile=profile)
            command = [binary, "-c", str(ini_path), str(sandbox / "runner.php")]
            run_cwd = str(sandbox)
            child_env = _sandbox_env(home)

        try:
            out, err, exit_code, timed_out, truncated = _run_command(
                command,
                run_cwd,
                stdin_data.encode("utf-8", "replace"),
                timeout,
                child_env,
                MAX_OUTPUT_BYTES,
                docker_name=docker_name,
            )
        except Exception as exc:
            return PhpRunResult(
                attempted=False,
                reason=f"php execution failed to start: {exc}",
                command=command,
            )

        stdout = out.decode("utf-8", "replace")[:MAX_OUTPUT_BYTES]
        stderr = err.decode("utf-8", "replace")[:MAX_OUTPUT_BYTES]
        if timed_out:
            return PhpRunResult(
                attempted=True,
                timed_out=True,
                reason=f"php execution timed out after {timeout}s",
                stdout=stdout,
                stderr=stderr,
                command=command,
                output_truncated=truncated,
            )

        passed = flag_marker in stdout
        reason = (
            "sandbox flag marker observed in output"
            if passed
            else "sandbox flag marker not observed in output"
        )
        if truncated:
            reason += " (output truncated)"
        return PhpRunResult(
            attempted=True,
            passed=passed,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            reason=reason,
            command=command,
            output_truncated=truncated,
        )


def build_placements(
    input_source: str = "",
    input_key: str = "",
    payload: str = "",
    max_placements: int = 0,
) -> List[Tuple[str, Dict[str, Dict[str, str]]]]:
    source = (input_source or "").strip().upper()
    key = (input_key or "").strip() or "cmd"
    placements: List[Tuple[str, Dict[str, Dict[str, str]]]] = []

    def add(label: str, bucket: str, name: str):
        request = {bucket: {name: payload}}
        if bucket != "request":
            request["request"] = {name: payload}
        placements.append((label, request))

    if source in {"GET", "POST", "COOKIE", "REQUEST"}:
        bucket = source.lower()
        if bucket == "request":
            placements.append((f"REQUEST[{key}]", {"request": {key: payload}}))
        else:
            add(f"{source}[{key}]", bucket, key)
    else:
        for bucket in ("get", "post", "cookie"):
            add(f"{bucket.upper()}[{key}]", bucket, key)

    for fallback in ("cmd", "c", "x", "code", "f", "file", "input"):
        if fallback == key:
            continue
        for bucket in ("get", "post"):
            add(f"{bucket.upper()}[{fallback}]", bucket, fallback)
    if max_placements and max_placements > 0:
        return placements[:max_placements]
    return placements


def select_entry_file(files: Dict[str, str]) -> str:
    if not files:
        return ""
    normalized = {}
    for name, content in files.items():
        try:
            normalized[_safe_relpath(name)] = content
        except ValueError:
            continue
    if not normalized:
        return ""

    preferred = ("index.php", "app.php", "main.php", "router.php", "route.php")
    for wanted in preferred:
        for path in sorted(normalized):
            low = path.lower()
            if low == wanted or low.endswith("/" + wanted):
                return path

    def score(path: str) -> int:
        content = normalized[path]
        value = 0
        if re.search(r"\$_(GET|POST|REQUEST|COOKIE|FILES)", content):
            value += 3
        if re.search(
            r"\b(system|exec|shell_exec|passthru|eval|include|require|"
            r"file_get_contents|readfile|highlight_file|show_source)\s*\(",
            content,
        ):
            value += 2
        value -= path.count("/")
        return value

    return sorted(normalized, key=lambda item: (-score(item), item))[0]


def verify_payloads(
    source: str,
    payloads: Sequence[str],
    input_source: str = "",
    input_key: str = "",
    php_bin: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
    flagfile: str = "/flag",
    max_payloads: int = 8,
    stop_on_first_pass: bool = True,
    sandbox_flag: Optional[str] = None,
    max_placements: int = 0,
    runtime: str = "native",
    docker_image: str = DOCKER_IMAGE,
    payload_flag_path: Optional[str] = None,
    profile: str = "trusted",
    project_files: Optional[Dict[str, str]] = None,
    entry: str = "source.php",
) -> PhpVerification:
    use_docker = str(runtime or "native").strip().lower() == "docker"
    if use_docker:
        binary = ""
        verification = PhpVerification(php_path=f"docker:{docker_image}", php_version="")
        if not docker_available(docker_image):
            verification.reason = f"docker runtime unavailable (image {docker_image} not found)"
            return verification
    else:
        binary = php_bin or find_php_binary()
        verification = PhpVerification(
            php_path=binary or "",
            php_version=php_version(binary) if binary else "",
        )
        if not binary:
            verification.reason = "php CLI not found"
            return verification

    seen = set()
    candidates = []
    for payload in payloads:
        text = str(payload or "").strip()
        if not text or text == "N/A" or text in seen:
            continue
        seen.add(text)
        candidates.append(text)
        if len(candidates) >= max_payloads:
            break

    target_flag = payload_flag_path or sandbox_flag
    for payload in candidates:
        variants = [payload]
        if target_flag and flagfile and flagfile in payload:
            rewritten = payload.replace(flagfile, target_flag)
            if rewritten not in variants:
                variants.insert(0, rewritten)
        for variant in variants:
            for label, request in build_placements(
                input_source, input_key, variant, max_placements=max_placements
            ):
                result = run_source(
                    source,
                    request=request,
                    php_bin=binary,
                    timeout=timeout,
                    flagfile=flagfile,
                    flag_path=sandbox_flag,
                    runtime=runtime,
                    docker_image=docker_image,
                    profile=profile,
                    project_files=project_files,
                    entry=entry,
                )
                verification.attempts.append(result)
                if result.passed:
                    verification.payload = payload
                    verification.placement = label
                    verification.passed = True
                    verification.reason = f"verified by PHP oracle via {label}"
                    if stop_on_first_pass:
                        return verification
    verification.reason = verification.reason or "no candidate produced the sandbox flag marker"
    return verification


def environment_report(php_bin: Optional[str] = None) -> Dict[str, object]:
    binary = php_bin or find_php_binary()
    docker = docker_available()
    if not binary:
        return {
            "available": False,
            "php_path": "",
            "php_version": "",
            "extensions": [],
            "docker": docker,
            "docker_image": DOCKER_IMAGE if docker else "",
        }
    version, extensions = probe_php(binary)
    return {
        "available": bool(version),
        "php_path": binary,
        "php_version": version,
        "extensions": list(extensions),
        "docker": docker,
        "docker_image": DOCKER_IMAGE if docker else "",
    }


PORTABLE_PHP_INDEX = "https://windows.php.net/downloads/releases/releases.json"
PORTABLE_PHP_DEST = ".purewaf-php"


def install_portable_php(
    dest: str = PORTABLE_PHP_DEST,
    major: str = "8.3",
    quiet: bool = False,
) -> Optional[str]:
    import hashlib
    import json
    import urllib.request
    import zipfile

    if not sys.platform.startswith("win"):
        if not quiet:
            print("[!] portable PHP install is Windows-only; use apt/brew or docker on POSIX")
        return None

    try:
        with urllib.request.urlopen(PORTABLE_PHP_INDEX, timeout=30) as response:
            index = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        if not quiet:
            print(f"[!] could not read {PORTABLE_PHP_INDEX}: {exc}")
        return None

    entry = index.get(major)
    if not isinstance(entry, dict):
        if not quiet:
            print(f"[!] no portable build for PHP {major} in the release index")
        return None
    zip_info = None
    for key in ("nts-vs17-x64", "nts-vs16-x64", "ts-vs17-x64", "ts-vs16-x64"):
        if key in entry:
            zip_info = entry[key]["zip"]
            break
    if not zip_info:
        if not quiet:
            print(f"[!] no x64 zip for PHP {major}")
        return None

    target_root = Path(dest)
    target_root.mkdir(parents=True, exist_ok=True)
    version = str(entry.get("version") or major).split("-")[0]
    target_dir = target_root / ("php" + version.replace(".", ""))
    if (target_dir / "php.exe").exists():
        if not quiet:
            print(f"[*] portable PHP already present: {target_dir / 'php.exe'}")
        return str(target_dir / "php.exe")

    url = "https://windows.php.net/downloads/releases/" + zip_info["path"]
    archive_path = target_root / zip_info["path"]
    if not quiet:
        print(f"[*] downloading {url} ({zip_info.get('size')})")
    try:
        with urllib.request.urlopen(url, timeout=300) as response, archive_path.open("wb") as handle:
            while True:
                chunk = response.read(1024 * 256)
                if not chunk:
                    break
                handle.write(chunk)
    except Exception as exc:
        if not quiet:
            print(f"[!] download failed: {exc}")
        return None

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    expected = str(zip_info.get("sha256") or "")
    if expected and digest.lower() != expected.lower():
        if not quiet:
            print(f"[!] sha256 mismatch: got {digest}, expected {expected}")
        return None

    try:
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(target_dir)
    except Exception as exc:
        if not quiet:
            print(f"[!] extraction failed: {exc}")
        return None

    php_exe = target_dir / "php.exe"
    if not php_exe.exists():
        if not quiet:
            print(f"[!] extracted archive has no php.exe at {target_dir}")
        return None
    if not quiet:
        print(f"[+] portable PHP installed: {php_exe}")
        print(f"    set PUREWAF_PHP={php_exe}")
    return str(php_exe)


def _main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run a PureWaf payload against a local PHP challenge source.")
    parser.add_argument("--source", default="", help="path to the PHP challenge source")
    parser.add_argument("--payload", default="", help="payload value to inject")
    parser.add_argument("--get", default="", help="GET parameter name")
    parser.add_argument("--post", default="", help="POST parameter name")
    parser.add_argument("--cookie", default="", help="Cookie parameter name")
    parser.add_argument("--flagfile", default="/flag")
    parser.add_argument("--php", default="", help="explicit php binary path")
    parser.add_argument(
        "--runtime",
        default="native",
        choices=("native", "docker"),
        help="native host PHP or a Linux php:8.3-cli container",
    )
    parser.add_argument(
        "--profile",
        default="trusted",
        choices=SANDBOX_PROFILES,
        help="trusted keeps shell functions; strict disables shell/network/FFI",
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--env", action="store_true", help="print detected PHP environment and exit")
    parser.add_argument(
        "--install-portable",
        action="store_true",
        help="download an official portable Windows PHP into .purewaf-php and exit",
    )
    args = parser.parse_args(argv)

    if args.install_portable:
        path = install_portable_php()
        return 0 if path else 1

    if args.env:
        print(json.dumps(environment_report(args.php or None), ensure_ascii=False, indent=2))
        return 0

    if not args.source or not args.payload:
        parser.error("--source and --payload are required unless --env/--install-portable is used")

    if args.source == "-":
        source = sys.stdin.read()
    else:
        source = Path(args.source).read_text(encoding="utf-8", errors="replace")

    if args.get:
        input_source, input_key = "GET", args.get
    elif args.post:
        input_source, input_key = "POST", args.post
    elif args.cookie:
        input_source, input_key = "COOKIE", args.cookie
    else:
        input_source, input_key = "GET", "cmd"

    with tempfile.TemporaryDirectory(prefix="purewaf-cli-") as tmp:
        sandbox_flag = str(Path(tmp) / (Path(args.flagfile).name or "flag"))
        verification = verify_payloads(
            source,
            [args.payload],
            input_source=input_source,
            input_key=input_key,
            php_bin=args.php or None,
            timeout=args.timeout,
            flagfile=args.flagfile,
            max_payloads=1,
            max_placements=1,
            sandbox_flag=sandbox_flag,
            runtime=args.runtime,
            profile=args.profile,
        )
    print(json.dumps(verification.as_dict(), ensure_ascii=False, indent=2))
    return 0 if verification.passed else 1


if __name__ == "__main__":
    raise SystemExit(_main())