import subprocess
import json
import shutil
import threading
import time
import tempfile
from pathlib import Path
from utils.logger import logger

OUTPUT_FILE = "output/nuclei.json"


def _stop_process(process):
    if process is None:
        return
    if process.poll() is not None:
        return

    try:
        process.terminate()
        process.wait(timeout=3)
    except Exception:
        try:
            process.kill()
            process.wait(timeout=2)
        except Exception:
            pass


def _resolve_binary(name):
    in_path = shutil.which(name)
    if in_path:
        return in_path

    local = Path(__file__).resolve().parents[1] / "bin" / name
    if local.exists() and local.is_file():
        return str(local)

    return None


def _truncate(value, limit):
    if value is None:
        return ""
    s = str(value)
    if len(s) <= limit:
        return s
    return s[:limit] + "...(truncated)"

def _normalize_nuclei_result(obj):
    info = obj.get("info", {}) or {}
    references = info.get("reference") or info.get("references") or []
    if isinstance(references, str):
        references = [references]
    if not isinstance(references, list):
        references = []

    return {
        "template": obj.get("template-id", ""),
        "name": info.get("name", ""),
        "severity": info.get("severity", ""),
        "description": info.get("description", ""),
        "matched_url": obj.get("matched-at", ""),
        "type": obj.get("type", ""),
        "tags": info.get("tags", []) or [],
        "references": references,
        "classification": info.get("classification", {}) or {},
        "matcher-name": obj.get("matcher-name", ""),
        "curl-command": obj.get("curl-command", ""),
        "extracted-results": obj.get("extracted-results", []) or [],
        "timestamp": obj.get("timestamp", ""),
        "host": obj.get("host", ""),
        "ip": obj.get("ip", ""),
        "port": obj.get("port", ""),
        "request": _truncate(obj.get("request", ""), 4000),
        "response": _truncate(obj.get("response", ""), 4000),
        "remediation": info.get("remediation", ""),
        "impact": info.get("impact", ""),
    }


def run_nuclei_multi(targets, progress=None, cookie=None):
    """
    Scan multiple targets with Nuclei and merge results.
    targets: list of URLs to scan
    """
    if not targets:
        with open(OUTPUT_FILE, "w") as f:
            json.dump({"findings": [], "exit_code": 0, "raw_warnings": ["No targets provided"]}, f, indent=4)
        return OUTPUT_FILE

    all_normalized = []
    all_warnings = []
    start_time = time.time()
    last_log = {"t": start_time}

    cleaned_targets = []
    for target in targets:
        if isinstance(target, str):
            candidate = target.strip()
            if candidate and candidate not in cleaned_targets:
                cleaned_targets.append(candidate)

    if not cleaned_targets:
        with open(OUTPUT_FILE, "w") as f:
            json.dump({"findings": [], "exit_code": 0, "raw_warnings": ["No valid targets provided"]}, f, indent=4)
        return OUTPUT_FILE

    nuclei_bin = _resolve_binary("nuclei")
    if nuclei_bin is None:
        with open(OUTPUT_FILE, "w") as f:
            json.dump({"findings": [], "exit_code": 1, "raw_warnings": ["nuclei binary not found"]}, f, indent=4)
        return OUTPUT_FILE

    if isinstance(progress, dict):
        progress["detail"] = f" | batching {len(cleaned_targets)} targets"

    temp_path = None
    process = None

    try:
        with tempfile.NamedTemporaryFile("w", delete=False, prefix="nuclei-targets-", suffix=".txt") as temp_file:
            temp_path = temp_file.name
            temp_file.write("\n".join(cleaned_targets))
            temp_file.write("\n")

        cmd = [
            nuclei_bin,
            "-l", temp_path,
            "-jsonl",
            "-silent",
            "-no-interactsh",
            "-c", "100",
            "-rl", "300",
            "-max-body-size", "5000",
        ]

        if cookie:
            cmd.extend(["-H", f"Cookie: {cookie}"])

        logger.info(f"nuclei multi: starting batched scan with {len(cleaned_targets)} targets")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            preexec_fn=lambda: __import__("resource").setrlimit(__import__("resource").RLIMIT_AS, (2 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024)) if hasattr(__import__("resource"), "RLIMIT_AS") else None,
        )

        stderr_lines = []
        stderr_lock = threading.Lock()
        results_count = {"n": 0}

        def read_stderr():
            while True:
                if process.stderr is None:
                    break

                line = process.stderr.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    time.sleep(0.05)
                    continue

                s = (line or "").strip()
                if not s or (s.startswith("{") and '"duration"' in s):
                    continue

                with stderr_lock:
                    stderr_lines.append(s)
                    if len(stderr_lines) > 200:
                        del stderr_lines[:-200]

        def update_progress():
            if not isinstance(progress, dict):
                return
            now = time.time()
            progress["detail"] = f" | targets={len(cleaned_targets)} results={results_count['n']} elapsed={int(now - start_time)}s"
            if now - last_log["t"] >= 5:
                logger.info(f"nuclei multi: targets={len(cleaned_targets)} results={results_count['n']} elapsed={int(now - start_time)}s")
                last_log["t"] = now

        stderr_thread = threading.Thread(target=read_stderr, daemon=True)
        stderr_thread.start()

        if process.stdout is not None:
            for line in process.stdout:
                line = (line or "").strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                all_normalized.append(_normalize_nuclei_result(obj))
                results_count["n"] += 1
                update_progress()

        returncode = process.wait()
        stderr_thread.join(timeout=2)

        with stderr_lock:
            stderr_text = "\n".join(stderr_lines)

        if returncode != 0:
            all_warnings.append(f"Nuclei exit {returncode}. {stderr_text[:500]}")

        logger.info(f"nuclei multi: completed batched scan targets={len(cleaned_targets)} elapsed={int(time.time() - start_time)}s findings={len(all_normalized)} return={returncode}")

    except Exception as e:
        logger.exception("nuclei multi: batched scan failed")
        all_warnings.append(str(e))
        if process is not None:
            _stop_process(process)

    finally:
        if temp_path:
            try:
                Path(temp_path).unlink(missing_ok=True)
            except Exception:
                pass

    with open(OUTPUT_FILE, "w") as f:
        json.dump({
            "findings": all_normalized,
            "exit_code": 0 if all_normalized else 1,
            "raw_warnings": all_warnings,
        }, f, indent=4)

    return OUTPUT_FILE


def run_nuclei(target, progress=None, cookie=None):
    process = None
    try:
        nuclei_bin = _resolve_binary("nuclei")
        if nuclei_bin is None:
            raise EnvironmentError("nuclei not installed or not in PATH")

        cmd = [
            nuclei_bin,
            "-u", target,
            "-jsonl",
            "-silent",
            "-no-interactsh",
            "-c", "50",
            "-rl", "100",
            "-max-body-size", "5000",
        ]

        if cookie:
            cmd.extend(["-H", f"Cookie: {cookie}"])

        if isinstance(progress, dict):
            progress["detail"] = " | starting nuclei"

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            preexec_fn=lambda: __import__("resource").setrlimit(__import__("resource").RLIMIT_AS, (2 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024)) if hasattr(__import__("resource"), "RLIMIT_AS") else None
        )

        stderr_lines = []
        stderr_lock = threading.Lock()
        last_stats = {"line": ""}
        results_count = {"n": 0}
        start_time = time.time()
        last_log = {"t": start_time}

        def update_progress():
            if not isinstance(progress, dict):
                return
            parts = []
            parts.append(f"results: {results_count['n']}")
            if last_stats["line"]:
                parts.append(last_stats["line"])
            progress["detail"] = " | " + " | ".join(parts)
            # also emit periodic logger messages so users can see activity
            try:
                now = time.time()
                if now - last_log["t"] >= 5:
                    logger.info(f"nuclei: target {str(target)[:80]} results={results_count['n']} elapsed={int(now-start_time)}s last={last_stats['line']}")
                    last_log["t"] = now
            except Exception:
                pass

        def read_stderr():
            while True:
                if process.stderr is None:
                    break

                line = process.stderr.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    time.sleep(0.05)
                    continue

                s = (line or "").strip()
                if not s:
                    continue

                # Ignore nuclei stats ticker lines if present.
                if s.startswith("{") and '"duration"' in s and '"percent"' in s:
                    continue

                with stderr_lock:
                    stderr_lines.append(s)
                    if len(stderr_lines) > 500:
                        del stderr_lines[:-500]
                    last_stats["line"] = s[:80]
                update_progress()
                # log stderr snippets occasionally
                try:
                    now = time.time()
                    if now - last_log["t"] >= 5:
                        logger.info(f"nuclei stderr: target {str(target)[:80]} snippet={s[:200]} results={results_count['n']} elapsed={int(now-start_time)}s")
                        last_log["t"] = now
                except Exception:
                    pass

        stderr_thread = threading.Thread(target=read_stderr, daemon=True)
        stderr_thread.start()

        results = []
        # Stream stdout (JSONL results)
        if process.stdout is not None:
            for line in process.stdout:
                line = (line or "").strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                results.append(obj)
                results_count["n"] += 1
                update_progress()

        returncode = process.wait()
        stderr_thread.join(timeout=2)

        stderr_text = ""
        with stderr_lock:
            stderr_text = "\n".join(stderr_lines)

        # Normalize results regardless of exit code
        # Nuclei often exits with non-zero on success or when no templates match
        normalized = []

        for r in results:
            info = r.get("info", {}) or {}
            references = info.get("reference") or info.get("references") or []
            if isinstance(references, str):
                references = [references]
            if not isinstance(references, list):
                references = []

            normalized.append(
                {
                    "template": r.get("template-id", ""),
                    "name": info.get("name", ""),
                    "severity": info.get("severity", ""),
                    "description": info.get("description", ""),
                    "matched_url": r.get("matched-at", ""),
                    "type": r.get("type", ""),
                    "tags": info.get("tags", []) or [],
                    "references": references,
                    "classification": info.get("classification", {}) or {},
                    "matcher-name": r.get("matcher-name", ""),
                    "curl-command": r.get("curl-command", ""),
                    "extracted-results": r.get("extracted-results", []) or [],
                    "timestamp": r.get("timestamp", ""),
                    "host": r.get("host", ""),
                    "ip": r.get("ip", ""),
                    "port": r.get("port", ""),
                    "request": _truncate(r.get("request", ""), 4000),
                    "response": _truncate(r.get("response", ""), 4000),
                    "remediation": info.get("remediation", ""),
                    "impact": info.get("impact", ""),
                }
            )

        logger.info(f"nuclei: completed target {str(target)[:80]} return={returncode} findings={len(normalized)} elapsed={int(time.time()-start_time)}s")

        warning_msgs = []
        if returncode == -9:
            warning_msgs.append("Process killed (exit -9) - likely out of memory. Partial results collected.")
        elif returncode == 2:
            warning_msgs.append("Nuclei exited with code 2 - templates not found or setup issue.")
        elif returncode != 0:
            warning_msgs.append(f"Nuclei exited with status {returncode}.")
        
        if returncode != 0:
            warning_msgs.append(f"Stderr: {stderr_text[:500]}")

        with open(OUTPUT_FILE, "w") as f:
            json.dump({
                "target": target,
                "findings": normalized,
                "exit_code": returncode,
                "raw_warnings": warning_msgs
            }, f, indent=4)

        return OUTPUT_FILE

    except KeyboardInterrupt:
        _stop_process(process)
        raise

    except Exception as e:
        _stop_process(process)
        with open(OUTPUT_FILE, "w") as f:
            json.dump({
                "error": str(e),
                "hint": "check nuclei version, templates, or compatibility",
                "status": "execution_failed"
            }, f, indent=4)

        return OUTPUT_FILE
