import subprocess
import json
import shutil
import threading
import time

OUTPUT_FILE = "output/nuclei.json"


def _truncate(value, limit):
    if value is None:
        return ""
    s = str(value)
    if len(s) <= limit:
        return s
    return s[:limit] + "...(truncated)"


def run_nuclei(target, progress=None):
    try:
        if shutil.which("nuclei") is None:
            raise EnvironmentError("nuclei not installed or not in PATH")

        cmd = [
            "nuclei",
            "-u", target,
            "-jsonl",
            "-silent",
            "-no-interactsh",
            "-stats",
            "-si", "5"
        ]

        if isinstance(progress, dict):
            progress["detail"] = " | starting nuclei"

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        stderr_lines = []
        stderr_lock = threading.Lock()
        last_stats = {"line": ""}
        results_count = {"n": 0}

        def update_progress():
            if not isinstance(progress, dict):
                return
            parts = []
            parts.append(f"results: {results_count['n']}")
            if last_stats["line"]:
                parts.append(last_stats["line"])
            progress["detail"] = " | " + " | ".join(parts)

        def read_stderr():
            buffer = ""
            while True:
                chunk = process.stderr.read(1024) if process.stderr is not None else ""
                if not chunk:
                    break
                buffer += chunk
                buffer = buffer.replace("\r", "\n")
                lines = buffer.split("\n")
                buffer = lines.pop()  # remainder
                for line in lines:
                    s = (line or "").strip()
                    if not s:
                        continue
                    with stderr_lock:
                        stderr_lines.append(s)
                        if len(stderr_lines) > 500:
                            del stderr_lines[:-500]
                        last_stats["line"] = s[:80]
                    update_progress()
            leftover = buffer.strip()
            if leftover:
                with stderr_lock:
                    stderr_lines.append(leftover)
                    if len(stderr_lines) > 500:
                        del stderr_lines[:-500]
                    last_stats["line"] = leftover[:80]
                update_progress()

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

        # 🔥 classify execution state properly
        if returncode != 0:
            err_msg = (stderr_text or "").strip()
            if not err_msg:
                err_msg = "nuclei exited with non-zero status"
            raise RuntimeError(f"Nuclei failed (exit code {returncode}): {err_msg}")

        if "error" in (stderr_text or "").lower() or "failed" in (stderr_text or "").lower():
            # Some warnings contain the word failed; keep this conservative
            pass

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

        with open(OUTPUT_FILE, "w") as f:
            json.dump({
                "target": target,
                "findings": normalized,
                "raw_warnings": (stderr_text or "").strip().splitlines()
            }, f, indent=4)

        return OUTPUT_FILE

    except Exception as e:
        with open(OUTPUT_FILE, "w") as f:
            json.dump({
                "error": str(e),
                "hint": "check nuclei version, templates, or compatibility",
                "status": "execution_failed"
            }, f, indent=4)

        return OUTPUT_FILE