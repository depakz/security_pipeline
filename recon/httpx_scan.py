import subprocess
import json
import shutil
from pathlib import Path

OUTPUT_FILE = "output/httpx.json"


def _resolve_binary(name):
    in_path = shutil.which(name)
    if in_path:
        return in_path

    local = Path(__file__).resolve().parents[1] / "bin" / name
    if local.exists() and local.is_file():
        return str(local)

    return None


def check_httpx():
    if _resolve_binary("httpx") is None:
        raise EnvironmentError("httpx is not installed or not in PATH")


def run_httpx(target, cookie=None):
    try:
        check_httpx()
        httpx_bin = _resolve_binary("httpx")

        cmd = [
            httpx_bin,
            "-u", target,
            "-json",
            "-silent",
            "-timeout", "10",
            "-tech-detect",
            "-title",
            "-status-code",
            "-web-server",
            "-ip",
            "-tls-probe",
        ]

        if cookie:
            cmd.extend(["-H", f"Cookie: {cookie}"])

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        stdout, stderr = process.communicate(timeout=60)

        if process.returncode != 0:
            raise RuntimeError(stderr.strip())

        if not stdout.strip():
            raise ValueError("Empty HTTPX output")

        results = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
                results.append(obj)
            except json.JSONDecodeError:
                continue

        # Normalize output (VERY IMPORTANT for your aggregator)
        normalized = []

        for r in results:
            normalized.append({
                "url": r.get("url", ""),
                "status_code": r.get("status_code", ""),
                "title": r.get("title", ""),
                "webserver": r.get("webserver", ""),
                "tech": r.get("tech", []),
                "ip": r.get("ip", ""),
                "content_type": r.get("content_type", ""),
                "method": r.get("method", ""),
                "port": r.get("port", ""),
                "scheme": r.get("scheme", ""),
                "tls_grab": r.get("tls-grab", {}) or {},
                "tls": r.get("tls", {}) or {},
                "favicon": r.get("favicon", ""),
            })

        with open(OUTPUT_FILE, "w") as f:
            json.dump(normalized, f, indent=4)

        return OUTPUT_FILE

    except subprocess.TimeoutExpired:
        data = {"error": "httpx scan timed out"}

    except Exception as e:
        data = {"error": str(e)}

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=4)

    return OUTPUT_FILE