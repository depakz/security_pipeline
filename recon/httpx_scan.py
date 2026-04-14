import subprocess
import json
import shutil

OUTPUT_FILE = "output/httpx.json"


def check_httpx():
    if shutil.which("httpx") is None:
        raise EnvironmentError("httpx is not installed or not in PATH")


def run_httpx(target):
    try:
        check_httpx()

        cmd = [
            "httpx",
            "-u", target,
            "-json",
            "-silent",
            "-timeout", "10"
        ]

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
                "ip": r.get("ip", "")
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