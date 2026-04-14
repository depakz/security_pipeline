import subprocess
import json
import shutil
import re
from pathlib import Path

OUTPUT_FILE = "output/gospider.json"


def _resolve_binary(name):
    in_path = shutil.which(name)
    if in_path:
        return in_path

    local = Path(__file__).resolve().parents[1] / "bin" / name
    if local.exists() and local.is_file():
        return str(local)

    return None


def run_gospider(target):
    try:
        gospider_bin = _resolve_binary("gospider")
        if gospider_bin is None:
            raise EnvironmentError("gospider not found in PATH")

        # normalize target (VERY IMPORTANT)
        if not target.startswith("http"):
            target = "https://" + target

        cmd = [
            gospider_bin,
            "-s", target,
            "-d", "1",
            "-c", "3",
            "-t", "2"
        ]

        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        if process.returncode != 0:
            raise RuntimeError(process.stderr.strip() or "gospider failed silently")

        # 🔥 CRITICAL FIX: combine both streams
        output = (process.stdout or "") + "\n" + (process.stderr or "")

        if not output.strip():
            raise ValueError("No output from gospider (blocked or non-crawlable target)")

        endpoints = set()

        for line in output.splitlines():
            match = re.search(r"https?://[^\s\]]+", line)
            if match:
                endpoints.add(match.group(0))

        data = {
            "target": target,
            "endpoints": list(endpoints)
        }

    except Exception as e:
        data = {
            "error": str(e),
            "debug_hint": "check WAF blocking, URL scheme, or crawl depth"
        }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=4)

    return OUTPUT_FILE