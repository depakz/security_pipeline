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

        # Normalize target. If the caller doesn't specify a scheme, try HTTPS then HTTP.
        candidates = []
        if isinstance(target, str) and (target.startswith("https://") or target.startswith("http://")):
            candidates = [target]
        else:
            candidates = [f"https://{target}", f"http://{target}"]

        last_error = "No output from gospider (blocked or non-crawlable target)"
        fallback_data = None

        for candidate in candidates:
            cmd = [
                gospider_bin,
                "-s",
                candidate,
                "-d",
                "1",
                "-c",
                "3",
                "-t",
                "2",
            ]

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            if process.returncode != 0:
                last_error = process.stderr.strip() or "gospider failed silently"
                continue

            # Combine both streams (some gospider builds log to stderr).
            output = (process.stdout or "") + "\n" + (process.stderr or "")
            if not output.strip():
                last_error = "No output from gospider (blocked or non-crawlable target)"
                continue

            endpoints = set()
            for line in output.splitlines():
                match = re.search(r"https?://[^\s\]]+", line)
                if match:
                    endpoints.add(match.group(0))

            data = {
                "target": candidate,
                "endpoints": list(endpoints),
            }

            # Prefer the first scheme that yields actual endpoints.
            if endpoints:
                break

            # Keep a non-error fallback (matches previous behavior: empty endpoints is OK).
            fallback_data = data

        else:
            data = None

        if data is None:
            if fallback_data is not None:
                data = fallback_data
            else:
                raise ValueError(last_error)

    except Exception as e:
        data = {
            "error": str(e),
            "debug_hint": "check WAF blocking, URL scheme, or crawl depth",
        }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=4)

    return OUTPUT_FILE