import json
import re
import shutil
import subprocess
from pathlib import Path

OUTPUT_FILE = "output/katana.json"


def _resolve_binary(name: str):
    in_path = shutil.which(name)
    if in_path:
        return in_path

    local = Path(__file__).resolve().parents[1] / "bin" / name
    if local.exists() and local.is_file():
        return str(local)

    return None


def run_katana(target: str, depth: int = 2, timeout_seconds: int = 300):
    """Run katana crawler and persist results to OUTPUT_FILE.

    Returns the OUTPUT_FILE path (even on error). Never raises.
    """

    try:
        katana_bin = _resolve_binary("katana")
        if katana_bin is None:
            raise EnvironmentError("katana not installed or not in PATH")

        candidates = []
        if isinstance(target, str) and (target.startswith("https://") or target.startswith("http://")):
            candidates = [target]
        else:
            candidates = [f"https://{target}", f"http://{target}"]

        last_error = "No output from katana (blocked or non-crawlable target)"
        used_target = ""
        urls = set()

        for candidate in candidates:
            used_target = candidate
            cmd = [
                katana_bin,
                "-u",
                candidate,
                "-d",
                str(int(depth)),
                "-silent",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=int(timeout_seconds),
            )

            if result.returncode != 0:
                last_error = (result.stderr or "").strip() or "katana exited with non-zero status"
                continue

            output = (result.stdout or "") + "\n" + (result.stderr or "")
            if not output.strip():
                last_error = "No output from katana (blocked or non-crawlable target)"
                continue

            for line in output.splitlines():
                s = (line or "").strip()
                if not s:
                    continue

                # Prefer URLs as-is when katana prints them cleanly.
                if s.startswith("http://") or s.startswith("https://"):
                    urls.add(s)
                    continue

                # Fallback: extract any URL from noisy lines.
                m = re.search(r"https?://[^\s\]]+", s)
                if m:
                    urls.add(m.group(0))

            if urls:
                break

        if not urls and last_error:
            # Still produce a valid output file so the aggregator can continue.
            data = {
                "target": used_target or str(target),
                "endpoints": [],
                "warning": last_error,
            }
        else:
            data = {
                "target": used_target or str(target),
                "endpoints": sorted(urls),
            }

    except subprocess.TimeoutExpired:
        data = {"error": "katana scan timed out", "status": "timeout"}

    except Exception as e:
        data = {
            "error": str(e),
            "hint": "install katana or place it in ./bin/katana",
            "status": "execution_failed",
        }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=4)

    return OUTPUT_FILE
