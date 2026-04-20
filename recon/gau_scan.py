import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

OUTPUT_FILE = "output/gau.json"


def _resolve_binary(name: str):
    in_path = shutil.which(name)
    if in_path:
        return in_path

    local = Path(__file__).resolve().parents[1] / "bin" / name
    if local.exists() and local.is_file():
        return str(local)

    return None


def _extract_domain(target: str) -> str:
    if not isinstance(target, str):
        return ""

    s = target.strip()
    if not s:
        return ""

    if "://" in s:
        try:
            parsed = urlparse(s)
            return (parsed.hostname or "").strip(".")
        except Exception:
            s = s.split("://", 1)[-1]

    # Strip path and port if present
    host = s.split("/", 1)[0]
    host = host.split(":", 1)[0]
    return host.strip(".")


def run_gau(target: str, timeout_seconds: int = 180):
    """Run gau (passive URL collection) and persist results to OUTPUT_FILE.

    Returns the OUTPUT_FILE path (even on error). Never raises.
    """

    try:
        gau_bin = _resolve_binary("gau")
        if gau_bin is None:
            raise EnvironmentError("gau not installed or not in PATH")

        domain = _extract_domain(target)
        if not domain:
            raise ValueError("Invalid target domain")

        cmd = [gau_bin, domain]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=int(timeout_seconds),
        )

        if result.returncode != 0:
            err = (result.stderr or "").strip() or "gau exited with non-zero status"
            raise RuntimeError(err)

        urls = set()
        for line in (result.stdout or "").splitlines():
            s = (line or "").strip()
            if s:
                urls.add(s)

        data = {
            "target": domain,
            "endpoints": sorted(urls),
        }

    except subprocess.TimeoutExpired:
        data = {"error": "gau scan timed out", "status": "timeout"}

    except Exception as e:
        data = {
            "error": str(e),
            "hint": "install gau or place it in ./bin/gau",
            "status": "execution_failed",
        }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=4)

    return OUTPUT_FILE
