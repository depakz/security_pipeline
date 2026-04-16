import subprocess
from typing import Dict, List
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def run_sqlmap(url):
    try:
        result = subprocess.run(
            ["sqlmap", "-u", url, "--batch", "--level=1"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        success = "is vulnerable" in (result.stdout or "").lower()

        # Prefer the tail for signal (banner is at the top).
        stdout = (result.stdout or "").strip()
        tail = "\n".join(stdout.splitlines()[-40:])

        return {
            "success": bool(success),
            "evidence": {
                "exit_code": result.returncode,
                "output_tail": tail[:4000],
            },
        }
    except Exception as e:
        return {"success": False, "evidence": str(e)}


def _set_query_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)

    updated = []
    found = False
    for k, v in pairs:
        if k == param:
            updated.append((k, value))
            found = True
        else:
            updated.append((k, v))

    if not found:
        updated.append((param, value))

    query = urlencode(updated, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def test_xss(url):
    try:
        payload = "<script>alert(1)</script>"

        parts = urlsplit(url)
        param_names = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True) if k]
        if not param_names:
            param_names = ["q"]

        tested: List[Dict[str, str]] = []
        for param in sorted(set(param_names)):
            test_url = _set_query_param(url, param, payload)

            # -sS: silent but show errors, -L: follow redirects
            result = subprocess.run(
                ["curl", "-sS", "-L", "--max-time", "15", test_url],
                capture_output=True,
                text=True,
            )

            body = result.stdout or ""
            success = payload in body
            tested.append(
                {
                    "param": param,
                    "url": test_url,
                    "exit_code": str(result.returncode),
                    "matched": "true" if success else "false",
                }
            )

            if success:
                return {
                    "success": True,
                    "evidence": {
                        "matched_param": param,
                        "tested": tested,
                        "response_snippet": body[:1200],
                    },
                }

        # Not reflected in any tested param
        return {
            "success": False,
            "evidence": {
                "tested": tested,
            },
        }

    except Exception as e:
        return {"success": False, "evidence": str(e)}


def brute_force_login(url):
    return {"success": False, "evidence": "Not implemented"}
