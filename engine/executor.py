import subprocess
from typing import Dict, List
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen
import socket
import json


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


def run_git_extractor(base_url: str) -> Dict:
    """Non-destructive extractor for exposed .git directories.

    Attempts to read common git files like /.git/config and /.git/HEAD
    and returns any discovered data as 'paths' or 'credentials'.
    """
    try:
        results = {"paths": [], "credentials": [], "fetched": {}}
        candidates = ["/.git/config", "/.git/HEAD", "/.git/logs/HEAD"]
        for p in candidates:
            url = base_url.rstrip("/") + p
            try:
                req = Request(url, headers={"User-Agent": "security-pipeline/1.0"})
                with urlopen(req, timeout=5) as r:
                    body = (r.read() or b"").decode(errors="ignore")
                results["fetched"][p] = body[:4000]
                # crude parsing for user/email in config
                if "[remote" in body or "url =" in body:
                    results["paths"].append(p)
                if "user" in body or "email" in body or "password" in body:
                    results["credentials"].append(p)
            except Exception:
                continue

        success = bool(results["paths"] or results["credentials"])
        return {"success": success, "evidence": results}
    except Exception as e:
        return {"success": False, "evidence": str(e)}


def run_ssh_brute(host: str, port: int = 22, creds: List[Dict] = None) -> Dict:
    """SSH handler with optional, explicit opt-in brute/auth attempts.

    Behavior:
    - Always attempts a non-destructive banner grab.
    - Only attempts authentication if `enable_bruteforce` is True.
      In that case, it will try credentials provided in `creds` (list of {"user":..., "pass":...}).
    - Authentication attempts use `paramiko` if available; otherwise return informative error.

    Safety: This function will never perform blind dictionary attacks unless the caller
    explicitly enables `enable_bruteforce` and supplies credential candidates.
    """
    result = {"success": False, "evidence": {}}
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, int(port)))
        try:
            banner = s.recv(256).decode(errors="ignore")
        except Exception:
            banner = ""
        try:
            s.close()
        except Exception:
            pass

        result["evidence"]["banner"] = banner
        result["evidence"]["host"] = host
        result["evidence"]["port"] = port

        if not enable_bruteforce:
            result.update({"success": True, "note": "banner_only"})
            return result

        # Explicitly requested: try authentication for provided credentials only
        if not creds:
            return {"success": False, "evidence": "enable_bruteforce_requested_but_no_credentials_provided"}

        try:
            import paramiko
        except Exception:
            return {"success": False, "evidence": "paramiko_not_installed"}

        # Attempt provided credentials (do not perform any aggressive guessing)
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for cred in creds:
            user = cred.get("user") or cred.get("username")
            pwd = cred.get("pass") or cred.get("password")
            if not user or pwd is None:
                continue
            try:
                ssh_client.connect(hostname=host, port=int(port), username=user, password=pwd, timeout=5, banner_timeout=5, allow_agent=False, look_for_keys=False)
                # successful auth
                result.update({"success": True, "evidence": {"authenticated_user": user}})
                try:
                    ssh_client.close()
                except Exception:
                    pass
                return result
            except Exception as e:
                # record failure for this credential
                result.setdefault("attempts", []).append({"user": user, "error": str(e)})

        # No creds succeeded
        result.update({"success": False, "evidence": result.get("attempts", [])})
        return result

    except Exception as e:
        return {"success": False, "evidence": str(e)}


def run_config_reader(target_url: str) -> Dict:
    """Attempt a non-destructive GET to the provided target_url and scan for secrets.

    Returns matched indicators (e.g., 'root:', 'DB_PASSWORD', 'AWS').
    """
    try:
        req = Request(target_url, headers={"User-Agent": "security-pipeline/1.0"})
        with urlopen(req, timeout=8) as r:
            body = (r.read() or b"").decode(errors="ignore")

        matches = []
        indicators = ["root:", "DB_PASSWORD", "DATABASE_URL", "AWS_ACCESS_KEY_ID", "SECRET_KEY", "password="]
        for ind in indicators:
            if ind.lower() in body.lower():
                matches.append(ind)

        success = bool(matches)
        evidence = {"matched_indicators": matches, "snippet": body[:2000]}
        return {"success": success, "evidence": evidence}
    except Exception as e:
        return {"success": False, "evidence": str(e)}
