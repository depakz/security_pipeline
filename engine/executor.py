import subprocess

def run_sqlmap(url):
    try:
        result = subprocess.run(
            ["sqlmap", "-u", url, "--batch", "--level=1"],
            capture_output=True,
            text=True,
            timeout=300
        )
        success = "is vulnerable" in result.stdout.lower()
        return {"success": success, "evidence": result.stdout[:500]}
    except Exception as e:
        return {"success": False, "evidence": str(e)}


def test_xss(url):
    try:
        payload = "<script>alert(1)</script>"
        test_url = f"{url}?q={payload}"

        result = subprocess.run(
            ["curl", "-s", test_url],
            capture_output=True,
            text=True
        )

        success = payload in result.stdout
        return {"success": success, "evidence": result.stdout[:300]}
    except Exception as e:
        return {"success": False, "evidence": str(e)}


def brute_force_login(url):
    return {"success": False, "evidence": "Not implemented"}
