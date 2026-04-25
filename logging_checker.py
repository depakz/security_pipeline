#!/usr/bin/env python3

from __future__ import annotations

import argparse
import time
import uuid
from typing import Any, Dict, List

import requests


WAF_SIGNATURES = [
    "cloudflare",
    "modsecurity",
    "sucuri",
    "akamai",
    "imperva",
    "f5",
    "awswaf",
    "incapsula",
]


def _has_waf_signature(headers: Dict[str, Any]) -> List[str]:
    found: List[str] = []
    blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items()).lower()
    for sig in WAF_SIGNATURES:
        if sig in blob:
            found.append(sig)
    return sorted(set(found))


def run_logging_check(target: str, noisy_requests: int = 500, timeout: int = 5) -> Dict[str, Any]:
    session = requests.Session()
    nonce = uuid.uuid4().hex

    noisy_path = f"/.well-known/non-existent-security-probe-{nonce}"
    noisy_url = target.rstrip("/") + noisy_path

    codes: List[int] = []
    start = time.perf_counter()
    errors = 0

    for _ in range(noisy_requests):
        try:
            r = session.get(noisy_url, timeout=timeout, allow_redirects=False)
            codes.append(r.status_code)
        except requests.RequestException:
            errors += 1

    final_url = target.rstrip("/") + f"/.well-known/post-noise-check-{nonce}"
    final = session.get(final_url, timeout=timeout, allow_redirects=False)
    elapsed = time.perf_counter() - start

    waf_hits = _has_waf_signature(dict(final.headers))
    blocked = final.status_code in (403, 429)
    finding = (not blocked) and (len(waf_hits) == 0)

    return {
        "validator": "logging_checker",
        "owasp": "A09",
        "vulnerability": "security-logging-monitoring-failures",
        "validated": bool(finding),
        "confidence": 0.85 if finding else 0.35,
        "details": {
            "target": target,
            "noisy_requests_sent": noisy_requests,
            "request_errors": errors,
            "elapsed_seconds": round(elapsed, 3),
            "sample_status_codes": codes[:20],
            "final_status_code": final.status_code,
            "final_headers": dict(final.headers),
            "waf_signatures_detected": waf_hits,
            "expected_controls": ["429 Too Many Requests", "403 Forbidden", "WAF signature"],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Noisy A09 logging/rate-limit checker")
    parser.add_argument("target", help="Base target URL, e.g., http://localhost:8080")
    parser.add_argument("--count", type=int, default=500, help="Number of noisy requests to send")
    parser.add_argument("--timeout", type=int, default=5, help="Per-request timeout seconds")
    args = parser.parse_args()

    result = run_logging_check(args.target, noisy_requests=args.count, timeout=args.timeout)
    import json
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
