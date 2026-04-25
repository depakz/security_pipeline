from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from engine.models import Evidence, ExecutionContext, ValidationResult
from utils.logger import logger


SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Strict-Transport-Security",
]


class LoggingValidator:
    """OWASP A09 passive audit for security headers as a hardening signal."""

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        url = state.get("url") or state.get("target")
        return isinstance(url, str) and url.startswith(("http://", "https://"))

    def run(self, state: Dict[str, Any]):
        target_url = state.get("url") or state.get("target")
        if not isinstance(target_url, str) or not target_url:
            return None

        headers = {"User-Agent": "security-pipeline-validator/1.0"}
        cookie = state.get("cookie")
        if isinstance(cookie, str) and cookie.strip():
            headers["Cookie"] = cookie.strip()

        timeout = int(state.get("timeout", 6) or 6)

        try:
            response = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=True)
            response_headers = dict(response.headers)
            present_headers = [header for header in SECURITY_HEADERS if header in response_headers]
            missing_headers = [header for header in SECURITY_HEADERS if header not in response_headers]

            logger.info(
                "LoggingValidator: headers present=%s missing=%s for %s",
                present_headers,
                missing_headers,
                target_url,
            )

            success = len(missing_headers) >= 1

            return ValidationResult(
                success=success,
                confidence=0.82 if success else 0.25,
                severity="info" if success else "low",
                vulnerability="a09-security-logging-monitoring-failures",
                evidence=Evidence(
                    request={"target": target_url},
                    response={"status": response.status_code, "present_headers": present_headers, "missing_headers": missing_headers},
                    matched=",".join(present_headers or missing_headers),
                    extra={"headers_checked": SECURITY_HEADERS},
                ),
                impact="Security headers provide a passive signal of application hardening and operational security maturity.",
                remediation="Add the standard defensive headers at the web server or application layer and track them in regression tests.",
            )

        except requests.RequestException as exc:
            return ValidationResult(
                success=False,
                confidence=0.0,
                severity="info",
                vulnerability="a09-security-logging-monitoring-failures",
                evidence=Evidence(
                    request={"target": target_url},
                    response=str(exc),
                    matched="",
                    extra={"headers_checked": SECURITY_HEADERS},
                ),
            )