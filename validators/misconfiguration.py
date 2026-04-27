from __future__ import annotations

from typing import Any, Dict, Optional

import requests

from engine.models import Evidence, ExecutionContext, ValidationResult
from utils.logger import logger


MISCONFIG_PATTERNS = (
    "index of /",
    "directory listing",
    "trace / http",
    "debug=true",
    "stack trace",
    "exception in thread",
)


class SecurityMisconfigurationValidator:
    """OWASP A05 validator for insecure HTTP/server configuration patterns."""

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

        timeout = int(state.get("timeout", 8) or 8)
        headers = {"User-Agent": "security-pipeline-validator/1.0"}
        cookie = state.get("cookie")
        if isinstance(cookie, str) and cookie.strip():
            headers["Cookie"] = cookie.strip()

        logger.info("SecurityMisconfigurationValidator: probing %s", target_url)

        try:
            base = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=True)
            options = requests.options(target_url, headers=headers, timeout=timeout, allow_redirects=False)
            trace = requests.request("TRACE", target_url, headers=headers, timeout=timeout, allow_redirects=False)

            allow_header = (options.headers.get("Allow") or "").upper()
            base_text = (base.text or "")[:4000].lower()
            trace_text = (trace.text or "")[:1200].lower()

            findings = []
            if "TRACE" in allow_header:
                findings.append("trace_method_enabled")
            if trace.status_code < 400 and ("trace /" in trace_text or trace_text.strip()):
                findings.append("trace_echo_enabled")
            if any(pattern in base_text for pattern in MISCONFIG_PATTERNS):
                findings.append("debug_or_directory_listing_exposure")

            if findings:
                return ValidationResult(
                    success=True,
                    confidence=0.9,
                    severity="high",
                    vulnerability="a05-security-misconfiguration",
                    evidence=Evidence(
                        request={"target": target_url},
                        response={
                            "base_status": base.status_code,
                            "options_status": options.status_code,
                            "trace_status": trace.status_code,
                            "allow": allow_header,
                            "trace_snippet": (trace.text or "")[:300],
                        },
                        matched=",".join(findings),
                        extra={"findings": findings},
                    ),
                    impact="Insecure server/application configuration can expose sensitive behavior and increase attack surface.",
                    remediation="Disable TRACE in production, remove debug artifacts, and harden default server configuration baselines.",
                )

            return ValidationResult(
                success=False,
                confidence=0.2,
                severity="info",
                vulnerability="a05-security-misconfiguration",
                evidence=Evidence(
                    request={"target": target_url},
                    response={
                        "base_status": base.status_code,
                        "options_status": options.status_code,
                        "trace_status": trace.status_code,
                        "allow": allow_header,
                    },
                    matched="",
                ),
                impact="No strong misconfiguration signal was confirmed from the tested controls.",
                remediation="Maintain hardened defaults and regularly validate HTTP method policy and debug leakage.",
            )

        except requests.RequestException as exc:
            return ValidationResult(
                success=False,
                confidence=0.0,
                severity="info",
                vulnerability="a05-security-misconfiguration",
                evidence=Evidence(
                    request={"target": target_url},
                    response=str(exc),
                    matched="",
                ),
            )