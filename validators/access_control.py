from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlsplit

import requests

from engine.models import Evidence, ExecutionContext, ValidationResult
from utils.logger import logger


SENSITIVE_PATH_MARKERS = (
    "admin",
    "dashboard",
    "manage",
    "users",
    "account",
    "profile",
    "settings",
)


def _candidate_urls(state: Dict[str, Any], target_url: str) -> List[str]:
    endpoints = state.get("endpoints") or []
    out: List[str] = []

    if isinstance(endpoints, list):
        for ep in endpoints:
            if isinstance(ep, str) and ep.startswith(("http://", "https://")):
                out.append(ep)

    if not out:
        base = target_url.rstrip("/")
        out.extend(
            [
                f"{base}/admin",
                f"{base}/dashboard",
                f"{base}/users",
                f"{base}/account",
                f"{base}/profile",
                f"{base}/settings",
            ]
        )

    return list(dict.fromkeys(out))


class BrokenAccessControlValidator:
    """OWASP A01 validator for unauthenticated access to sensitive routes."""

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
        auth_headers = dict(headers)
        if isinstance(cookie, str) and cookie.strip():
            auth_headers["Cookie"] = cookie.strip()

        candidates = _candidate_urls(state, target_url)
        sensitive_candidates = [u for u in candidates if any(marker in u.lower() for marker in SENSITIVE_PATH_MARKERS)]
        if not sensitive_candidates:
            sensitive_candidates = candidates[:5]

        logger.info("BrokenAccessControlValidator: probing %s candidate paths", len(sensitive_candidates))

        for url in sensitive_candidates[:10]:
            try:
                unauth = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
                auth = requests.get(url, headers=auth_headers, timeout=timeout, allow_redirects=False)

                body = (unauth.text or "")[:1200].lower()
                looks_sensitive = any(k in body for k in ("admin", "dashboard", "user", "settings", "profile"))

                confirmed = (
                    unauth.status_code == 200
                    and (auth.status_code in (200, 302, 403) or "Cookie" in auth_headers)
                    and looks_sensitive
                )

                if confirmed:
                    return ValidationResult(
                        success=True,
                        confidence=0.9,
                        severity="high",
                        vulnerability="a01-broken-access-control",
                        evidence=Evidence(
                            request={"url": url, "mode": "unauth_vs_auth"},
                            response={
                                "unauth_status": unauth.status_code,
                                "auth_status": auth.status_code,
                                "unauth_snippet": (unauth.text or "")[:400],
                            },
                            matched="unauthenticated_sensitive_resource_access",
                            extra={"candidate_count": len(sensitive_candidates)},
                        ),
                        impact="Unauthorized users may access protected resources without proper authorization checks.",
                        remediation="Enforce server-side authorization on every sensitive route and object-level resource access.",
                    )

            except requests.RequestException:
                continue

        return ValidationResult(
            success=False,
            confidence=0.15,
            severity="info",
            vulnerability="a01-broken-access-control",
            evidence=Evidence(
                request={"target": target_url, "tested_urls": sensitive_candidates[:10]},
                response={"tested": len(sensitive_candidates[:10])},
                matched="",
            ),
            impact="No clear unauthorized access pattern was confirmed with current probes.",
            remediation="Keep route/object authorization tests in CI and validate authorization for every privileged endpoint.",
        )