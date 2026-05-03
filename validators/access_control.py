from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlsplit
import time

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
    "api",
    "config",
    "internal",
    "secret",
    "private",
)

A01_COVERAGE_MARKERS = [
    "route_access_control",
    "object_level_authorization_idor",
    "function_level_authorization",
    "privilege_escalation",
    "forced_browsing_sensitive_paths",
]

# IDOR test patterns - common integer/UUID patterns
IDOR_PATTERNS = [
    "/user/{id}",
    "/account/{id}",
    "/order/{id}",
    "/profile/{id}",
    "/document/{id}",
    "/report/{id}",
    "/settings/{id}",
]

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
                f"{base}/admin/users",
                f"{base}/dashboard",
                f"{base}/api/users",
                f"{base}/api/admin",
                f"{base}/users",
                f"{base}/account",
                f"{base}/profile",
                f"{base}/settings",
                f"{base}/config",
                f"{base}/internal",
            ]
        )

    return list(dict.fromkeys(out))


def _test_idor(base_url: str, headers: Dict[str, str], timeout: int) -> Optional[Dict[str, Any]]:
    """Test for Insecure Direct Object Reference (IDOR) vulnerabilities."""
    try:
        # Try common IDOR endpoints
        idor_endpoints = [
            f"{base_url}/user/1",
            f"{base_url}/user/123",
            f"{base_url}/account/1",
            f"{base_url}/account/999",
            f"{base_url}/order/1",
            f"{base_url}/profile/1",
            f"{base_url}/api/user/1",
            f"{base_url}/api/account/1",
        ]
        
        for endpoint in idor_endpoints:
            try:
                resp = requests.get(endpoint, headers=headers, timeout=timeout, allow_redirects=False)
                if resp.status_code == 200:
                    # Check if response contains user data
                    body_lower = resp.text.lower()
                    if any(marker in body_lower for marker in ["user", "email", "id", "name", "account"]):
                        return {
                            "url": endpoint,
                            "status": resp.status_code,
                            "snippet": resp.text[:500]
                        }
            except:
                pass
        return None
    except Exception:
        return None


def _test_privilege_escalation(base_url: str, headers: Dict[str, str], admin_headers: Dict[str, str], timeout: int) -> Optional[Dict[str, Any]]:
    """Test for privilege escalation vulnerabilities."""
    try:
        endpoints = [
            f"{base_url}/admin",
            f"{base_url}/admin/users",
            f"{base_url}/admin/settings",
            f"{base_url}/api/admin",
        ]
        
        for endpoint in endpoints:
            try:
                unauth_resp = requests.get(endpoint, headers=headers, timeout=timeout, allow_redirects=False)
                admin_resp = requests.get(endpoint, headers=admin_headers, timeout=timeout, allow_redirects=False)
                
                # If non-admin can see what admin sees, it's privilege escalation
                if unauth_resp.status_code == 200 and admin_resp.status_code == 200:
                    if len(unauth_resp.text) > 100:  # Has meaningful response
                        return {
                            "endpoint": endpoint,
                            "unauth_status": unauth_resp.status_code,
                            "admin_status": admin_resp.status_code
                        }
            except:
                pass
        return None
    except Exception:
        return None


class BrokenAccessControlValidator:
    """OWASP A01 validator for unauthenticated access to sensitive routes, IDOR, and privilege escalation."""

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

        # Extract base URL
        base_url = target_url.rstrip("/")
        parts = urlsplit(target_url)
        base_url = f"{parts.scheme}://{parts.netloc}"

        logger.info("BrokenAccessControlValidator: probing access control on %s", target_url)

        # Test 1: IDOR vulnerabilities
        idor_result = _test_idor(base_url, headers, timeout)
        if idor_result:
            return ValidationResult(
                success=True,
                confidence=0.85,
                severity="high",
                vulnerability="a01-broken-access-control-idor",
                evidence=Evidence(
                    request={"url": idor_result["url"], "method": "GET"},
                    response={"status": idor_result["status"], "snippet": idor_result["snippet"][:300]},
                    matched="direct_object_reference_accessible",
                    extra={"coverage_markers": A01_COVERAGE_MARKERS},
                ),
                impact="Attackers can access other users' data directly by manipulating object references (IDs, UUIDs, etc.)",
                remediation="Implement server-side authorization checks for every object access. Verify user has permission to access requested resource.",
            )

        # Test 2: Privilege escalation
        priv_esc = _test_privilege_escalation(base_url, headers, auth_headers, timeout)
        if priv_esc:
            return ValidationResult(
                success=True,
                confidence=0.8,
                severity="critical",
                vulnerability="a01-broken-access-control-privilege-escalation",
                evidence=Evidence(
                    request={"url": priv_esc["endpoint"], "comparison": "unauth_vs_auth"},
                    response=priv_esc,
                    matched="privilege_escalation_possible",
                    extra={"coverage_markers": A01_COVERAGE_MARKERS},
                ),
                impact="Non-privileged users can access administrative functions without proper role-based access control.",
                remediation="Implement strict role-based access control (RBAC). Verify user role/permissions on every privileged action.",
            )

        # Test 3: Unauthenticated access to sensitive paths
        candidates = _candidate_urls(state, target_url)
        sensitive_candidates = [u for u in candidates if any(marker in u.lower() for marker in SENSITIVE_PATH_MARKERS)]
        if not sensitive_candidates:
            sensitive_candidates = candidates[:5]

        for url in sensitive_candidates[:10]:
            try:
                unauth = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)

                body = (unauth.text or "")[:1200].lower()
                looks_sensitive = any(k in body for k in ("admin", "dashboard", "user", "settings", "profile", "config"))

                if unauth.status_code == 200 and looks_sensitive:
                    return ValidationResult(
                        success=True,
                        confidence=0.9,
                        severity="high",
                        vulnerability="a01-broken-access-control",
                        evidence=Evidence(
                            request={"url": url, "auth": "none"},
                            response={
                                "status": unauth.status_code,
                                "snippet": (unauth.text or "")[:400],
                            },
                            matched="unauthenticated_sensitive_resource_access",
                            extra={"coverage_markers": A01_COVERAGE_MARKERS},
                        ),
                        impact="Unauthorized users can access protected resources without authentication.",
                        remediation="Enforce authentication and server-side authorization checks on every sensitive route.",
                    )

            except requests.RequestException:
                continue

        return ValidationResult(
            success=False,
            confidence=0.1,
            severity="info",
            vulnerability="a01-broken-access-control",
            evidence=Evidence(
                request={"target": target_url, "tested": len(sensitive_candidates[:10])},
                response={},
                matched="",
                extra={"coverage_markers": A01_COVERAGE_MARKERS},
            ),
            impact="No obvious broken access control detected with current tests.",
            remediation="Conduct manual authorization testing and implement comprehensive RBAC/IDOR prevention.",
        )