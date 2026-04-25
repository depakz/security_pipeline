from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import requests

from engine.models import Evidence, ExecutionContext, ValidationResult
from utils.logger import logger


def _looks_like_login_endpoint(url: str, state: Dict[str, Any]) -> bool:
    tokens = ("login", "signin", "sign-in", "auth", "session", "account")
    if any(token in url.lower() for token in tokens):
        return True
    for key in ("login_url", "login_endpoint", "auth_url"):
        value = state.get(key)
        if isinstance(value, str) and value:
            return True
        if value is True:
            return True
    return False


def _collect_set_cookies(response: requests.Response) -> List[str]:
    cookies: List[str] = []
    header_value = response.headers.get("Set-Cookie")
    if isinstance(header_value, str) and header_value:
        cookies.append(header_value)
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None:
        try:
            cookies.extend(raw_headers.get_all("Set-Cookie") or [])
        except Exception:
            pass
    return cookies


class AuthValidator:
    """OWASP A07 validator for missing login rate limiting and insecure remember-me cookies."""

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        url = state.get("login_url") or state.get("url") or state.get("target")
        return isinstance(url, str) and url.startswith(("http://", "https://"))

    def run(self, state: Dict[str, Any]):
        target_url = state.get("login_url") or state.get("url") or state.get("target")
        if not isinstance(target_url, str) or not target_url:
            return None

        headers = {"User-Agent": "security-pipeline-validator/1.0"}
        cookie = state.get("cookie")
        if isinstance(cookie, str) and cookie.strip():
            headers["Cookie"] = cookie.strip()

        timeout = int(state.get("timeout", 8) or 8)
        attempt_count = int(state.get("login_attempts", 4) or 4)
        login_like = _looks_like_login_endpoint(target_url, state)

        payload = state.get("login_payload")
        if not isinstance(payload, dict) or not payload:
            username = state.get("login_username") or "security-pipeline-test"
            password = state.get("login_password") or "invalid-password"
            payload = {"username": str(username), "password": str(password)}

        findings: List[str] = []
        attempt_details: List[Dict[str, Any]] = []
        session = requests.Session()

        if login_like:
            logger.info("AuthValidator: probing login rate limiting at %s", target_url)
            status_codes: List[int] = []

            for attempt_number in range(1, attempt_count + 1):
                start = time.perf_counter()
                try:
                    response = session.post(
                        target_url,
                        data=payload,
                        headers=headers,
                        timeout=timeout,
                        allow_redirects=False,
                    )
                    elapsed = time.perf_counter() - start
                    status_codes.append(response.status_code)
                    attempt_details.append({"attempt": attempt_number, "status": response.status_code, "elapsed_s": round(elapsed, 3)})
                except requests.RequestException as exc:
                    attempt_details.append({"attempt": attempt_number, "error": str(exc)})
                    continue

            if status_codes and not any(code in {429, 403} for code in status_codes):
                findings.append("missing_rate_limiting")

        try:
            get_response = session.get(target_url, headers=headers, timeout=timeout, allow_redirects=False)
            set_cookie_headers = _collect_set_cookies(get_response)
            insecure_cookie_headers: List[str] = []

            for header_value in set_cookie_headers:
                lowered = header_value.lower()
                if not any(token in lowered for token in ("remember", "remember_me", "persistent", "stay_signed_in")):
                    continue
                if "secure" not in lowered or "httponly" not in lowered:
                    insecure_cookie_headers.append(header_value)

            if insecure_cookie_headers:
                findings.append("remember_me_cookie_without_secure_httponly")

            evidence_extra = {
                "login_like": login_like,
                "attempts": attempt_details,
                "set_cookie_headers": set_cookie_headers,
            }

            if findings:
                logger.warning("AuthValidator: confirmed %s at %s", findings, target_url)
                return ValidationResult(
                    success=True,
                    confidence=0.93 if len(findings) > 1 else 0.88,
                    severity="high",
                    vulnerability="a07-identification-and-authentication-failures",
                    evidence=Evidence(
                        request={"target": target_url, "payload": payload},
                        response={"login_response_status": get_response.status_code, "findings": findings},
                        matched=",".join(findings),
                        extra=evidence_extra,
                    ),
                    impact="The login flow does not enforce expected authentication controls, enabling brute-force or session persistence abuse.",
                    remediation="Add account lockout or rate limiting for login attempts and set Secure/HttpOnly on remember-me cookies.",
                )

            return ValidationResult(
                success=False,
                confidence=0.15,
                severity="info",
                vulnerability="a07-identification-and-authentication-failures",
                evidence=Evidence(
                    request={"target": target_url, "payload": payload},
                    response={"login_response_status": get_response.status_code, "attempts": attempt_details},
                    matched="",
                    extra=evidence_extra,
                ),
                impact="No obvious authentication-control weakness was confirmed from the available probe.",
                remediation="Keep login controls, cookie flags, and lockout telemetry under regression test.",
            )

        except requests.RequestException as exc:
            return ValidationResult(
                success=False,
                confidence=0.0,
                severity="info",
                vulnerability="a07-identification-and-authentication-failures",
                evidence=Evidence(
                    request={"target": target_url, "payload": payload},
                    response=str(exc),
                    matched="",
                    extra={"login_like": login_like, "attempts": attempt_details},
                ),
            )