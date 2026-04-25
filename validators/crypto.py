from __future__ import annotations

import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from engine.models import Evidence, ExecutionContext, ValidationResult
from utils.logger import logger


def _build_headers(state: Dict[str, Any]) -> Dict[str, str]:
    headers = {"User-Agent": "security-pipeline-validator/1.0"}
    cookie = state.get("cookie")
    if isinstance(cookie, str) and cookie.strip():
        headers["Cookie"] = cookie.strip()
    extra_headers = state.get("headers")
    if isinstance(extra_headers, dict):
        for key, value in extra_headers.items():
            if isinstance(key, str) and isinstance(value, str):
                headers[key] = value
    return headers


def _has_sensitive_headers(headers: Dict[str, str]) -> List[str]:
    sensitive_names = {"authorization", "proxy-authorization", "cookie", "x-api-key", "x-auth-token", "x-access-token"}
    return sorted({name for name in headers if name.lower() in sensitive_names})


def _probe_tls_versions(host: str, port: int, timeout: int) -> Dict[str, Any]:
    versions: List[Tuple[str, ssl.TLSVersion]] = [
        ("TLSv1", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]
    accepted: List[str] = []
    errors: Dict[str, str] = {}

    for label, version in versions:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version

            with socket.create_connection((host, port), timeout=timeout) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                    tls_socket.do_handshake()
                    accepted.append(tls_socket.version() or label)
        except Exception as exc:
            errors[label] = str(exc)

    return {"accepted_versions": sorted(set(accepted)), "errors": errors}


class CryptoValidator:
    """OWASP A02 validator for weak cryptography and plaintext sensitive transport."""

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

        parts = urlsplit(target_url)
        timeout = int(state.get("timeout", 8) or 8)
        headers = _build_headers(state)
        sensitive_headers = _has_sensitive_headers(headers)

        logger.info("CryptoValidator: probing %s", target_url)

        if parts.scheme == "https":
            port = parts.port or 443
            tls_probe = _probe_tls_versions(parts.hostname or parts.netloc, port, timeout)
            weak_versions = [version for version in tls_probe["accepted_versions"] if version in {"TLSv1", "TLSv1.1"}]

            if weak_versions:
                return ValidationResult(
                    success=True,
                    confidence=0.96,
                    severity="high",
                    vulnerability="a02-cryptographic-failures",
                    evidence=Evidence(
                        request={"target": target_url, "probe": "tls_version"},
                        response=tls_probe,
                        matched=",".join(weak_versions),
                        extra={"weak_versions": weak_versions},
                    ),
                    impact="The service accepts deprecated TLS versions that weaken transport confidentiality and integrity.",
                    remediation="Disable TLS 1.0 and TLS 1.1, enforce TLS 1.2+ or TLS 1.3, and restrict weak cipher suites.",
                )

            return ValidationResult(
                success=False,
                confidence=0.35 if tls_probe["accepted_versions"] else 0.1,
                severity="info",
                vulnerability="a02-cryptographic-failures",
                evidence=Evidence(
                    request={"target": target_url, "probe": "tls_version"},
                    response=tls_probe,
                    matched="",
                    extra={"sensitive_headers_present": sensitive_headers},
                ),
                impact="No weak TLS version was confirmed from the available probe.",
                remediation="Keep TLS restricted to modern versions and continue monitoring cipher policy drift.",
            )

        if sensitive_headers:
            logger.warning("CryptoValidator: sensitive headers detected over plaintext HTTP: %s", sensitive_headers)
            return ValidationResult(
                success=True,
                confidence=0.9,
                severity="high",
                vulnerability="a02-cryptographic-failures",
                evidence=Evidence(
                    request={"target": target_url, "headers": sensitive_headers},
                    response={"scheme": parts.scheme, "transport": "plaintext"},
                    matched=",".join(sensitive_headers),
                    extra={"url": target_url},
                ),
                impact="Sensitive headers are being transmitted without transport encryption, exposing credentials or session material.",
                remediation="Require HTTPS, redirect HTTP to HTTPS, and avoid sending credentials or session tokens over plaintext transport.",
            )

        return ValidationResult(
            success=False,
            confidence=0.0,
            severity="info",
            vulnerability="a02-cryptographic-failures",
            evidence=Evidence(
                request={"target": target_url},
                response={"sensitive_headers_present": sensitive_headers},
                matched="",
            ),
            impact="No weak cryptographic transport behavior was confirmed.",
            remediation="Prefer HTTPS everywhere and monitor TLS configuration continuously.",
        )