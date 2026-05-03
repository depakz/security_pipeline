from __future__ import annotations

import socket
import ssl
import requests
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from brain.attack_variant_catalog import get_attack_variants
from engine.models import Evidence, ExecutionContext, ValidationResult
from utils.logger import logger


# Weak cipher suites and protocols
WEAK_CIPHERS = [
    "NULL", "EXPORT", "DES", "RC4", "MD5", "PSK", "eNULL",
    "aNULL", "ANON", "DH_DSS", "DH_RSA", "DHE_DSS", "DHE_RSA"
]

WEAK_HASH_FUNCTIONS = ["md5", "sha1", "md4", "ripemd", "sha0"]

A02_COVERAGE_MARKERS = [
    "weak_tls_versions",
    "plaintext_sensitive_transport",
    "missing_transport_encryption",
    "insecure_cipher_or_protocol_policy",
    "sensitive_data_exposure_in_transit",
]


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
    sensitive_names = {
        name.lower()
        for name in get_attack_variants(
            "A02",
            "sensitive_headers",
            ["Authorization", "Proxy-Authorization", "Cookie", "X-API-Key", "X-Auth-Token", "X-Access-Token"],
        )
    }
    return sorted({name for name in headers if name.lower() in sensitive_names})


def _check_missing_security_headers(response_headers: Dict[str, str]) -> List[str]:
    """Check for missing security headers."""
    missing = []
    important_headers = {
        "strict-transport-security": "HSTS - enforces HTTPS",
        "x-content-type-options": "prevents MIME sniffing",
        "x-frame-options": "prevents clickjacking",
        "x-xss-protection": "legacy XSS protection",
        "content-security-policy": "controls resource loading",
        "referrer-policy": "controls referrer information",
    }
    
    for header, description in important_headers.items():
        if header not in {k.lower() for k in response_headers.keys()}:
            missing.append(f"{header} ({description})")
    
    return missing


def _probe_tls_versions(host: str, port: int, timeout: int) -> Dict[str, Any]:
    versions: List[Tuple[str, ssl.TLSVersion]] = [
        ("TLSv1", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]
    accepted: List[str] = []
    errors: Dict[str, str] = {}
    cipher_info = {}

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
                    actual_version = tls_socket.version() or label
                    accepted.append(actual_version)
                    
                    # Try to get cipher info
                    try:
                        cipher = tls_socket.cipher()
                        if cipher:
                            cipher_info[actual_version] = cipher[0]
                    except:
                        pass
        except Exception as exc:
            errors[label] = str(exc)

    return {
        "accepted_versions": sorted(set(accepted)),
        "errors": errors,
        "cipher_info": cipher_info,
    }


class CryptoValidator:
    """OWASP A02 validator for weak cryptography, plaintext transport, and missing security headers."""

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

        # Test 1: Plaintext HTTP transmitting sensitive data
        if parts.scheme == "http" and sensitive_headers:
            return ValidationResult(
                success=True,
                confidence=0.95,
                severity="critical",
                vulnerability="a02-crypto-plaintext-transport",
                evidence=Evidence(
                    request={"url": target_url, "headers_with_sensitive_data": sensitive_headers},
                    response={"scheme": "http", "has_sensitive_headers": True},
                    matched="plaintext_transport_with_sensitive_data",
                    extra={"coverage_markers": A02_COVERAGE_MARKERS},
                ),
                impact="Sensitive authentication data (API keys, tokens, cookies) are transmitted over unencrypted HTTP. Network eavesdroppers can capture credentials.",
                remediation="Enforce HTTPS on all endpoints. Use HSTS headers. Never send sensitive data over HTTP.",
            )

        # Test 2: Check TLS/SSL versions if HTTPS
        if parts.scheme == "https":
            port = parts.port or 443
            host = parts.hostname or parts.netloc
            
            try:
                tls_probe = _probe_tls_versions(host, port, timeout)
                weak_versions = [version for version in tls_probe["accepted_versions"] if version in {"TLSv1", "TLSv1.1"}]

                if weak_versions:
                    return ValidationResult(
                        success=True,
                        confidence=0.9,
                        severity="high",
                        vulnerability="a02-crypto-weak-tls",
                        evidence=Evidence(
                            request={"target": target_url, "test": "tls_version_probe"},
                            response={
                                "accepted_versions": tls_probe["accepted_versions"],
                                "weak_versions": weak_versions,
                                "cipher_info": tls_probe.get("cipher_info", {}),
                            },
                            matched=",".join(weak_versions),
                            extra={"coverage_markers": A02_COVERAGE_MARKERS},
                        ),
                        impact="The server accepts outdated TLS versions (< 1.2) which are vulnerable to known attacks like POODLE and BEAST.",
                        remediation="Disable TLS 1.0 and 1.1. Use TLS 1.2 minimum (preferably 1.3). Update cipher suites to strong algorithms.",
                    )
                
                # Check for weak ciphers
                weak_ciphers_found = []
                for version, cipher in tls_probe.get("cipher_info", {}).items():
                    if any(weak in cipher.upper() for weak in WEAK_CIPHERS):
                        weak_ciphers_found.append(f"{version}: {cipher}")
                
                if weak_ciphers_found:
                    return ValidationResult(
                        success=True,
                        confidence=0.85,
                        severity="high",
                        vulnerability="a02-crypto-weak-cipher",
                        evidence=Evidence(
                            request={"target": target_url},
                            response={"weak_ciphers": weak_ciphers_found},
                            matched=",".join(weak_ciphers_found),
                            extra={"coverage_markers": A02_COVERAGE_MARKERS},
                        ),
                        impact="The server accepts weak cipher suites which may be exploitable.",
                        remediation="Configure only strong cipher suites. Use OWASP cipher recommendations.",
                    )
                    
            except Exception as e:
                logger.debug("TLS probe error: %s", e)

        # Test 3: Check for missing security headers
        try:
            resp = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=False)
            missing_headers = _check_missing_security_headers(dict(resp.headers))
            
            if len(missing_headers) >= 3:  # Multiple critical headers missing
                return ValidationResult(
                    success=True,
                    confidence=0.8,
                    severity="medium",
                    vulnerability="a02-crypto-missing-security-headers",
                    evidence=Evidence(
                        request={"url": target_url},
                        response={"missing_headers": missing_headers},
                        matched=", ".join(missing_headers[:3]),
                        extra={"coverage_markers": A02_COVERAGE_MARKERS},
                    ),
                    impact=f"Missing {len(missing_headers)} security headers: {', '.join(missing_headers[:3])}. This reduces defense against various attacks.",
                    remediation="Add HSTS, X-Content-Type-Options, X-Frame-Options, CSP, and other security headers to all responses.",
                )
            
        except Exception:
            pass

        return ValidationResult(
            success=False,
            confidence=0.0,
            severity="info",
            vulnerability="a02-crypto",
            evidence=Evidence(
                request={"target": target_url},
                response={},
                matched="",
                extra={"coverage_markers": A02_COVERAGE_MARKERS},
            ),
            impact="No cryptographic failures detected by current probes.",
            remediation="Implement TLS 1.2+, strong ciphers, HSTS, and security headers. Avoid plaintext transport of sensitive data.",
        )
