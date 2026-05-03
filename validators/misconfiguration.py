from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urljoin

import requests

from engine.models import Evidence, ExecutionContext, ValidationResult
from utils.logger import logger


A05_COVERAGE_MARKERS = [
    "dangerous_http_methods_enabled",
    "debug_or_stacktrace_exposure",
    "directory_listing_or_index_exposure",
    "insecure_default_configuration",
    "excessive_technology_disclosure",
]


MISCONFIG_PATTERNS = (
    "index of /",
    "directory listing",
    "trace / http",
    "debug=true",
    "stack trace",
    "exception in thread",
    "internal server error",
    "fatal error",
    "error 500",
)

# Common default pages
DEFAULT_ADMIN_PATHS = [
    "/admin",
    "/wp-admin",
    "/administrator",
    "/phpmyadmin",
    "/cpanel",
    "/admin.php",
]

# Common unpatched applications
COMMON_APPS = [
    ("/wp-includes/", "WordPress"),
    ("/joomla/", "Joomla"),
    ("/drupal/", "Drupal"),
    ("/phpmyadmin/", "phpMyAdmin"),
    ("/.env", "Environment file"),
    ("/config.php", "Config file"),
    ("/.git/", "Git directory"),
    ("/.svn/", "SVN directory"),
]


class SecurityMisconfigurationValidator:
    """OWASP A05 validator for insecure HTTP/server configuration, default credentials, and information disclosure."""

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

        base_url = target_url.rstrip("/")
        findings = []

        # Test 1: Dangerous HTTP methods
        try:
            options = requests.options(target_url, headers=headers, timeout=timeout, allow_redirects=False)
            allow_header = (options.headers.get("Allow") or "").upper()
            
            if "TRACE" in allow_header:
                return ValidationResult(
                    success=True,
                    confidence=0.9,
                    severity="high",
                    vulnerability="a05-security-misconfiguration-trace",
                    evidence=Evidence(
                        request={"target": target_url, "method": "OPTIONS"},
                        response={"allow_header": allow_header},
                        matched="TRACE_method_enabled",
                        extra={"coverage_markers": A05_COVERAGE_MARKERS},
                    ),
                    impact="TRACE method enabled allows attackers to view request headers including cookies and auth tokens.",
                    remediation="Disable TRACE, CONNECT, and other unnecessary HTTP methods.",
                )
            
            dangerous_methods = [m for m in ["PUT", "DELETE", "PATCH"] if m in allow_header]
            if dangerous_methods:
                findings.append(f"dangerous_methods: {','.join(dangerous_methods)}")
        except:
            pass

        # Test 2: Debug/stack trace exposure
        try:
            base = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=True)
            base_text = (base.text or "")[:4000].lower()
            
            if any(pattern in base_text for pattern in MISCONFIG_PATTERNS):
                return ValidationResult(
                    success=True,
                    confidence=0.85,
                    severity="high",
                    vulnerability="a05-security-misconfiguration-debug",
                    evidence=Evidence(
                        request={"target": target_url},
                        response={"status": base.status_code, "snippet": base.text[:500] if base.text else ""},
                        matched="debug_or_directory_listing_exposure",
                        extra={"coverage_markers": A05_COVERAGE_MARKERS},
                    ),
                    impact="Application exposes debug information, stack traces, or directory listings which reveals internal structure.",
                    remediation="Disable debug mode in production. Catch exceptions and display generic error pages. Disable directory listing.",
                )
        except:
            pass

        # Test 2b: Explicit directory listing/index exposure on common roots and static paths.
        try:
            dir_listing_candidates = [target_url, urljoin(base_url + "/", ".git/"), urljoin(base_url + "/", "static/"), urljoin(base_url + "/", "assets/")]
            for candidate_url in dir_listing_candidates:
                resp = requests.get(candidate_url, headers=headers, timeout=timeout, allow_redirects=True)
                body = (resp.text or "")[:4000].lower()
                title = (resp.headers.get("title") or "").lower()
                if resp.status_code == 200 and ("index of /" in body or "directory listing" in body or "parent directory" in body or "<title>index of" in body or "index of" in title):
                    return ValidationResult(
                        success=True,
                        confidence=0.8,
                        severity="medium",
                        vulnerability="a05-security-misconfiguration-directory-listing",
                        evidence=Evidence(
                            request={"target": candidate_url},
                            response={"status": resp.status_code, "snippet": resp.text[:500] if resp.text else ""},
                            matched="directory_listing_or_index_exposure",
                            extra={"coverage_markers": A05_COVERAGE_MARKERS},
                        ),
                        impact="Directory listing or index exposure can reveal sensitive files, application structure, and deployment details.",
                        remediation="Disable directory listing and remove exposed index endpoints or static repository directories.",
                    )
        except:
            pass

        # Test 3: Default/unpatched application detection
        for path, app_name in COMMON_APPS:
            try:
                resp = requests.get(urljoin(base_url, path), headers=headers, timeout=timeout, allow_redirects=False)
                if resp.status_code == 200:
                    findings.append(f"{app_name}_detected_at_{path}")
                elif resp.status_code == 301:
                    findings.append(f"{app_name}_potentially_at_{path}")
            except:
                pass

        # Test 4: Default credentials (info-level detection)
        for admin_path in DEFAULT_ADMIN_PATHS:
            try:
                resp = requests.get(urljoin(base_url, admin_path), headers=headers, timeout=timeout, allow_redirects=False)
                if resp.status_code == 200 and ("login" in resp.text.lower() or "password" in resp.text.lower()):
                    findings.append(f"admin_interface_exposed_at_{admin_path}")
            except:
                pass

        # Test 5: Insecure default configuration via exposed admin or default pages.
        if findings:
            default_config_hits = [finding for finding in findings if "admin_interface_exposed_at_" in finding or "_detected_at_" in finding or "_potentially_at_" in finding]
            if default_config_hits:
                return ValidationResult(
                    success=True,
                    confidence=0.7,
                    severity="medium",
                    vulnerability="a05-security-misconfiguration-default",
                    evidence=Evidence(
                        request={"target": target_url},
                        response={"findings": findings},
                        matched=",".join(default_config_hits[:3]),
                        extra={"coverage_markers": A05_COVERAGE_MARKERS},
                    ),
                    impact="Exposed default applications, admin paths, or default configuration pages indicate insecure deployment hardening.",
                    remediation="Remove default apps, restrict administrative interfaces, and harden deployment configuration.",
                )

        if findings:
            return ValidationResult(
                success=True,
                confidence=0.75,
                severity="medium",
                vulnerability="a05-security-misconfiguration",
                evidence=Evidence(
                    request={"target": target_url},
                    response={"findings": findings},
                    matched=",".join(findings[:3]),
                    extra={"coverage_markers": A05_COVERAGE_MARKERS},
                ),
                impact="Application or server misconfiguration detected. This includes exposed sensitive paths, debug info, or unpatched components.",
                remediation="Review security configuration. Keep all software updated. Remove default files. Disable debug modes. Restrict admin access.",
            )

        return ValidationResult(
            success=False,
            confidence=0.0,
            severity="info",
            vulnerability="a05-security-misconfiguration",
            evidence=Evidence(
                request={"target": target_url},
                response={},
                matched="",
                extra={"coverage_markers": A05_COVERAGE_MARKERS},
            ),
            impact="No obvious security misconfiguration detected.",
            remediation="Regularly audit server configuration, disable unnecessary features, keep software patched.",
        )
