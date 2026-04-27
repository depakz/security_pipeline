from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests

from engine.models import Evidence, ExecutionContext, ValidationResult
from utils.logger import logger


CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
VERSION_REGEX = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")


def _collect_text(value: Any, out: List[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _collect_text(v, out)
    elif isinstance(value, list):
        for item in value:
            _collect_text(item, out)


class OutdatedComponentsValidator:
    """OWASP A06 validator for vulnerable/outdated component evidence."""

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        findings = state.get("findings") or []
        url = state.get("url") or state.get("target")
        return (isinstance(findings, list) and len(findings) > 0) or (
            isinstance(url, str) and url.startswith(("http://", "https://"))
        )

    def run(self, state: Dict[str, Any]):
        target_url = state.get("url") or state.get("target")
        findings = state.get("findings") or []
        timeout = int(state.get("timeout", 8) or 8)

        corpus: List[str] = []
        _collect_text(findings, corpus)
        joined = "\n".join(corpus)
        cves = sorted(set(m.group(0).upper() for m in CVE_REGEX.finditer(joined)))

        headers_seen: Dict[str, str] = {}
        disclosed_versions: List[str] = []

        if isinstance(target_url, str) and target_url.startswith(("http://", "https://")):
            try:
                response = requests.get(
                    target_url,
                    headers={"User-Agent": "security-pipeline-validator/1.0"},
                    timeout=timeout,
                    allow_redirects=True,
                )
                for key in ("Server", "X-Powered-By", "Via"):
                    value = response.headers.get(key)
                    if isinstance(value, str) and value.strip():
                        headers_seen[key] = value
                        disclosed_versions.extend(VERSION_REGEX.findall(value))
            except requests.RequestException:
                pass

        confirmed = len(cves) > 0 or len(disclosed_versions) > 0
        if confirmed:
            logger.warning(
                "OutdatedComponentsValidator: cves=%s disclosed_versions=%s",
                cves,
                disclosed_versions,
            )
            return ValidationResult(
                success=True,
                confidence=0.92 if cves else 0.72,
                severity="high",
                vulnerability="a06-vulnerable-and-outdated-components",
                evidence=Evidence(
                    request={"target": target_url},
                    response={
                        "cves": cves,
                        "version_headers": headers_seen,
                        "disclosed_versions": disclosed_versions,
                    },
                    matched=",".join(cves or disclosed_versions),
                    extra={"cve_count": len(cves), "header_count": len(headers_seen)},
                ),
                impact="Known-vulnerable or stale components can expose publicly documented exploit paths.",
                remediation="Upgrade affected components, remove vulnerable versions from deployment, and enforce patch SLAs.",
            )

        return ValidationResult(
            success=False,
            confidence=0.2,
            severity="info",
            vulnerability="a06-vulnerable-and-outdated-components",
            evidence=Evidence(
                request={"target": target_url},
                response={"cves": cves, "version_headers": headers_seen},
                matched="",
            ),
            impact="No strong vulnerable/outdated component indicator was confirmed from available signals.",
            remediation="Continue SBOM/CVE correlation and dependency lifecycle management in CI/CD.",
        )