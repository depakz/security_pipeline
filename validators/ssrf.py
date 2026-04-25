from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from engine.models import Evidence, ExecutionContext, ValidationResult
from utils.logger import logger


DEFAULT_PARAMS = ["url", "uri", "dest", "destination", "next", "redirect", "path", "feed", "image", "src", "callback", "endpoint", "target", "webhook", "host", "link"]
LOOPBACK_TARGETS = ["http://127.0.0.1", "http://127.0.0.1:80", "http://localhost"]
SSRF_MARKERS = ["127.0.0.1", "localhost", "connection refused", "refused", "timed out", "timeout", "econnrefused", "internal server error", "bad gateway", "gateway timeout"]


def _replace_query_param(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    updated: List[Tuple[str, str]] = []
    replaced = False

    for current_key, current_value in pairs:
        if current_key == key and not replaced:
            updated.append((current_key, value))
            replaced = True
        elif current_key == key:
            continue
        else:
            updated.append((current_key, current_value))

    if not replaced:
        updated.append((key, value))

    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(updated, doseq=True), parts.fragment))


def _candidate_params(state: Dict[str, Any], target_url: str) -> List[str]:
    params = state.get("ssrf_params")
    if isinstance(params, list) and params:
        return [param for param in params if isinstance(param, str) and param.strip()]

    parsed = urlsplit(target_url)
    query_params = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if key]
    if query_params:
        return query_params

    return list(DEFAULT_PARAMS)


class SSRFValidator:
    """OWASP A10 validator that probes a loopback fetch through a suspected URL parameter."""

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

        candidate_params = _candidate_params(state, target_url)
        baseline_value = str(state.get("ssrf_baseline", "https://example.com/"))

        logger.info("SSRFValidator: probing %s with parameters %s", target_url, candidate_params)

        for param in candidate_params:
            if not param:
                continue

            baseline_url = _replace_query_param(target_url, param, baseline_value)
            for loopback_url in LOOPBACK_TARGETS:
                probe_url = _replace_query_param(target_url, param, loopback_url)

                try:
                    baseline_response = requests.get(baseline_url, headers=headers, timeout=timeout, allow_redirects=False)
                    probe_response = requests.get(probe_url, headers=headers, timeout=timeout, allow_redirects=False)

                    probe_body = (probe_response.text or "")[:2000]
                    probe_lower = probe_body.lower()
                    matched_markers = [marker for marker in SSRF_MARKERS if marker in probe_lower]

                    if matched_markers or (probe_response.status_code in {400, 401, 403, 500, 502, 503, 504} and probe_body):
                        logger.warning("SSRFValidator: confirmed probe via %s=%s", param, loopback_url)
                        return ValidationResult(
                            success=True,
                            confidence=0.95 if matched_markers else 0.8,
                            severity="high",
                            vulnerability="a10-server-side-request-forgery",
                            evidence=Evidence(
                                request={"baseline_url": baseline_url, "probe_url": probe_url, "param": param},
                                response={
                                    "baseline_status": baseline_response.status_code,
                                    "probe_status": probe_response.status_code,
                                    "probe_snippet": probe_body[:500],
                                },
                                matched=",".join(matched_markers) if matched_markers else loopback_url,
                                extra={"param": param, "loopback_url": loopback_url, "candidate_params": candidate_params},
                            ),
                            impact="The application appears to fetch attacker-controlled URLs, enabling internal network probing or metadata access.",
                            remediation="Restrict outbound fetch destinations with allowlists, block loopback/link-local ranges, and normalize URL parsing before fetches.",
                        )
                except requests.RequestException as exc:
                    error_text = str(exc).lower()
                    if any(marker in error_text for marker in SSRF_MARKERS):
                        logger.warning("SSRFValidator: exception-based confirmation via %s=%s (%s)", param, loopback_url, exc)
                        return ValidationResult(
                            success=True,
                            confidence=0.9,
                            severity="high",
                            vulnerability="a10-server-side-request-forgery",
                            evidence=Evidence(
                                request={"baseline_url": baseline_url, "probe_url": probe_url, "param": param},
                                response=str(exc),
                                matched=str(exc),
                                extra={"loopback_url": loopback_url, "candidate_params": candidate_params},
                            ),
                            impact="The application processed a server-side URL fetch attempt and surfaced loopback-specific network behavior.",
                            remediation="Block loopback, localhost, and internal RFC1918 destinations in outbound fetch logic and use strict URL allowlists.",
                        )

        return ValidationResult(
            success=False,
            confidence=0.0,
            severity="info",
            vulnerability="a10-server-side-request-forgery",
            evidence=Evidence(
                request={"target": target_url, "candidate_params": candidate_params},
                response={"loopback_targets": LOOPBACK_TARGETS},
                matched="",
            ),
            impact="No SSRF behavior was confirmed from the tested loopback probes.",
            remediation="Keep URL fetchers behind allowlists and monitor internal-destination egress attempts.",
        )