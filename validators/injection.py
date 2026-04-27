from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from engine.models import Evidence, EvidenceBundle, ExecutionContext, ValidationResult


SQL_ERROR_MARKERS = (
    "sql syntax",
    "mysql",
    "postgres",
    "sqlite",
    "oracle",
    "odbc",
    "jdbc",
    "syntax error",
    "unterminated quoted string",
    "sqlstate",
)

XSS_PAYLOAD = "<svg onload=alert(1)>"
SQLI_PAYLOAD = "1'"
COMMAND_PAYLOAD = "||echo SECURITY_PIPELINE_A03"
COMMAND_MARKER = "SECURITY_PIPELINE_A03"
FILE_PAYLOAD = "../../../../etc/passwd"
FILE_MARKERS = ("root:x:0:0:", "/bin/bash", "/etc/passwd")
TEMPLATE_PAYLOAD = "{{7*7}}"
TEMPLATE_MARKERS = ("49", TEMPLATE_PAYLOAD)
LDAP_PAYLOAD = "*)(uid=*)"
LDAP_MARKERS = ("ldap error", "invalid dn", "filter error", "ldap:")


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
    params = state.get("injection_params")
    if isinstance(params, list) and params:
        return [param for param in params if isinstance(param, str) and param.strip()]

    parsed = urlsplit(target_url)
    query_params = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if key]
    if query_params:
        return query_params

    return ["q", "id", "search", "name", "item", "query"]


class InjectionValidator:
    """OWASP A03 validator for reflected XSS and basic SQL error-based injection signals."""

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        url = state.get("url") or state.get("target")
        return isinstance(url, str) and url.startswith(("http://", "https://"))

    def _run_probe(self, url: str, headers: Dict[str, str], timeout: int) -> Dict[str, Any]:
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        body = response.text or ""
        lowered = body.lower()
        sql_error_hits = [marker for marker in SQL_ERROR_MARKERS if marker in lowered]
        xss_reflected = XSS_PAYLOAD in body
        command_marker_seen = COMMAND_MARKER in body
        file_marker_seen = any(marker in body for marker in FILE_MARKERS)
        template_marker_seen = any(marker in body for marker in TEMPLATE_MARKERS)
        ldap_marker_seen = any(marker in lowered for marker in LDAP_MARKERS)
        return {
            "status_code": response.status_code,
            "body": body,
            "sql_error_hits": sql_error_hits,
            "xss_reflected": xss_reflected,
            "command_marker_seen": command_marker_seen,
            "file_marker_seen": file_marker_seen,
            "template_marker_seen": template_marker_seen,
            "ldap_marker_seen": ldap_marker_seen,
            "headers": dict(response.headers),
        }

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
        findings: List[ValidationResult] = []

        for param in candidate_params:
            baseline_url = _replace_query_param(target_url, param, "injection-test")
            sqli_url = _replace_query_param(target_url, param, SQLI_PAYLOAD)
            xss_url = _replace_query_param(target_url, param, XSS_PAYLOAD)
            command_url = _replace_query_param(target_url, param, COMMAND_PAYLOAD)
            file_url = _replace_query_param(target_url, param, FILE_PAYLOAD)
            template_url = _replace_query_param(target_url, param, TEMPLATE_PAYLOAD)
            ldap_url = _replace_query_param(target_url, param, LDAP_PAYLOAD)

            try:
                baseline = self._run_probe(baseline_url, headers, timeout)
                sqli = self._run_probe(sqli_url, headers, timeout)
                xss = self._run_probe(xss_url, headers, timeout)
                command = self._run_probe(command_url, headers, timeout)
                file_probe = self._run_probe(file_url, headers, timeout)
                template_probe = self._run_probe(template_url, headers, timeout)
                ldap_probe = self._run_probe(ldap_url, headers, timeout)
            except requests.RequestException:
                continue

            if sqli["sql_error_hits"]:
                findings.append(
                    ValidationResult(
                        success=True,
                        confidence=0.92,
                        severity="high",
                        vulnerability="a03-injection-sqli",
                        evidence=Evidence(
                            request={"baseline_url": baseline_url, "probe_url": sqli_url, "param": param},
                            response={
                                "baseline_status": baseline["status_code"],
                                "probe_status": sqli["status_code"],
                                "sql_error_hits": sqli["sql_error_hits"],
                            },
                            matched=",".join(sqli["sql_error_hits"]),
                            extra={"param": param, "payload": SQLI_PAYLOAD},
                        ),
                        evidence_bundle=EvidenceBundle(
                            raw_request=f"GET {sqli_url}",
                            raw_response=_clip(sqli["body"]),
                            matched_indicator=",".join(sqli["sql_error_hits"]),
                            execution_proof={"sql_error_visible": True},
                            metadata={"param": param, "probe": "sqli"},
                        ),
                        impact="The application exposed SQL error behavior in response to injected input, indicating injection risk.",
                        remediation="Use parameterized queries, input validation, and suppress detailed database errors from responses.",
                        execution_proved=False,
                    )
                )

            if xss["xss_reflected"]:
                findings.append(
                    ValidationResult(
                        success=True,
                        confidence=0.9,
                        severity="high",
                        vulnerability="a03-injection-xss",
                        evidence=Evidence(
                            request={"baseline_url": baseline_url, "probe_url": xss_url, "param": param},
                            response={
                                "baseline_status": baseline["status_code"],
                                "probe_status": xss["status_code"],
                                "reflected": True,
                            },
                            matched=XSS_PAYLOAD,
                            extra={"param": param, "payload": XSS_PAYLOAD},
                        ),
                        evidence_bundle=EvidenceBundle(
                            raw_request=f"GET {xss_url}",
                            raw_response=_clip(xss["body"]),
                            matched_indicator=XSS_PAYLOAD,
                            execution_proof={"payload_reflected": True},
                            metadata={"param": param, "probe": "xss"},
                        ),
                        impact="User-controlled input is reflected without encoding, enabling client-side script execution.",
                        remediation="Encode output contextually, use templating safeguards, and add CSP defenses.",
                        execution_proved=False,
                    )
                )

            if command["command_marker_seen"]:
                findings.append(
                    ValidationResult(
                        success=True,
                        confidence=0.91,
                        severity="high",
                        vulnerability="a03-injection-command",
                        evidence=Evidence(
                            request={"baseline_url": baseline_url, "probe_url": command_url, "param": param},
                            response={
                                "baseline_status": baseline["status_code"],
                                "probe_status": command["status_code"],
                                "command_marker_seen": True,
                            },
                            matched=COMMAND_MARKER,
                            extra={"param": param, "payload": COMMAND_PAYLOAD},
                        ),
                        evidence_bundle=EvidenceBundle(
                            raw_request=f"GET {command_url}",
                            raw_response=_clip(command["body"]),
                            matched_indicator=COMMAND_MARKER,
                            execution_proof={"command_marker_seen": True},
                            metadata={"param": param, "probe": "command"},
                        ),
                        impact="The application reflected a command-execution marker, indicating possible command injection behavior.",
                        remediation="Avoid shell invocation with user input, use argument-safe subprocess APIs, and strictly validate command parameters.",
                        execution_proved=False,
                    )
                )

            if file_probe["file_marker_seen"]:
                findings.append(
                    ValidationResult(
                        success=True,
                        confidence=0.9,
                        severity="high",
                        vulnerability="a03-injection-file",
                        evidence=Evidence(
                            request={"baseline_url": baseline_url, "probe_url": file_url, "param": param},
                            response={
                                "baseline_status": baseline["status_code"],
                                "probe_status": file_probe["status_code"],
                                "file_marker_seen": True,
                            },
                            matched=",".join([marker for marker in FILE_MARKERS if marker in file_probe["body"]]) or FILE_PAYLOAD,
                            extra={"param": param, "payload": FILE_PAYLOAD},
                        ),
                        evidence_bundle=EvidenceBundle(
                            raw_request=f"GET {file_url}",
                            raw_response=_clip(file_probe["body"]),
                            matched_indicator="file_read_marker",
                            execution_proof={"file_marker_seen": True},
                            metadata={"param": param, "probe": "file"},
                        ),
                        impact="The application appears to expose local file content or file-read indicators through user-controlled input.",
                        remediation="Reject path traversal input, canonicalize file paths, and restrict file access to allowlisted resources.",
                        execution_proved=False,
                    )
                )

            if template_probe["template_marker_seen"]:
                findings.append(
                    ValidationResult(
                        success=True,
                        confidence=0.88,
                        severity="high",
                        vulnerability="a03-injection-template",
                        evidence=Evidence(
                            request={"baseline_url": baseline_url, "probe_url": template_url, "param": param},
                            response={
                                "baseline_status": baseline["status_code"],
                                "probe_status": template_probe["status_code"],
                                "template_marker_seen": True,
                            },
                            matched=TEMPLATE_PAYLOAD,
                            extra={"param": param, "payload": TEMPLATE_PAYLOAD},
                        ),
                        evidence_bundle=EvidenceBundle(
                            raw_request=f"GET {template_url}",
                            raw_response=_clip(template_probe["body"]),
                            matched_indicator=TEMPLATE_PAYLOAD,
                            execution_proof={"template_marker_seen": True},
                            metadata={"param": param, "probe": "template"},
                        ),
                        impact="The application appears to process template syntax or reflect a template evaluation marker.",
                        remediation="Do not evaluate user input in template engines and escape template delimiters before rendering.",
                        execution_proved=False,
                    )
                )

            if ldap_probe["ldap_marker_seen"]:
                findings.append(
                    ValidationResult(
                        success=True,
                        confidence=0.86,
                        severity="high",
                        vulnerability="a03-injection-ldap",
                        evidence=Evidence(
                            request={"baseline_url": baseline_url, "probe_url": ldap_url, "param": param},
                            response={
                                "baseline_status": baseline["status_code"],
                                "probe_status": ldap_probe["status_code"],
                                "ldap_marker_seen": True,
                            },
                            matched=LDAP_PAYLOAD,
                            extra={"param": param, "payload": LDAP_PAYLOAD},
                        ),
                        evidence_bundle=EvidenceBundle(
                            raw_request=f"GET {ldap_url}",
                            raw_response=_clip(ldap_probe["body"]),
                            matched_indicator=LDAP_PAYLOAD,
                            execution_proof={"ldap_marker_seen": True},
                            metadata={"param": param, "probe": "ldap"},
                        ),
                        impact="The application appears to surface LDAP filter errors or process LDAP-like injection input unsafely.",
                        remediation="Use strict LDAP escaping and parameter binding for directory queries.",
                        execution_proved=False,
                    )
                )

            if findings:
                return findings if len(findings) > 1 else findings[0]

        return ValidationResult(
            success=False,
            confidence=0.0,
            severity="info",
            vulnerability="a03-injection",
            evidence=Evidence(
                request={"target": target_url, "params": candidate_params},
                response={"status": "no_confirmed_injection"},
                matched="",
                extra={"candidate_params": candidate_params},
            ),
            impact="No injection behavior was confirmed by the available external probes.",
            remediation="Keep injection protections in place and add regression tests for all user-controlled parameters.",
        )


def _clip(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."
