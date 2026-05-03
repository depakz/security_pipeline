from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from engine.models import Evidence, EvidenceBundle, ExecutionContext, ValidationResult


WORKFLOW_PARAM_NAMES = ("step", "state", "status", "phase", "stage", "action", "workflow", "role")
WORKFLOW_VALUES = ("draft", "pending", "review", "approved", "complete", "completed", "admin")
DENY_MARKERS = ("forbidden", "denied", "unauthorized", "not allowed", "invalid state", "step mismatch")

WORKFLOW_TEMPLATES = {
    "generic_approval": {
        "baseline": "draft",
        "bypass_values": ["approved", "completed"],
        "param_names": ["step", "state", "status"],
    },
    "payment_flow": {
        "baseline": "pending",
        "bypass_values": ["complete", "completed", "paid"],
        "param_names": ["stage", "status", "state"],
    },
    "role_escalation": {
        "baseline": "user",
        "bypass_values": ["admin", "superuser", "manager"],
        "param_names": ["role", "state", "status"],
    },
}

A04_COVERAGE_MARKERS = [
    "workflow_bypass",
    "state_transition_bypass",
    "business_logic_flaw",
    "idor_design_gap",
    "missing_security_controls_by_design",
]


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
    params = state.get("workflow_params")
    if isinstance(params, list) and params:
        return [param for param in params if isinstance(param, str) and param.strip()]

    parsed = urlsplit(target_url)
    query_params = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if key]
    if query_params:
        return query_params

    return list(WORKFLOW_PARAM_NAMES)


def _workflow_values(state: Dict[str, Any]) -> List[str]:
    values = state.get("workflow_bypass_values")
    if isinstance(values, list) and values:
        result = [value for value in values if isinstance(value, str) and value.strip()]
        if result:
            return result
    return list(WORKFLOW_VALUES)


def _workflow_templates(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    templates = state.get("workflow_templates")
    if isinstance(templates, list) and templates:
        normalized: List[Dict[str, Any]] = []
        for template in templates:
            if not isinstance(template, dict):
                continue
            name = template.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            normalized.append(
                {
                    "name": name.strip(),
                    "baseline": str(template.get("baseline") or "draft"),
                    "bypass_values": [value for value in template.get("bypass_values", []) if isinstance(value, str) and value.strip()],
                    "param_names": [value for value in template.get("param_names", []) if isinstance(value, str) and value.strip()],
                }
            )
        if normalized:
            return normalized

    return [
        {"name": name, **template}
        for name, template in WORKFLOW_TEMPLATES.items()
    ]


class InsecureDesignValidator:
    """OWASP A04 validator for workflow abuse and state-transition bypass."""

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        url = state.get("url") or state.get("target")
        return isinstance(url, str) and url.startswith(("http://", "https://"))

    def _probe(self, url: str, headers: Dict[str, str], timeout: int) -> Dict[str, Any]:
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        body = response.text or ""
        lowered = body.lower()
        deny_detected = any(marker in lowered for marker in DENY_MARKERS)
        success_markers = any(marker in lowered for marker in ("approved", "completed", "success", "payment received", "order placed"))
        return {
            "status_code": response.status_code,
            "body": body,
            "deny_detected": deny_detected,
            "success_markers": success_markers,
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
        workflow_attempts: List[Dict[str, Any]] = []

        for template in _workflow_templates(state):
            template_name = str(template.get("name") or "generic")
            baseline_value = str(template.get("baseline") or state.get("workflow_baseline", "draft"))
            bypass_values = template.get("bypass_values") or _workflow_values(state)
            param_names = template.get("param_names") or candidate_params

            for param in param_names:
                baseline_url = _replace_query_param(target_url, param, baseline_value)

                try:
                    baseline = self._probe(baseline_url, headers, timeout)
                except requests.RequestException:
                    continue

                for bypass_value in bypass_values:
                    bypass_url = _replace_query_param(target_url, param, bypass_value)

                    try:
                        bypass = self._probe(bypass_url, headers, timeout)
                    except requests.RequestException:
                        continue

                    workflow_attempts.append(
                        {
                            "template": template_name,
                            "param": param,
                            "baseline_value": baseline_value,
                            "bypass_value": bypass_value,
                            "baseline_status": baseline["status_code"],
                            "probe_status": bypass["status_code"],
                            "baseline_denied": baseline["deny_detected"],
                            "probe_denied": bypass["deny_detected"],
                            "success_markers": bypass["success_markers"],
                        }
                    )

                    bypassed = (
                        bypass["status_code"] == 200
                        and not bypass["deny_detected"]
                        and (bypass["success_markers"] or baseline["deny_detected"] or baseline["status_code"] in {401, 403, 409})
                    )

                    if bypassed:
                        return ValidationResult(
                            success=True,
                            confidence=0.89,
                            severity="high",
                            vulnerability="a04-insecure-design",
                            evidence=Evidence(
                                request={"baseline_url": baseline_url, "probe_url": bypass_url, "param": param},
                                response={
                                    "baseline_status": baseline["status_code"],
                                    "probe_status": bypass["status_code"],
                                    "baseline_denied": baseline["deny_detected"],
                                    "probe_denied": bypass["deny_detected"],
                                },
                                matched=f"{param}={bypass_value}",
                                extra={
                                    "template": template_name,
                                    "param": param,
                                    "baseline_value": baseline_value,
                                    "bypass_value": bypass_value,
                                    "workflow_params": candidate_params,
                                    "workflow_attempts": workflow_attempts,
                                    "coverage_markers": A04_COVERAGE_MARKERS,
                                },
                            ),
                            evidence_bundle=EvidenceBundle(
                                raw_request=f"GET {bypass_url}",
                                raw_response=_clip(bypass["body"]),
                                matched_indicator=bypass_value,
                                execution_proof={"workflow_bypass_observed": True},
                                metadata={"template": template_name, "param": param, "baseline_value": baseline_value, "bypass_value": bypass_value, "workflow_attempts": workflow_attempts},
                            ),
                            impact="The application appears to accept an out-of-order or elevated workflow state without enforcing the intended design.",
                            remediation="Enforce server-side workflow state machines, validate transitions, and do not trust client-controlled step or status fields.",
                            execution_proved=False,
                        )

        return ValidationResult(
            success=False,
            confidence=0.0,
            severity="info",
            vulnerability="a04-insecure-design",
            evidence=Evidence(
                request={"target": target_url, "params": candidate_params},
                response={"status": "no_confirmed_workflow_bypass"},
                matched="",
                extra={"candidate_params": candidate_params, "workflow_attempts": workflow_attempts, "coverage_markers": A04_COVERAGE_MARKERS},
            ),
            impact="No workflow bypass was confirmed from the available probes.",
            remediation="Keep server-side workflow enforcement and test state transitions in regression suites.",
        )


def _clip(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."
