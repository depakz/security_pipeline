from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from engine.models import Evidence, ExecutionContext, ValidationResult


A08_COVERAGE_MARKERS = [
    "insecure_deserialization_signal",
    "unsigned_or_untrusted_packages",
    "software_integrity_verification_gap",
    "tamper_resistance_gap",
    "unsafe_update_or_dependency_trust",
]


class InsecureDeserializationValidator:
    """OWASP A08 validator for insecure deserialization signals.

    Detection strategy:
    1) Detect common serialized signatures in existing request/finding context.
    2) Attempt a non-destructive timing probe payload (sleep-like marker).
    3) If timing delta aligns with configured sleep window, return validated finding.
    """

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        url = state.get("url") or state.get("target")
        return isinstance(url, str) and url.startswith(("http://", "https://"))

    def _collect_text(self, value: Any, out: List[str]) -> None:
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, dict):
            for v in value.values():
                self._collect_text(v, out)
        elif isinstance(value, list):
            for item in value:
                self._collect_text(item, out)

    def _detect_signatures(self, state: Dict[str, Any]) -> List[str]:
        corpus: List[str] = []
        self._collect_text(state.get("findings", []), corpus)
        self._collect_text(state.get("metadata", {}), corpus)
        self._collect_text(state.get("body", {}), corpus)
        self._collect_text(state.get("request_body", {}), corpus)
        self._collect_text(state.get("url", ""), corpus)

        joined = "\n".join(corpus)
        markers = []
        if "Tzo" in joined or "O:" in joined:
            markers.append("php_serialized_signature")
        if "rO0" in joined:
            markers.append("java_serialized_signature")
        if "__reduce__" in joined or "pickle" in joined:
            markers.append("python_pickle_signature")
        return markers

    def _guess_stack(self, state: Dict[str, Any], markers: List[str]) -> str:
        if any("java" in m for m in markers):
            return "java"
        if any("php" in m for m in markers):
            return "php"

        findings = state.get("findings", []) or []
        txt = str(findings).lower()
        if "tomcat" in txt or "jsp" in txt or "java" in txt:
            return "java"
        if "php" in txt or "laravel" in txt or "wordpress" in txt:
            return "php"
        return "generic"

    def _build_probe_payload(self, stack: str, sleep_seconds: int) -> Tuple[str, str]:
        if stack == "java":
            return (
                "data",
                f"rO0ABXQAFHNlY3VyaXR5LXByb2JlLXNsZWVwLXs=sleep:{sleep_seconds}",
            )
        if stack == "php":
            return (
                "data",
                f"Tzo4OiJzdGRDbGFzcyI6MTp7czo1OiJzbGVlcCI7aTo{sleep_seconds};fQ==",
            )
        return ("data", f"serialized_probe_sleep_{sleep_seconds}")

    def run(self, state: Dict[str, Any]):
        target_url = state.get("url") or state.get("target")
        if not isinstance(target_url, str) or not target_url:
            return None

        markers = self._detect_signatures(state)
        stack = self._guess_stack(state, markers)

        sleep_seconds = int(state.get("deserialization_sleep_seconds", 5) or 5)
        probe_param, probe_payload = self._build_probe_payload(stack, sleep_seconds)

        cookie = state.get("cookie")
        headers = {"User-Agent": "security-pipeline-validator/1.0"}
        if isinstance(cookie, str) and cookie.strip():
            headers["Cookie"] = cookie

        timeout = int(state.get("timeout", 12) or 12)

        try:
            baseline_start = time.perf_counter()
            baseline_resp = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=True)
            baseline_time = time.perf_counter() - baseline_start

            attack_params = {probe_param: probe_payload}
            attack_start = time.perf_counter()
            attack_resp = requests.get(
                target_url,
                params=attack_params,
                headers=headers,
                timeout=max(timeout, sleep_seconds + 5),
                allow_redirects=True,
            )
            attack_time = time.perf_counter() - attack_start

            delta = attack_time - baseline_time
            validated = abs(delta - sleep_seconds) <= 2.0 and attack_resp.status_code < 500

            confidence = 0.92 if validated else (0.65 if markers else 0.3)
            matched = ",".join(markers) if markers else "timing_probe_only"

            return ValidationResult(
                success=validated,
                confidence=confidence,
                severity="high" if validated else "info",
                vulnerability="a08-insecure-deserialization",
                evidence=Evidence(
                    request={
                        "baseline_url": target_url,
                        "payload_param": probe_param,
                        "payload": probe_payload,
                        "stack_guess": stack,
                    },
                    response={
                        "baseline_status": baseline_resp.status_code,
                        "attack_status": attack_resp.status_code,
                        "baseline_time_s": round(baseline_time, 3),
                        "attack_time_s": round(attack_time, 3),
                        "delta_s": round(delta, 3),
                    },
                    matched=matched,
                    extra={
                        "signatures_detected": markers,
                        "validated": validated,
                        "sleep_seconds": sleep_seconds,
                        "coverage_markers": A08_COVERAGE_MARKERS,
                    },
                ),
                impact="Unsafe deserialization can enable remote code execution, privilege escalation, or arbitrary object manipulation.",
                remediation="Avoid native object deserialization for untrusted data. Enforce strict allowlists, integrity checks, and safer data formats (JSON with schema validation).",
            )

        except requests.RequestException as exc:
            return ValidationResult(
                success=False,
                confidence=0.0,
                severity="info",
                vulnerability="a08-insecure-deserialization",
                evidence=Evidence(
                    request={"target": target_url, "stack_guess": stack},
                    response=str(exc),
                    matched=",".join(markers),
                    extra={"coverage_markers": A08_COVERAGE_MARKERS},
                ),
            )
