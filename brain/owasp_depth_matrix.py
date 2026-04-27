"""OWASP Top 10 depth coverage matrix utilities.

Provides subcase-level coverage accounting per OWASP 2021 category.
This is a measurement layer, not an exploitation engine.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Set, Tuple


OWASP_SUBCASE_CATALOG: Dict[str, List[str]] = {
    "A01": [
        "route_access_control",
        "object_level_authorization_idor",
        "function_level_authorization",
        "privilege_escalation",
        "forced_browsing_sensitive_paths",
    ],
    "A02": [
        "weak_tls_versions",
        "plaintext_sensitive_transport",
        "missing_transport_encryption",
        "insecure_cipher_or_protocol_policy",
        "sensitive_data_exposure_in_transit",
    ],
    "A03": [
        "sql_injection",
        "xss_reflected_or_stored",
        "command_injection",
        "template_injection",
        "ldap_or_query_injection",
    ],
    "A04": [
        "workflow_bypass",
        "state_transition_bypass",
        "business_logic_flaw",
        "idor_design_gap",
        "missing_security_controls_by_design",
    ],
    "A05": [
        "dangerous_http_methods_enabled",
        "debug_or_stacktrace_exposure",
        "directory_listing_or_index_exposure",
        "insecure_default_configuration",
        "excessive_technology_disclosure",
    ],
    "A06": [
        "known_cve_indicator_detected",
        "outdated_component_version_disclosed",
        "dependency_patch_lag_signal",
        "vulnerable_server_software_signal",
        "unsafe_component_inventory_gap",
    ],
    "A07": [
        "missing_login_rate_limit",
        "insecure_remember_me_cookie_flags",
        "weak_session_management_signal",
        "credential_control_weakness",
        "authentication_flow_hardening_gap",
    ],
    "A08": [
        "insecure_deserialization_signal",
        "unsigned_or_untrusted_packages",
        "software_integrity_verification_gap",
        "tamper_resistance_gap",
        "unsafe_update_or_dependency_trust",
    ],
    "A09": [
        "missing_security_headers_as_monitoring_signal",
        "insufficient_monitoring_indicators",
        "audit_visibility_hardening_gap",
        "low_detection_surface_signal",
        "telemetry_control_gap",
    ],
    "A10": [
        "loopback_ssrf_probe",
        "internal_network_reachability_via_ssrf",
        "metadata_service_reachability_signal",
        "url_fetch_allowlist_gap",
        "server_side_request_validation_gap",
    ],
}


PATTERN_RULES: List[Tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"a01|broken[\s_-]?access|access[\s_-]?control|idor", re.I), "A01", "object_level_authorization_idor"),
    (re.compile(r"admin|dashboard|forbidden|unauth", re.I), "A01", "route_access_control"),
    (re.compile(r"privilege|escalat", re.I), "A01", "privilege_escalation"),

    (re.compile(r"a02|crypt|tls|ssl|cipher", re.I), "A02", "weak_tls_versions"),
    (re.compile(r"plaintext|http://|sensitive header|authorization|cookie", re.I), "A02", "plaintext_sensitive_transport"),

    (re.compile(r"a03|injection|sqli|sql", re.I), "A03", "sql_injection"),
    (re.compile(r"xss", re.I), "A03", "xss_reflected_or_stored"),
    (re.compile(r"command", re.I), "A03", "command_injection"),
    (re.compile(r"template", re.I), "A03", "template_injection"),
    (re.compile(r"ldap", re.I), "A03", "ldap_or_query_injection"),

    (re.compile(r"a04|insecure[\s_-]?design|workflow|state", re.I), "A04", "workflow_bypass"),
    (re.compile(r"idor", re.I), "A04", "idor_design_gap"),
    (re.compile(r"logic", re.I), "A04", "business_logic_flaw"),

    (re.compile(r"a05|misconfig|trace|options", re.I), "A05", "dangerous_http_methods_enabled"),
    (re.compile(r"debug|stack\s*trace|exception", re.I), "A05", "debug_or_stacktrace_exposure"),
    (re.compile(r"index of|directory", re.I), "A05", "directory_listing_or_index_exposure"),
    (re.compile(r"server|x-powered-by|technology", re.I), "A05", "excessive_technology_disclosure"),

    (re.compile(r"a06|outdated|component|cve", re.I), "A06", "known_cve_indicator_detected"),
    (re.compile(r"version", re.I), "A06", "outdated_component_version_disclosed"),

    (re.compile(r"a07|auth|login|credential|password", re.I), "A07", "missing_login_rate_limit"),
    (re.compile(r"remember", re.I), "A07", "insecure_remember_me_cookie_flags"),
    (re.compile(r"session", re.I), "A07", "weak_session_management_signal"),

    (re.compile(r"a08|deserializ|serializ", re.I), "A08", "insecure_deserialization_signal"),
    (re.compile(r"unsigned|package|integrity|signature", re.I), "A08", "unsigned_or_untrusted_packages"),

    (re.compile(r"a09|logging|monitor|audit", re.I), "A09", "insufficient_monitoring_indicators"),
    (re.compile(r"security header|x-content-type-options|csp|x-frame-options", re.I), "A09", "missing_security_headers_as_monitoring_signal"),

    (re.compile(r"a10|ssrf|server-side request", re.I), "A10", "loopback_ssrf_probe"),
    (re.compile(r"127\.0\.0\.1|localhost|metadata", re.I), "A10", "internal_network_reachability_via_ssrf"),
]


def _collect_strings(value: Any, out: List[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, Mapping):
        for item in value.values():
            _collect_strings(item, out)
    elif isinstance(value, list):
        for item in value:
            _collect_strings(item, out)


def _extract_candidate_text(records: Iterable[Mapping[str, Any]]) -> List[str]:
    parts: List[str] = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        _collect_strings(record, parts)
        tags = record.get("compliance_tags")
        if isinstance(tags, Mapping):
            owasp_tag = tags.get("OWASP")
            if isinstance(owasp_tag, str):
                parts.append(owasp_tag)
    return parts


def _collect_variant_attempts(records: Iterable[Mapping[str, Any]]) -> Dict[str, int]:
    counters = {
        "a02_variant_attempts": 0,
        "a03_variant_attempts": 0,
        "a10_variant_attempts": 0,
    }

    for record in records:
        if not isinstance(record, Mapping):
            continue
        evidence = record.get("evidence")
        if not isinstance(evidence, Mapping):
            continue
        extra = evidence.get("extra")
        if not isinstance(extra, Mapping):
            continue

        a02 = extra.get("attempted_sensitive_header_variants")
        if isinstance(a02, list):
            counters["a02_variant_attempts"] += len(a02)

        a03 = extra.get("attempted_payload_variants")
        if isinstance(a03, list):
            counters["a03_variant_attempts"] += len(a03)

        a10 = extra.get("attempted_loopback_targets")
        if isinstance(a10, list):
            counters["a10_variant_attempts"] += len(a10)

    counters["total_recorded_variant_attempts"] = (
        counters["a02_variant_attempts"]
        + counters["a03_variant_attempts"]
        + counters["a10_variant_attempts"]
    )
    return counters


def _detect_subcases(text: str) -> Dict[str, Set[str]]:
    detected: Dict[str, Set[str]] = {k: set() for k in OWASP_SUBCASE_CATALOG}
    for pattern, category, subcase in PATTERN_RULES:
        if pattern.search(text):
            detected.setdefault(category, set()).add(subcase)
    return detected


def build_depth_coverage(records: List[Mapping[str, Any]]) -> Dict[str, Any]:
    candidate_text = _extract_candidate_text(records)
    joined = "\n".join(candidate_text)
    detected = _detect_subcases(joined)

    category_rows: List[Dict[str, Any]] = []
    total_tested = 0
    total_subcases = 0
    categories_with_coverage = 0

    for category in sorted(OWASP_SUBCASE_CATALOG.keys()):
        all_subcases = OWASP_SUBCASE_CATALOG[category]
        tested = sorted(detected.get(category, set()))
        untested = [s for s in all_subcases if s not in tested]

        tested_count = len(tested)
        total_count = len(all_subcases)
        coverage = round((tested_count / total_count) * 100.0, 2) if total_count else 0.0

        if tested_count > 0:
            categories_with_coverage += 1

        total_tested += tested_count
        total_subcases += total_count

        category_rows.append(
            {
                "owasp_category": category,
                "tested_subcases_count": tested_count,
                "total_subcases_count": total_count,
                "coverage_percent": coverage,
                "tested_subcases": tested,
                "untested_subcases": untested,
            }
        )

    overall = round((total_tested / total_subcases) * 100.0, 2) if total_subcases else 0.0

    variant_attempts = _collect_variant_attempts(records)

    return {
        "summary": {
            "categories_total": 10,
            "categories_with_any_tested_subcase": categories_with_coverage,
            "categories_without_tested_subcases": 10 - categories_with_coverage,
            "subcases_tested": total_tested,
            "subcases_total": total_subcases,
            "overall_subcase_coverage_percent": overall,
            "variant_attempts": variant_attempts,
        },
        "categories": category_rows,
    }
