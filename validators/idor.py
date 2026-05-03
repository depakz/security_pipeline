from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from engine.models import Evidence, ExecutionContext, ValidationResult


A04_COVERAGE_MARKERS = [
    "workflow_bypass",
    "state_transition_bypass",
    "business_logic_flaw",
    "idor_design_gap",
    "missing_security_controls_by_design",
]


def _levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            ins = curr[j - 1] + 1
            delete = prev[j] + 1
            subst = prev[j - 1] + (0 if ca == cb else 1)
            curr.append(min(ins, delete, subst))
        prev = curr
    return prev[-1]


def _similarity(a: str, b: str) -> float:
    max_len = max(len(a), len(b), 1)
    dist = _levenshtein_distance(a, b)
    return 1.0 - (dist / max_len)


def _replace_query_param(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)

    out: List[Tuple[str, str]] = []
    replaced = False
    for k, v in pairs:
        if k == key and not replaced:
            out.append((k, value))
            replaced = True
        elif k == key:
            continue
        else:
            out.append((k, v))

    if not replaced:
        out.append((key, value))

    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(out, doseq=True), parts.fragment))


class IDORValidator:
    """A04 Insecure Design validator for simple IDOR checks.

    Performs a baseline request (id=1 by default) and a tampered request
    (id=2 by default), then compares response body similarity.
    """

    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context
        self.destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        url = state.get("url") or state.get("target")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            return False
        protocols = state.get("protocols", []) or []
        return not protocols or "http" in protocols

    def run(self, state: Dict[str, Any]):
        target_url = state.get("url") or state.get("target")
        if not isinstance(target_url, str) or not target_url:
            return None

        parts = urlsplit(target_url)
        query_keys = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True) if k]
        candidate_params = state.get("idor_params")
        if not isinstance(candidate_params, list) or not candidate_params:
            candidate_params = query_keys or ["id", "user_id", "account_id"]

        baseline_id = str(state.get("baseline_id", "1"))
        compare_id = str(state.get("compare_id", "2"))
        deny_markers = [
            "access denied",
            "forbidden",
            "unauthorized",
            "permission denied",
            "not allowed",
        ]

        cookie = state.get("cookie")
        headers = {"User-Agent": "security-pipeline-validator/1.0"}
        if isinstance(cookie, str) and cookie.strip():
            headers["Cookie"] = cookie

        timeout = int(state.get("timeout", 10) or 10)
        threshold = float(state.get("idor_similarity_threshold", 0.85) or 0.85)

        best_result: Optional[Dict[str, Any]] = None

        for param in [p for p in candidate_params if isinstance(p, str) and p.strip()]:
            try:
                url_a = _replace_query_param(target_url, param, baseline_id)
                url_b = _replace_query_param(target_url, param, compare_id)

                resp_a = requests.get(url_a, headers=headers, timeout=timeout, allow_redirects=True)
                resp_b = requests.get(url_b, headers=headers, timeout=timeout, allow_redirects=True)

                body_a = resp_a.text or ""
                body_b = resp_b.text or ""

                sim = _similarity(body_a, body_b)
                body_b_l = body_b.lower()
                deny_detected = any(marker in body_b_l for marker in deny_markers)

                confirmed = (
                    resp_a.status_code == 200
                    and resp_b.status_code == 200
                    and sim < threshold
                    and not deny_detected
                )

                candidate = {
                    "param": param,
                    "baseline_url": url_a,
                    "tampered_url": url_b,
                    "status_baseline": resp_a.status_code,
                    "status_tampered": resp_b.status_code,
                    "similarity": round(sim, 4),
                    "distance": _levenshtein_distance(body_a, body_b),
                    "deny_detected": deny_detected,
                    "baseline_snippet": body_a[:400],
                    "tampered_snippet": body_b[:400],
                }

                if best_result is None or candidate["similarity"] < best_result["similarity"]:
                    best_result = candidate

                if confirmed:
                    return ValidationResult(
                        success=True,
                        confidence=0.9,
                        severity="high",
                        vulnerability="a04-insecure-design-idor",
                        evidence=Evidence(
                            request={"baseline": url_a, "tampered": url_b},
                            response={
                                "status_baseline": resp_a.status_code,
                                "status_tampered": resp_b.status_code,
                            },
                            matched=f"param={param}; similarity={sim:.4f}",
                            extra={**candidate, "coverage_markers": A04_COVERAGE_MARKERS},
                        ),
                        impact="An authenticated/unauthenticated user may access another user's data by changing object identifiers.",
                        remediation="Enforce object-level authorization checks on every read/write operation and avoid direct object references without access control.",
                    )

            except Exception as exc:
                best_result = {
                    "param": param,
                    "error": str(exc),
                }

        return ValidationResult(
            success=False,
            confidence=0.0,
            severity="info",
            vulnerability="a04-insecure-design-idor",
            evidence=Evidence(
                request={"target": target_url, "params": candidate_params},
                response=best_result or {},
                matched="",
                extra={"coverage_markers": A04_COVERAGE_MARKERS},
            ),
            impact="No confident IDOR behavior detected with the tested identifier transitions.",
            remediation="Keep object-level authorization checks and add ownership tests in CI for all object-access endpoints.",
        )
