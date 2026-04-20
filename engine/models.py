from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List
from urllib.parse import urljoin


_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass
class ExecutionContext:
    target: str = ""
    endpoints: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_state(cls, state: Dict[str, Any]) -> "ExecutionContext":
        if not isinstance(state, dict):
            return cls()

        target = str(state.get("target") or "")

        endpoints: List[str] = []

        # Backward compatible: endpoint URLs as strings
        raw_endpoints = state.get("endpoints") or []
        if isinstance(raw_endpoints, list):
            for item in raw_endpoints:
                if isinstance(item, str) and item.strip():
                    endpoints.append(item.strip())
                elif isinstance(item, dict):
                    u = item.get("url")
                    if not isinstance(u, str) or not u.strip():
                        continue
                    u = u.strip()
                    if u.startswith("http://") or u.startswith("https://"):
                        endpoints.append(u)
                        continue

                    base = state.get("url")
                    if isinstance(base, str) and base.startswith(("http://", "https://")):
                        try:
                            endpoints.append(urljoin(base.rstrip("/") + "/", u.lstrip("/")))
                        except Exception:
                            pass

        # New: optional raw URL list if state.endpoints is structured
        extra_urls = state.get("endpoint_urls") or []
        if isinstance(extra_urls, list):
            for u in extra_urls:
                if isinstance(u, str) and u.strip():
                    endpoints.append(u.strip())

        # Stable dedupe
        deduped: List[str] = []
        seen = set()
        for u in endpoints:
            if u in seen:
                continue
            seen.add(u)
            deduped.append(u)
        endpoints = deduped

        findings = state.get("findings") or []
        if not isinstance(findings, list):
            findings = []
        findings = [f for f in findings if isinstance(f, dict)]

        metadata = state.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}

        return cls(target=target, endpoints=endpoints, findings=findings, metadata=metadata)


@dataclass
class Evidence:
    request: Any
    response: Any
    matched: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    success: bool
    confidence: float
    severity: str
    vulnerability: str
    evidence: Evidence
    impact: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        severity = (self.severity or "info").strip().lower()
        if severity not in _ALLOWED_SEVERITIES:
            severity = "info"

        try:
            confidence = float(self.confidence)
        except Exception:
            confidence = 0.0

        if confidence < 0.0:
            confidence = 0.0
        if confidence > 1.0:
            confidence = 1.0

        return {
            "success": bool(self.success),
            "vulnerability": self.vulnerability,
            "severity": severity,
            "validation": {
                "status": "confirmed" if self.success else "failed",
                "confidence": confidence,
            },
            "evidence": {
                "request": self.evidence.request,
                "response": self.evidence.response,
                "matched": self.evidence.matched,
                "extra": self.evidence.extra or {},
            },
            "impact": self.impact,
            "remediation": self.remediation,
        }
