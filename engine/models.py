from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


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
