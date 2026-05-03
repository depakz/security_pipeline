from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass
class ExecutionContext:
    target: str = ""
    endpoints: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    cookie: str = ""
    headers: Dict[str, Any] = field(default_factory=dict)
    session_context: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_state(cls, state: Dict[str, Any]) -> "ExecutionContext":
        if not isinstance(state, dict):
            return cls()

        target = str(state.get("target") or "")

        endpoints = state.get("endpoints") or []
        if not isinstance(endpoints, list):
            endpoints = []
        endpoints = [e for e in endpoints if isinstance(e, str)]

        findings = state.get("findings") or []
        if not isinstance(findings, list):
            findings = []
        findings = [f for f in findings if isinstance(f, dict)]

        metadata = state.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}

        cookie = state.get("cookie") or ""
        if not isinstance(cookie, str):
            cookie = str(cookie)

        headers = state.get("headers") or {}
        if not isinstance(headers, dict):
            headers = {}

        session_context = state.get("session_context") or {}
        if not isinstance(session_context, dict):
            session_context = {}

        return cls(
            target=target,
            endpoints=endpoints,
            findings=findings,
            metadata=metadata,
            cookie=cookie,
            headers=headers,
            session_context=session_context,
        )


@dataclass
class Evidence:
    request: Any
    response: Any
    matched: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceBundle:
    """
    Enhanced evidence storage for high-confidence validation.
    
    Stores complete evidence of actual code execution, not just pattern matches.
    Examples:
    - Shell command output (not just HTTP response)
    - File contents extracted via LFI
    - Successfully executed exploit code
    """
    raw_request: str  # Full HTTP request or command
    raw_response: str  # Full HTTP response or command output
    matched_indicator: str  # The specific string/pattern matched
    execution_proof: Dict[str, Any] = field(default_factory=dict)  # e.g., {"shell_output": "..."}
    tool_logs: List[Dict[str, Any]] = field(default_factory=list)  # Output from scanner tools
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional context

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_request": self.raw_request,
            "raw_response": self.raw_response,
            "matched_indicator": self.matched_indicator,
            "execution_proof": self.execution_proof,
            "tool_logs": self.tool_logs,
            "metadata": self.metadata,
        }


@dataclass
class ValidationResult:
    success: bool
    confidence: float
    severity: str
    vulnerability: str
    evidence: Evidence
    impact: str = ""
    remediation: str = ""
    confidence_score: float = 0.0  # High-precision confidence (0.0-1.0)
    evidence_bundle: Optional[EvidenceBundle] = None  # Enhanced evidence for successful exploits
    chain_source: Optional[str] = None  # Parent vulnerability that enabled this attack
    execution_proved: bool = False  # True if we have shell output or file content, not just regex match

    def __post_init__(self):
        """Ensure confidence_score is synced with confidence if not explicitly set."""
        if self.confidence_score == 0.0:
            self.confidence_score = self.confidence

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

        try:
            confidence_score = float(self.confidence_score)
        except Exception:
            confidence_score = confidence

        if confidence_score < 0.0:
            confidence_score = 0.0
        if confidence_score > 1.0:
            confidence_score = 1.0

        result = {
            "success": bool(self.success),
            "vulnerability": self.vulnerability,
            "severity": severity,
            "validation": {
                "status": "confirmed" if self.success else "failed",
                "confidence": confidence,
                "confidence_score": confidence_score,
                "execution_proved": self.execution_proved,
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

        if self.evidence_bundle is not None:
            result["evidence_bundle"] = self.evidence_bundle.to_dict()

        if self.chain_source is not None:
            result["chain_source"] = self.chain_source

        return result
