"""Integrity validator for software integrity and deserialization risks.

This validator is intentionally non-destructive: it focuses on safe detection
signals, response heuristics, and externally observed callback evidence rather
than generating live exploit payloads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from engine.models import Evidence, EvidenceBundle, ExecutionContext, ValidationResult

try:
    from brain.fact_store import FactStore, FactCategory, Fact
except Exception:  # pragma: no cover - optional runtime dependency
    FactStore = None  # type: ignore
    FactCategory = None  # type: ignore
    Fact = None  # type: ignore


@dataclass
class IntegritySignal:
    target: str
    indicator: str
    details: Dict[str, Any] = field(default_factory=dict)


class IntegrityValidator:
    def __init__(self, context: Optional[ExecutionContext] = None, fact_store: Optional[Any] = None):
        self.context = context
        self.fact_store = fact_store
        self.destructive = False

    COVERAGE_MARKERS = [
        "insecure_deserialization_signal",
        "unsigned_or_untrusted_packages",
        "software_integrity_verification_gap",
        "tamper_resistance_gap",
        "unsafe_update_or_dependency_trust",
    ]

    def can_run(self, state: Dict[str, Any]) -> bool:
        return bool(state.get("url") or state.get("target") or state.get("repo_url") or state.get("repository_url"))

    def _record_signal(self, signal: IntegritySignal) -> None:
        if not self.fact_store or FactStore is None or Fact is None or FactCategory is None:
            return
        try:
            self.fact_store.add_fact(
                Fact(  # type: ignore[misc]
                    category=FactCategory.EXPLOITATION_ARTIFACT,
                    key=f"integrity:{sha256(signal.target.encode()).hexdigest()[:16]}",
                    value={"indicator": signal.indicator, "details": signal.details, "target": signal.target},
                    confidence=0.75,
                    metadata={"validator": "integrity"},
                )
            )
        except Exception:
            pass

    def check_deserialization(
        self,
        target_url: str,
        body: Dict[str, Any],
        oob_observer: Optional[Callable[[str], bool]] = None,
    ) -> Optional[ValidationResult]:
        """Safely assess deserialization risk using heuristics and optional OOB observer hooks."""
        if not target_url:
            return None

        body_text = str(body or {})
        suspicious_tokens = (
            "ysoserial",
            "__reduce__",
            "ObjectInputStream",
            "BinaryFormatter",
            "pickle",
            "unserialize",
            "marshal",
            "Serializable",
        )
        matched = [token for token in suspicious_tokens if token.lower() in body_text.lower()]
        indicator = ",".join(matched)

        signal = IntegritySignal(target=target_url, indicator=indicator, details={"tokens": matched})
        self._record_signal(signal)

        oob_seen = False
        if oob_observer is not None and matched:
            probe_id = sha256(f"{target_url}|{indicator}".encode()).hexdigest()[:12]
            try:
                oob_seen = bool(oob_observer(probe_id))
            except Exception:
                oob_seen = False

        success = bool(matched)
        confidence = 0.95 if oob_seen else (0.72 if matched else 0.0)

        evidence_bundle = EvidenceBundle(
            raw_request=f"POST {target_url}",
            raw_response=body_text[:4000],
            matched_indicator=indicator,
            execution_proof={"oob_interaction": oob_seen, "suspicious_tokens": matched},
            tool_logs=[{"tool": "integrity-validator", "signal": indicator}],
            metadata={"target": target_url},
        )

        return ValidationResult(
            success=success,
            confidence=confidence,
            confidence_score=confidence,
            severity="high" if success else "info",
            vulnerability="insecure-deserialization" if success else "deserialization-clean",
            evidence=Evidence(
                request=target_url,
                response={"matched_tokens": matched},
                matched=indicator,
                extra={"oob_seen": oob_seen, "coverage_markers": self.COVERAGE_MARKERS},
            ),
            impact="Insecure deserialization can enable remote code execution or privilege escalation." if success else "No clear deserialization sink identified.",
            remediation="Use safe serializers, enforce type allowlists, and sign/verify serialized payloads.",
            evidence_bundle=evidence_bundle,
            execution_proved=oob_seen,
        )

    def check_unsigned_packages(self, repo_url: str, manifest_text: Optional[str] = None) -> Optional[ValidationResult]:
        """Check whether a repository or manifest appears unsigned or integrity-weak."""
        if not repo_url:
            return None

        body = manifest_text
        if body is None:
            try:
                req = Request(repo_url, headers={"User-Agent": "security-pipeline-validator/1.0"})
                with urlopen(req, timeout=8) as response:
                    body = (response.read() or b"").decode(errors="ignore")
            except Exception as exc:
                return ValidationResult(
                    success=False,
                    confidence=0.0,
                    confidence_score=0.0,
                    severity="info",
                    vulnerability="package-manifest-unavailable",
                    evidence=Evidence(request=repo_url, response=str(exc), matched=""),
                )

        normalized = (body or "").lower()
        unsigned = all(signature_marker not in normalized for signature_marker in ("gpg", "pgp", "signature", "signed-by", "sha256sum", "sigstore"))
        confidence = 0.9 if unsigned else 0.0
        indicator = "missing-signature" if unsigned else "signature-present"

        self._record_signal(IntegritySignal(target=repo_url, indicator=indicator, details={"unsigned": unsigned}))

        evidence_bundle = EvidenceBundle(
            raw_request=repo_url,
            raw_response=(body or "")[:4000],
            matched_indicator=indicator,
            execution_proof={"unsigned_package": unsigned},
            tool_logs=[{"tool": "integrity-validator", "indicator": indicator}],
            metadata={"repo_url": repo_url},
        )

        return ValidationResult(
            success=unsigned,
            confidence=confidence,
            confidence_score=confidence,
            severity="high" if unsigned else "info",
            vulnerability="unsigned-packages" if unsigned else "signed-packages",
            evidence=Evidence(request=repo_url, response={"unsigned": unsigned}, matched=indicator, extra={"coverage_markers": self.COVERAGE_MARKERS}),
            impact="Unsigned packages can allow malicious code substitution during delivery." if unsigned else "Package integrity controls were observed.",
            remediation="Require package signatures, checksum verification, and verified release manifests.",
            evidence_bundle=evidence_bundle,
            execution_proved=False,
        )

    def run(self, state: Dict[str, Any]):
        url = state.get("url") or state.get("target") or state.get("repo_url") or state.get("repository_url")
        repo_url = state.get("repo_url") or state.get("repository_url")
        body = state.get("body") or state.get("request_body") or {}

        results: List[ValidationResult] = []
        if url:
            deserialization = self.check_deserialization(str(url), body, state.get("oob_observer"))
            if deserialization:
                results.append(deserialization)
        if repo_url:
            package_check = self.check_unsigned_packages(str(repo_url), state.get("manifest_text"))
            if package_check:
                results.append(package_check)

        if not results:
            return None
        return results if len(results) > 1 else results[0]
