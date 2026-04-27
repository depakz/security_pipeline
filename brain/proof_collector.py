from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Dict, List, Optional


def _is_confirmed(result: Dict[str, Any]) -> bool:
    if result.get("success") is True:
        return True
    status = ((result.get("validation") or {}).get("status") or "").strip().lower()
    return status == "confirmed"


def _safe_excerpt(value: Any, limit: int = 800) -> str:
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


@dataclass
class ProofRecord:
    proof_id: str
    validator_id: str
    vulnerability: str
    confirmed: bool
    proof_kind: str
    proof_strength: float
    summary: str
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "validator_id": self.validator_id,
            "vulnerability": self.vulnerability,
            "confirmed": self.confirmed,
            "proof_kind": self.proof_kind,
            "proof_strength": self.proof_strength,
            "summary": self.summary,
            "artifacts": self.artifacts,
            "metadata": self.metadata,
        }


class ProofCollector:
    """Normalize validation outputs into proof-oriented records."""

    def _extract_artifacts(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        artifacts: List[Dict[str, Any]] = []
        evidence = result.get("evidence") or {}
        if isinstance(evidence, dict):
            matched = evidence.get("matched")
            if matched:
                artifacts.append({"type": "matched_indicator", "value": matched})

            response = evidence.get("response")
            if response is not None:
                artifacts.append({"type": "response", "value": _safe_excerpt(response)})

            request = evidence.get("request")
            if request is not None:
                artifacts.append({"type": "request", "value": _safe_excerpt(request)})

            extra = evidence.get("extra")
            if isinstance(extra, dict) and extra:
                artifacts.append({"type": "extra", "value": extra})

        bundle = result.get("evidence_bundle") or {}
        if isinstance(bundle, dict):
            raw_request = bundle.get("raw_request")
            raw_response = bundle.get("raw_response")
            execution_proof = bundle.get("execution_proof")
            if raw_request:
                artifacts.append({"type": "raw_request", "value": _safe_excerpt(raw_request)})
            if raw_response:
                artifacts.append({"type": "raw_response", "value": _safe_excerpt(raw_response)})
            if isinstance(execution_proof, dict) and execution_proof:
                artifacts.append({"type": "execution_proof", "value": execution_proof})

        return artifacts

    def _proof_kind(self, result: Dict[str, Any]) -> str:
        bundle = result.get("evidence_bundle") or {}
        if isinstance(bundle, dict) and isinstance(bundle.get("execution_proof"), dict) and bundle.get("execution_proof"):
            return "execution_proof"

        validation = result.get("validation") or {}
        if isinstance(validation, dict) and validation.get("execution_proved"):
            return "execution_proved"

        evidence = result.get("evidence") or {}
        if isinstance(evidence, dict) and (evidence.get("matched") or evidence.get("extra")):
            return "observed_response"

        return "confirmation_signal"

    def _proof_strength(self, result: Dict[str, Any], confirmed: bool, proof_kind: str) -> float:
        validation = result.get("validation") or {}
        confidence = float(validation.get("confidence_score", validation.get("confidence", 0.0)) or 0.0)

        if not confirmed:
            return 0.0
        if proof_kind == "execution_proof":
            return min(1.0, max(0.9, confidence))
        if proof_kind == "execution_proved":
            return min(1.0, max(0.88, confidence))
        if proof_kind == "observed_response":
            return min(1.0, max(0.75, confidence))
        return min(1.0, max(0.6, confidence))

    def collect(self, result: Dict[str, Any]) -> Optional[ProofRecord]:
        if not isinstance(result, dict):
            return None

        confirmed = _is_confirmed(result)
        validation = result.get("validation") or {}
        validator_id = str(result.get("validator_id") or result.get("vulnerability") or "unknown")
        vulnerability = str(result.get("vulnerability") or "unknown")
        proof_kind = self._proof_kind(result)
        proof_strength = self._proof_strength(result, confirmed, proof_kind)

        proof_id = sha256(f"{validator_id}|{vulnerability}|{proof_kind}|{confirmed}".encode()).hexdigest()[:16]
        artifacts = self._extract_artifacts(result)
        summary = (
            f"{vulnerability} confirmed via {proof_kind}"
            if confirmed
            else f"{vulnerability} not confirmed; collected {proof_kind} signals"
        )

        metadata = {
            "severity": result.get("severity") or validation.get("severity") or "info",
            "confidence": validation.get("confidence_score", validation.get("confidence", 0.0)),
            "execution_proved": bool(validation.get("execution_proved")),
        }

        return ProofRecord(
            proof_id=proof_id,
            validator_id=validator_id,
            vulnerability=vulnerability,
            confirmed=confirmed,
            proof_kind=proof_kind,
            proof_strength=round(float(proof_strength), 3),
            summary=summary,
            artifacts=artifacts,
            metadata=metadata,
        )

    def attach(self, result: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(result, dict):
            return result

        proof = self.collect(result)
        if proof is None:
            return result

        enriched = dict(result)
        enriched["proof"] = proof.to_dict()
        enriched.setdefault("proof_strength", proof.proof_strength)
        enriched.setdefault("proof_kind", proof.proof_kind)
        if proof.confirmed:
            validation = dict(enriched.get("validation") or {})
            validation.setdefault("status", "confirmed")
            validation.setdefault("confidence_score", proof.proof_strength)
            enriched["validation"] = validation
        return enriched

    def append_to_state(self, state: Dict[str, Any], result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(state, dict) or not isinstance(result, dict):
            return None

        proof = self.collect(result)
        if proof is None:
            return None

        proofs = state.setdefault("proofs", [])
        if isinstance(proofs, list):
            proofs.append(proof.to_dict())

        if proof.confirmed:
            confirmed_proofs = state.setdefault("confirmed_proofs", [])
            if isinstance(confirmed_proofs, list):
                confirmed_proofs.append(proof.to_dict())

        return proof.to_dict()
