from __future__ import annotations

import os
import sys
from typing import Any, Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from brain.attack_chain_manager import AttackChainManager
from brain.fact_store import FactStore
from brain.proof_collector import ProofCollector
from engine.models import Evidence, EvidenceBundle, ValidationResult
from engine.validation_engine import StateManager, ValidationEngine


class _StubValidator:
    validator_id = "stub_validator"
    priority = 10
    destructive = False

    def can_run(self, state: Dict[str, Any]) -> bool:
        return True

    def run(self, state: Dict[str, Any]):
        return ValidationResult(
            success=True,
            confidence=0.93,
            severity="high",
            vulnerability="stub-vuln",
            evidence=Evidence(
                request={"target": state.get("target")},
                response={"status": "confirmed"},
                matched="status:confirmed",
                extra={"marker": True},
            ),
            evidence_bundle=EvidenceBundle(
                raw_request="POST /probe",
                raw_response="200 OK",
                matched_indicator="status:confirmed",
                execution_proof={"oob_interaction": True},
                metadata={"source": "unit-test"},
            ),
            execution_proved=True,
        )


def test_proof_collector_attaches_execution_proof() -> None:
    collector = ProofCollector()
    result = ValidationResult(
        success=True,
        confidence=0.91,
        severity="high",
        vulnerability="demo-vuln",
        evidence=Evidence(
            request={"target": "https://example.test"},
            response={"body": "confirmed"},
            matched="confirmed",
            extra={"probe": "timing"},
        ),
        evidence_bundle=EvidenceBundle(
            raw_request="GET /demo",
            raw_response="200 OK",
            matched_indicator="confirmed",
            execution_proof={"callback": True},
            metadata={"mode": "test"},
        ),
        execution_proved=True,
    ).to_dict()

    enriched = collector.attach(result)

    assert enriched["proof"]["confirmed"] is True
    assert enriched["proof"]["proof_kind"] == "execution_proof"
    assert enriched["proof"]["proof_strength"] >= 0.9
    assert enriched["proof"]["artifacts"]


def test_validation_engine_persists_proofs_into_state() -> None:
    engine = ValidationEngine()
    engine.register(_StubValidator())

    state: Dict[str, Any] = {"target": "https://example.test", "proofs": [], "confirmed_proofs": []}
    results = engine.run(state)

    assert results
    assert any(result.get("proof") for result in results if isinstance(result, dict))
    assert state["proofs"]
    assert state["confirmed_proofs"]


def test_attack_chain_manager_emits_each_node_once() -> None:
    FactStore.reset()
    fact_store = FactStore()
    fact_store.clear()

    manager = AttackChainManager(fact_store)
    emitted: List[str] = []

    def collect(node) -> None:
        emitted.append(node.node_id)

    manager.register_chain_callback(collect)
    manager.validator_completed("ssrf_validator")
    manager.validator_completed("ssrf_validator")

    assert emitted
    assert len(emitted) == len(set(emitted))
