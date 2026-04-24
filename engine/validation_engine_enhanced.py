"""
Enhanced ValidationEngine: Result Processing with Chain Reactions and Fact Store Updates

This module implements intelligent result processing that:
1. Updates the fact store with discovered prerequisites
2. Triggers attack chain evaluations
3. Applies endpoint deduplication
4. Manages high-confidence vs low-confidence validations
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Callable
from engine.models import ExecutionContext, ValidationResult
from brain.fact_store import FactStore, FactCategory, Fact, PrerequisiteQuery
from brain.endpoint_normalizer import EndpointNormalizer
from brain.attack_chain_manager import AttackChainManager, ChainedExploitationNode
from utils.logger import logger


def _is_confirmed(result: Dict[str, Any]) -> bool:
    if result.get("success") is True:
        return True
    status = ((result.get("validation") or {}).get("status") or "").strip().lower()
    return status == "confirmed"


def _confirmed_key(result: Dict[str, Any]) -> Tuple[Any, Any]:
    return (result.get("validator_id"), result.get("vulnerability"))


class ValidationResultProcessor:
    """
    Intelligent validation result processor that:
    1. Extracts facts and updates fact store
    2. Triggers attack chains
    3. Injects exploitation nodes
    4. Applies deduplication logic
    """

    def __init__(
        self,
        fact_store: FactStore,
        endpoint_normalizer: Optional[EndpointNormalizer] = None,
        attack_chain_manager: Optional[AttackChainManager] = None,
    ):
        self.fact_store = fact_store
        self.endpoint_normalizer = endpoint_normalizer or EndpointNormalizer()
        self.attack_chain_manager = attack_chain_manager
        self.extraction_rules: Dict[str, Callable[[Dict], List[Fact]]] = {}
        self._register_default_extraction_rules()

    def _register_default_extraction_rules(self) -> None:
        """Register extraction rules for common vulnerability types."""

        def extract_creds_from_leak(result: Dict[str, Any]) -> List[Fact]:
            """Extract credentials from credential leak findings."""
            facts = []
            evidence = result.get("evidence", {})
            if isinstance(evidence, dict):
                # Try to parse credentials from response
                response = evidence.get("response", "")
                if isinstance(response, dict):
                    username = response.get("username")
                    password = response.get("password")
                    if username and password:
                        fact = self.fact_store.add_credential(
                            username=username,
                            password=password,
                            source_validator_id=result.get("validator_id"),
                            confidence=result.get("validation", {}).get(
                                "confidence_score", 0.9
                            ),
                        )
                        facts.append(fact)
            return facts

        def extract_service_info(result: Dict[str, Any]) -> List[Fact]:
            """Extract service information from discovery results."""
            facts = []
            evidence = result.get("evidence", {})
            if isinstance(evidence, dict):
                response = evidence.get("response", {})
                if isinstance(response, dict):
                    service_name = response.get("server") or response.get("service")
                    version = response.get("version")
                    if service_name:
                        metadata = {"version": version} if version else {}
                        fact = Fact(
                            category=FactCategory.SERVICE_INFO,
                            key=f"{service_name}:{version or 'unknown'}",
                            value={
                                "service": service_name,
                                "version": version,
                            },
                            confidence=0.85,
                            source_validator_id=result.get("validator_id"),
                            metadata=metadata,
                        )
                        self.fact_store.add_fact(fact)
                        facts.append(fact)
            return facts

        def extract_internal_host(result: Dict[str, Any]) -> List[Fact]:
            """Extract internal host information from SSRF/LFI findings."""
            facts = []
            evidence = result.get("evidence", {})
            if isinstance(evidence, dict):
                matched = evidence.get("matched", "")
                if isinstance(matched, str) and (
                    "192.168." in matched or "10." in matched or "172." in matched
                ):
                    fact = self.fact_store.add_internal_host(
                        hostname=matched,
                        source_validator_id=result.get("validator_id"),
                        confidence=0.7,
                    )
                    facts.append(fact)
            return facts

        def extract_exploitation_artifact(result: Dict[str, Any]) -> List[Fact]:
            """Extract exploitation artifacts (file contents, shell output, etc.)."""
            facts = []
            evidence_bundle = result.get("evidence_bundle")
            if evidence_bundle and isinstance(evidence_bundle, dict):
                execution_proof = evidence_bundle.get("execution_proof", {})
                if execution_proof:
                    artifact_type = list(execution_proof.keys())[0]
                    content = execution_proof[artifact_type]
                    fact = self.fact_store.add_exploitation_artifact(
                        artifact_id=f"{result.get('validator_id')}_artifact",
                        artifact_type=artifact_type,
                        content=str(content),
                        source_vulnerability=result.get("vulnerability"),
                        confidence=result.get("validation", {}).get(
                            "confidence_score", 0.9
                        ),
                    )
                    facts.append(fact)
            return facts

        self.extraction_rules["credential_leak"] = extract_creds_from_leak
        self.extraction_rules["service_discovery"] = extract_service_info
        self.extraction_rules["ssrf"] = extract_internal_host
        self.extraction_rules["lfi"] = extract_internal_host
        self.extraction_rules["rce"] = extract_exploitation_artifact

    def register_extraction_rule(
        self, vulnerability_type: str, rule: Callable[[Dict], List[Fact]]
    ) -> None:
        """Register a custom fact extraction rule."""
        self.extraction_rules[vulnerability_type] = rule

    def extract_facts_from_result(
        self, result: Dict[str, Any]
    ) -> List[Fact]:
        """
        Extract facts from validation results using registered rules.

        Args:
            result: Validation result dictionary

        Returns:
            List of facts extracted and added to fact store
        """
        if not _is_confirmed(result):
            return []

        vuln_type = result.get("vulnerability", "").lower()
        facts = []

        # Try registered extraction rule
        if vuln_type in self.extraction_rules:
            try:
                rule_facts = self.extraction_rules[vuln_type](result)
                facts.extend(rule_facts)
            except Exception as e:
                logger.warning(f"Error in extraction rule for {vuln_type}: {e}")

        # Always store a confirmed vulnerability fact
        vuln_fact = self.fact_store.add_confirmed_vulnerability(
            vuln_id=f"{result.get('validator_id')}_{vuln_type}",
            vuln_type=vuln_type,
            target=result.get("target", "unknown"),
            confidence=result.get("validation", {}).get("confidence_score", 0.9),
            source_validator_id=result.get("validator_id"),
            metadata={
                "evidence": result.get("evidence", {}),
                "chain_source": result.get("chain_source"),
            },
        )
        facts.append(vuln_fact)

        return facts

    def process_result(
        self, result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process a validation result through the enhanced pipeline:

        1. Extract facts and update fact store
        2. Notify attack chain manager
        3. Return enhanced result with chain recommendations

        Args:
            result: Validation result from validator

        Returns:
            Enhanced result with chain injection recommendations
        """
        if not _is_confirmed(result):
            return result

        # Extract and store facts
        facts = self.extract_facts_from_result(result)

        # Notify chain manager
        validator_id = result.get("validator_id")
        if validator_id and self.attack_chain_manager:
            self.attack_chain_manager.validator_completed(validator_id)
            pending_nodes = (
                self.attack_chain_manager.get_pending_exploitation_nodes()
            )

            if pending_nodes:
                result["injected_nodes"] = [node.to_dict() for node in pending_nodes]

        # Add chain recommendations based on facts
        result["extracted_facts"] = [fact.to_dict() for fact in facts]

        return result


class ValidationEngine:
    """
    Enhanced validation runner with support for:
    1. Fact store updates
    2. Attack chain management
    3. Endpoint deduplication
    4. High-confidence validation
    """

    def __init__(
        self,
        fact_store: Optional[FactStore] = None,
        endpoint_normalizer: Optional[EndpointNormalizer] = None,
        attack_chain_manager: Optional[AttackChainManager] = None,
    ):
        self.validators: List[Any] = []
        self.fact_store = fact_store or FactStore()
        self.endpoint_normalizer = endpoint_normalizer or EndpointNormalizer()
        self.attack_chain_manager = attack_chain_manager or AttackChainManager(
            self.fact_store
        )
        self.result_processor = ValidationResultProcessor(
            self.fact_store,
            self.endpoint_normalizer,
            self.attack_chain_manager,
        )

    def register(self, validator) -> None:
        self.validators.append(validator)

    def run(
        self,
        plan_or_state: Any,
        state: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Enhanced validator runner with fact store and deduplication.

        Args:
            plan_or_state: DAGPlan or state dict
            state: State dict (if plan provided as first arg)

        Returns:
            List of validation results with injected facts and chain recommendations
        """
        plan_mode = state is not None
        if state is None:
            state = plan_or_state
            validators = list(self.validators)
            validators.sort(
                key=lambda v: int(getattr(v, "priority", 0) or 0), reverse=True
            )
        else:
            plan = plan_or_state
            validators = list(getattr(plan, "validators", []) or [])

            # Use enhanced components from plan if available
            if hasattr(plan, "fact_store") and plan.fact_store:
                self.fact_store = plan.fact_store
            if hasattr(plan, "endpoint_normalizer") and plan.endpoint_normalizer:
                self.endpoint_normalizer = plan.endpoint_normalizer
            if hasattr(plan, "attack_chain_manager") and plan.attack_chain_manager:
                self.attack_chain_manager = plan.attack_chain_manager
                self.result_processor.attack_chain_manager = plan.attack_chain_manager

        if not isinstance(state, dict):
            return []

        context = ExecutionContext.from_state(state)
        findings: List[Dict[str, Any]] = []

        confirmed_validator_ids = set()
        if plan_mode:
            confirmed_vulns = state.get("confirmed_vulns") or []
            if isinstance(confirmed_vulns, list):
                for r in confirmed_vulns:
                    if not isinstance(r, dict) or not _is_confirmed(r):
                        continue
                    vid = r.get("validator_id")
                    if isinstance(vid, str) and vid:
                        confirmed_validator_ids.add(vid)

        for validator in validators:
            try:
                if getattr(validator, "destructive", False):
                    logger.warning(
                        f"Skipping destructive validator: "
                        f"{getattr(validator, 'validator_id', validator.__class__.__name__)}"
                    )
                    findings.append(
                        {
                            "success": False,
                            "vulnerability": getattr(
                                validator, "validator_id", validator.__class__.__name__
                            ),
                            "error": "validator_marked_destructive",
                        }
                    )
                    continue

                if not hasattr(validator, "can_run") or not hasattr(validator, "run"):
                    continue

                validator_id = (
                    getattr(validator, "validator_id", None)
                    or getattr(validator, "id", None)
                )
                validator_class = validator.__class__.__name__

                for attr in ("context", "execution_context"):
                    try:
                        if getattr(validator, attr, None) is None:
                            setattr(validator, attr, context)
                    except Exception:
                        pass

                if plan_mode and isinstance(validator_id, str) and validator_id in confirmed_validator_ids:
                    logger.debug(f"Skipping already-confirmed validator: {validator_id}")
                    continue

                if not validator.can_run(state):
                    continue

                result = validator.run(state)
                if not result:
                    continue

                results = result if isinstance(result, list) else [result]
                for r in results:
                    out = r.to_dict() if hasattr(r, "to_dict") else r
                    if not isinstance(out, dict):
                        continue

                    if validator_id:
                        out.setdefault("validator_id", validator_id)
                    out.setdefault("validator_class", validator_class)

                    if "success" not in out:
                        out["success"] = _is_confirmed(out)

                    pr = getattr(validator, "priority", None)
                    if pr is not None:
                        out.setdefault("priority", pr)

                    # Process result through enhanced pipeline
                    out = self.result_processor.process_result(out)

                    findings.append(out)

            except Exception as e:
                findings.append(
                    {
                        "success": False,
                        "vulnerability": validator.__class__.__name__,
                        "validator_id": (
                            getattr(validator, "validator_id", None)
                            or getattr(validator, "id", None)
                        ),
                        "validator_class": validator.__class__.__name__,
                        "error": str(e),
                    }
                )

        return findings


class StateManager:
    """
    Enhanced state manager with fact store integration.
    """

    def __init__(self, fact_store: Optional[FactStore] = None):
        self.fact_store = fact_store or FactStore()

    def update(self, state: Dict[str, Any], results: List[Dict[str, Any]]) -> int:
        """
        Update state with validation results and fact store.

        Args:
            state: Target state dict
            results: Validation results

        Returns:
            Number of newly confirmed vulnerabilities
        """
        if not isinstance(state, dict):
            return 0

        history = state.setdefault("validation_results", [])
        if not isinstance(history, list):
            history = []
            state["validation_results"] = history

        for r in results:
            if isinstance(r, dict):
                history.append(r)

        confirmed = state.setdefault("confirmed_vulns", [])
        if not isinstance(confirmed, list):
            confirmed = []
            state["confirmed_vulns"] = confirmed

        seen = set()
        for r in confirmed:
            if isinstance(r, dict) and _is_confirmed(r):
                seen.add(_confirmed_key(r))

        new_confirmed = 0
        for r in results:
            if not isinstance(r, dict) or not _is_confirmed(r):
                continue
            key = _confirmed_key(r)
            if key in seen:
                continue
            confirmed.append(r)
            seen.add(key)
            new_confirmed += 1

        signals = state.setdefault("signals", [])
        if not isinstance(signals, list):
            signals = []
            state["signals"] = signals
        for r in results:
            if not isinstance(r, dict) or not _is_confirmed(r):
                continue
            vuln = r.get("vulnerability")
            if isinstance(vuln, str) and vuln not in signals:
                signals.append(vuln)

        # Export fact store state
        state["fact_store_state"] = self.fact_store.export()

        return new_confirmed
