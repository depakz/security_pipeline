"""
Enhanced DAGEngine: Intelligent DAG Planning with Dynamic Chain Injection

This module extends the original DAG engine to support:
1. Dynamic exploitation node injection based on successful validations
2. Fact store querying to determine node readiness
3. Endpoint pattern deduplication
4. Attack chain management
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable

from engine.models import ExecutionContext
from brain.fact_store import FactStore
from brain.endpoint_normalizer import EndpointNormalizer
from brain.attack_chain_manager import AttackChainManager, ChainedExploitationNode

from .cve_mapper import CVEMapper
from .graph_builder import DAGGraph, GraphBuilder, GraphEngineAdapter
from .kb import ValidatorSpec, get_default_validator_specs
from validators.ftp import FTPAnonymousLoginValidator
from validators.http import MissingSecurityHeadersValidator
from validators.redis import RedisNoAuthValidator


VALIDATOR_CLASS_MAP = {
    "validators.redis.RedisNoAuthValidator": RedisNoAuthValidator,
    "validators.http.MissingSecurityHeadersValidator": MissingSecurityHeadersValidator,
    "validators.ftp.FTPAnonymousLoginValidator": FTPAnonymousLoginValidator,
}


@dataclass
class DAGPlan:
    graph: DAGGraph
    ordered_nodes: List[str] = field(default_factory=list)
    validators: List[Any] = field(default_factory=list)
    context: Optional[ExecutionContext] = None
    fact_store: Optional[FactStore] = None  # Centralized state
    endpoint_normalizer: Optional[EndpointNormalizer] = None  # Deduplication
    attack_chain_manager: Optional[AttackChainManager] = None  # Dynamic chains


@dataclass
class CVEValidationPlan:
    """Plan for CVE-specific validation runs"""

    cve_to_validators: Dict[str, List[str]] = field(default_factory=dict)
    cve_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    validator_instances: Dict[str, Any] = field(default_factory=dict)
    context_validator_ids: List[str] = field(default_factory=list)
    fact_store: Optional[FactStore] = None
    endpoint_normalizer: Optional[EndpointNormalizer] = None
    attack_chain_manager: Optional[AttackChainManager] = None


class DAGBrain:
    """
    Enhanced DAG engine with support for:
    - Fact store for state management
    - Endpoint deduplication
    - Attack chain management
    """

    def __init__(
        self,
        validator_specs: Optional[List[ValidatorSpec]] = None,
        use_graph_engine: bool = False,
        fact_store: Optional[FactStore] = None,
        endpoint_normalizer: Optional[EndpointNormalizer] = None,
    ):
        self.validator_specs = validator_specs or get_default_validator_specs()
        if use_graph_engine:
            self.graph_builder = GraphEngineAdapter()
        else:
            self.graph_builder = GraphBuilder()
        self.cve_mapper = CVEMapper()

        # New: Enhanced state management
        self.fact_store = fact_store or FactStore()
        self.endpoint_normalizer = endpoint_normalizer or EndpointNormalizer()
        self.attack_chain_manager = AttackChainManager(self.fact_store)
        self.injected_nodes: Dict[str, ChainedExploitationNode] = {}

    def build_graph(self, state: Dict[str, Any]) -> DAGGraph:
        return self.graph_builder.build(state, self.validator_specs)

    def _instantiate_validator(
        self,
        validator_cls,
        *,
        spec: Optional[ValidatorSpec],
        context: ExecutionContext,
    ):
        try:
            instance = validator_cls(context=context)
        except TypeError:
            instance = validator_cls()

        for attr in ("context", "execution_context"):
            try:
                setattr(instance, attr, context)
            except Exception:
                pass

        if spec is not None:
            try:
                setattr(instance, "validator_id", spec.id)
            except Exception:
                pass
            try:
                setattr(instance, "priority", int(getattr(spec, "priority", 0) or 0))
            except Exception:
                pass

        return instance

    def plan_validations(self, state: Dict[str, Any]) -> DAGPlan:
        """
        Plan validations with support for:
        1. Fact store queries
        2. Endpoint deduplication
        3. Attack chain management
        """
        context = ExecutionContext.from_state(state)
        graph = self.build_graph(state)
        ordered_nodes = self.graph_builder.topological_sort(graph)

        validators: List[Any] = []
        for node_id in ordered_nodes:
            node = graph.nodes.get(node_id)
            if not node or node.kind != "validator":
                continue

            spec = node.data.get("spec")
            if not spec:
                continue

            validator_cls = VALIDATOR_CLASS_MAP.get(spec.class_path)
            if not validator_cls:
                continue

            validators.append(
                self._instantiate_validator(validator_cls, spec=spec, context=context)
            )

        plan = DAGPlan(
            graph=graph,
            ordered_nodes=ordered_nodes,
            validators=validators,
            context=context,
            fact_store=self.fact_store,
            endpoint_normalizer=self.endpoint_normalizer,
            attack_chain_manager=self.attack_chain_manager,
        )

        return plan

    def register_chain_injection_callback(
        self, callback: Callable[[ChainedExploitationNode], None]
    ) -> None:
        """
        Register callback to be invoked when exploitation nodes should be injected.

        Args:
            callback: Function signature: callback(node: ChainedExploitationNode) -> None
        """
        self.attack_chain_manager.register_chain_callback(callback)

    def inject_exploitation_nodes(
        self, parent_validator_id: str
    ) -> List[ChainedExploitationNode]:
        """
        Notify the chain manager that a validator succeeded, and get
        any exploitation nodes that should be dynamically injected.

        Args:
            parent_validator_id: ID of the validator that succeeded

        Returns:
            List of ChainedExploitationNode to inject into DAG
        """
        self.attack_chain_manager.validator_completed(parent_validator_id)
        return self.attack_chain_manager.get_pending_exploitation_nodes()

    def should_skip_endpoint(
        self, endpoint: str, vulnerability_type: Optional[str] = None
    ) -> bool:
        """
        Check if an endpoint should be skipped due to pattern deduplication.

        Args:
            endpoint: URL to check
            vulnerability_type: Type of vulnerability being tested (e.g., "xss")

        Returns:
            True if pattern already scanned, False otherwise
        """
        return self.endpoint_normalizer.should_skip_scan(endpoint, vulnerability_type)

    def mark_endpoint_pattern_scanned(
        self, endpoint: str, vulnerability_type: Optional[str] = None
    ) -> None:
        """Mark an endpoint pattern as scanned."""
        pattern_key, _ = self.endpoint_normalizer.register_endpoint(
            endpoint, vulnerability_type
        )
        self.endpoint_normalizer.mark_pattern_scanned(pattern_key)

    def plan_cve_validations(
        self,
        state: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> CVEValidationPlan:
        """
        Plan CVE validations with fact store and deduplication support.
        """
        state_for_planning = dict(state) if isinstance(state, dict) else {}
        state_for_planning["findings"] = findings or []

        context = ExecutionContext.from_state(state_for_planning)

        cve_to_validators = self.cve_mapper.map_findings_to_cves(findings)

        needed_validator_ids = set()
        for validator_ids in cve_to_validators.values():
            needed_validator_ids.update([v for v in validator_ids if isinstance(v, str)])

        context_validator_ids: List[str] = []
        try:
            context_graph = self.build_graph(state_for_planning)
            context_order = self.graph_builder.topological_sort(context_graph)
            for node_id in context_order:
                node = context_graph.nodes.get(node_id)
                if not node or node.kind != "validator":
                    continue

                spec = node.data.get("spec")
                if not spec:
                    continue

                context_validator_ids.append(spec.id)
                needed_validator_ids.add(spec.id)
        except Exception:
            context_validator_ids = []

        validator_instances: Dict[str, Any] = {}
        for spec in self.validator_specs:
            if spec.id not in needed_validator_ids:
                continue

            validator_cls = VALIDATOR_CLASS_MAP.get(spec.class_path)
            if not validator_cls:
                continue

            validator_instances[spec.id] = self._instantiate_validator(
                validator_cls, spec=spec, context=context
            )

        cve_details: Dict[str, Dict[str, Any]] = {}
        for cve_id in cve_to_validators.keys():
            cve_details[cve_id] = self.cve_mapper.get_cve_verdict_data(cve_id)

        return CVEValidationPlan(
            cve_to_validators=cve_to_validators,
            cve_details=cve_details,
            validator_instances=validator_instances,
            context_validator_ids=context_validator_ids,
            fact_store=self.fact_store,
            endpoint_normalizer=self.endpoint_normalizer,
            attack_chain_manager=self.attack_chain_manager,
        )

    def describe(self, state: Dict[str, Any]) -> Dict[str, Any]:
        plan = self.plan_validations(state)
        return {
            "nodes": [
                {
                    "id": node.id,
                    "kind": node.kind,
                    "label": node.label,
                    "data": {k: v for k, v in node.data.items() if k != "spec"},
                }
                for node in plan.graph.nodes.values()
            ],
            "edges": [
                {"from": source, "to": target}
                for source, target in plan.graph.edges
            ],
            "ordered_nodes": plan.ordered_nodes,
            "validators": [validator.__class__.__name__ for validator in plan.validators],
            "fact_store_summary": self.fact_store.get_summary(),
            "endpoint_deduplication_stats": self.endpoint_normalizer.get_pattern_stats(),
        }

    def get_engine_state(self) -> Dict[str, Any]:
        """Export current engine state for debugging and analysis."""
        return {
            "fact_store": self.fact_store.export(),
            "endpoint_patterns": self.endpoint_normalizer.export(),
            "active_chains": self.attack_chain_manager.get_active_chains(),
            "chain_statistics": self.attack_chain_manager.get_chain_statistics(),
        }
