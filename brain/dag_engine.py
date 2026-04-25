from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from engine.models import ExecutionContext

from .cve_mapper import CVEMapper
from .graph_builder import DAGGraph, GraphBuilder, GraphEngineAdapter
from .kb import ValidatorSpec, get_default_validator_specs
from validators.auth import AuthValidator
from validators.crypto import CryptoValidator
from validators.deserialization import InsecureDeserializationValidator
from validators.ftp import FTPAnonymousLoginValidator
from validators.http import MissingSecurityHeadersValidator
from validators.idor import IDORValidator
from validators.logging import LoggingValidator
from validators.redis import RedisNoAuthValidator
from validators.ssrf import SSRFValidator


VALIDATOR_CLASS_MAP = {
    "validators.redis.RedisNoAuthValidator": RedisNoAuthValidator,
    "validators.http.MissingSecurityHeadersValidator": MissingSecurityHeadersValidator,
    "validators.crypto.CryptoValidator": CryptoValidator,
    "validators.auth.AuthValidator": AuthValidator,
    "validators.logging.LoggingValidator": LoggingValidator,
    "validators.ssrf.SSRFValidator": SSRFValidator,
    "validators.ftp.FTPAnonymousLoginValidator": FTPAnonymousLoginValidator,
    "validators.idor.IDORValidator": IDORValidator,
    "validators.deserialization.InsecureDeserializationValidator": InsecureDeserializationValidator,
}


@dataclass
class DAGPlan:
    graph: DAGGraph
    ordered_nodes: List[str] = field(default_factory=list)
    validators: List[Any] = field(default_factory=list)
    context: Optional[ExecutionContext] = None


@dataclass
class CVEValidationPlan:
    """Plan for CVE-specific validation runs"""

    cve_to_validators: Dict[str, List[str]] = field(default_factory=dict)  # CVE ID → validator IDs
    cve_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # CVE ID → metadata
    validator_instances: Dict[str, Any] = field(default_factory=dict)  # validator ID → instance
    context_validator_ids: List[str] = field(default_factory=list)  # validators selected via context rules


class DAGBrain:
    def __init__(self, validator_specs: Optional[List[ValidatorSpec]] = None, use_graph_engine: bool = False):
        self.validator_specs = validator_specs or get_default_validator_specs()
        # Allow optional use of GraphEngine via adapter without breaking API
        if use_graph_engine:
            self.graph_builder = GraphEngineAdapter()
        else:
            self.graph_builder = GraphBuilder()
        self.cve_mapper = CVEMapper()

    def build_graph(self, state: Dict[str, Any]) -> DAGGraph:
        return self.graph_builder.build(state, self.validator_specs)

    def _instantiate_validator(self, validator_cls, *, spec: Optional[ValidatorSpec], context: ExecutionContext):
        # Prefer explicit context injection, but remain backward compatible.
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

            validators.append(self._instantiate_validator(validator_cls, spec=spec, context=context))

        return DAGPlan(graph=graph, ordered_nodes=ordered_nodes, validators=validators, context=context)

    def plan_cve_validations(
        self,
        state: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> CVEValidationPlan:
        """
        Plan which validators to run for each discovered CVE.

        Args:
            state: Target state (target, ports, protocols, etc.)
            findings: List of findings from scanner results

        Returns:
            CVEValidationPlan with CVE→validator mappings and instances
        """
        state_for_planning = dict(state) if isinstance(state, dict) else {}
        state_for_planning["findings"] = findings or []

        context = ExecutionContext.from_state(state_for_planning)

        # Map CVEs to their applicable validators (scanner-assisted)
        cve_to_validators = self.cve_mapper.map_findings_to_cves(findings)

        needed_validator_ids = set()
        for validator_ids in cve_to_validators.values():
            needed_validator_ids.update([v for v in validator_ids if isinstance(v, str)])

        # Context-based rules: include validators matching ports/protocols/keywords even if no CVE.
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

        # Create instances for needed validators
        validator_instances: Dict[str, Any] = {}
        for spec in self.validator_specs:
            if spec.id not in needed_validator_ids:
                continue

            validator_cls = VALIDATOR_CLASS_MAP.get(spec.class_path)
            if not validator_cls:
                continue

            validator_instances[spec.id] = self._instantiate_validator(validator_cls, spec=spec, context=context)

        # Get CVE metadata for reporting
        cve_details: Dict[str, Dict[str, Any]] = {}
        for cve_id in cve_to_validators.keys():
            cve_details[cve_id] = self.cve_mapper.get_cve_verdict_data(cve_id)

        return CVEValidationPlan(
            cve_to_validators=cve_to_validators,
            cve_details=cve_details,
            validator_instances=validator_instances,
            context_validator_ids=context_validator_ids,
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
            "edges": [{"from": source, "to": target} for source, target in plan.graph.edges],
            "ordered_nodes": plan.ordered_nodes,
            "validators": [validator.__class__.__name__ for validator in plan.validators],
        }