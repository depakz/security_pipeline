from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .cve_mapper import CVEMapper
from .graph_builder import DAGGraph, GraphBuilder
from .kb import ValidatorSpec, get_default_validator_specs
from validators.http import MissingSecurityHeadersValidator
from validators.redis import RedisNoAuthValidator


VALIDATOR_CLASS_MAP = {
    "validators.redis.RedisNoAuthValidator": RedisNoAuthValidator,
    "validators.http.MissingSecurityHeadersValidator": MissingSecurityHeadersValidator,
}


@dataclass
class DAGPlan:
    graph: DAGGraph
    ordered_nodes: List[str] = field(default_factory=list)
    validators: List[Any] = field(default_factory=list)


@dataclass
class CVEValidationPlan:
    """Plan for CVE-specific validation runs"""
    cve_to_validators: Dict[str, List[str]] = field(default_factory=dict)  # CVE ID → validator IDs
    cve_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # CVE ID → metadata
    validator_instances: Dict[str, Any] = field(default_factory=dict)  # validator ID → instance


class DAGBrain:
    def __init__(self, validator_specs: Optional[List[ValidatorSpec]] = None):
        self.validator_specs = validator_specs or get_default_validator_specs()
        self.graph_builder = GraphBuilder()
        self.cve_mapper = CVEMapper()

    def build_graph(self, state: Dict[str, Any]) -> DAGGraph:
        return self.graph_builder.build(state, self.validator_specs)

    def plan_validations(self, state: Dict[str, Any]) -> DAGPlan:
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

            validators.append(validator_cls())

        return DAGPlan(graph=graph, ordered_nodes=ordered_nodes, validators=validators)

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
        # Map CVEs to their applicable validators
        cve_to_validators = self.cve_mapper.map_findings_to_cves(findings)
        
        # Build validator instances (only for validators needed by CVEs)
        validator_instances: Dict[str, Any] = {}
        needed_validator_ids = set()
        
        for cve_id, validator_ids in cve_to_validators.items():
            needed_validator_ids.update(validator_ids)
        
        # Create instances for needed validators
        for spec in self.validator_specs:
            if spec.id in needed_validator_ids:
                validator_cls = VALIDATOR_CLASS_MAP.get(spec.class_path)
                if validator_cls:
                    validator_instances[spec.id] = validator_cls()
        
        # Get CVE metadata for reporting
        cve_details = {}
        for cve_id in cve_to_validators.keys():
            cve_details[cve_id] = self.cve_mapper.get_cve_verdict_data(cve_id)
        
        return CVEValidationPlan(
            cve_to_validators=cve_to_validators,
            cve_details=cve_details,
            validator_instances=validator_instances,
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