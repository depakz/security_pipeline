from __future__ import annotations

import heapq
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple

from .kb import ValidatorSpec, extract_keywords


@dataclass
class DAGNode:
    id: str
    kind: str
    label: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DAGGraph:
    nodes: Dict[str, DAGNode] = field(default_factory=dict)
    edges: List[Tuple[str, str]] = field(default_factory=list)

    def add_node(self, node: DAGNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, source: str, target: str) -> None:
        if source == target:
            return
        edge = (source, target)
        if edge not in self.edges:
            self.edges.append(edge)


class GraphBuilder:
    def build(self, state: Dict[str, Any], validator_specs: Iterable[ValidatorSpec]) -> DAGGraph:
        graph = DAGGraph()
        target = (state.get("target") or "unknown-target").strip() or "unknown-target"

        root_id = f"target:{target}"
        graph.add_node(DAGNode(id=root_id, kind="root", label=target, data={"target": target}))

        ports = self._collect_ports(state)
        protocols = self._collect_protocols(state)
        finding_keywords = self._collect_keywords(state)

        for port in ports:
            port_id = f"port:{port}"
            graph.add_node(DAGNode(id=port_id, kind="discovery", label=f"Port {port}", data={"port": port}))
            graph.add_edge(root_id, port_id)

        for protocol in protocols:
            protocol_id = f"protocol:{protocol}"
            graph.add_node(DAGNode(id=protocol_id, kind="discovery", label=protocol.upper(), data={"protocol": protocol}))
            graph.add_edge(root_id, protocol_id)

        for spec in validator_specs:
            if not self._matches(spec, ports, protocols, finding_keywords):
                continue

            node_id = f"validator:{spec.id}"
            graph.add_node(
                DAGNode(
                    id=node_id,
                    kind="validator",
                    label=spec.name,
                    data={"spec": spec},
                )
            )

            graph.add_edge(root_id, node_id)
            for port in spec.required_ports:
                graph.add_edge(f"port:{port}", node_id)
            for protocol in spec.required_protocols:
                graph.add_edge(f"protocol:{protocol}", node_id)

        return graph

    def topological_sort(self, graph: DAGGraph) -> List[str]:
        incoming = defaultdict(int)
        outgoing = defaultdict(list)

        for source, target in graph.edges:
            outgoing[source].append(target)
            incoming[target] += 1
            incoming.setdefault(source, 0)

        def _priority(node_id: str) -> int:
            node = graph.nodes.get(node_id)
            if not node or node.kind != "validator":
                return 0

            spec = node.data.get("spec")
            try:
                return int(getattr(spec, "priority", 0) or 0)
            except Exception:
                return 0

        heap: List[Tuple[int, str]] = []
        for node_id in graph.nodes:
            if incoming.get(node_id, 0) == 0:
                heapq.heappush(heap, (-_priority(node_id), node_id))

        ordered: List[str] = []

        while heap:
            _, node_id = heapq.heappop(heap)
            ordered.append(node_id)
            for next_id in outgoing.get(node_id, []):
                incoming[next_id] -= 1
                if incoming[next_id] == 0:
                    heapq.heappush(heap, (-_priority(next_id), next_id))

        if len(ordered) != len(graph.nodes):
            raise ValueError("Graph contains a cycle or unresolved dependency")

        return ordered

    def _matches(self, spec: ValidatorSpec, ports: List[int], protocols: List[str], keywords: List[str]) -> bool:
        if spec.required_ports and not any(port in ports for port in spec.required_ports):
            return False
        if spec.required_protocols and not any(protocol in protocols for protocol in spec.required_protocols):
            return False
        if spec.keywords:
            combined = " ".join(keywords)
            if not any(keyword in combined for keyword in spec.keywords):
                return False
        return True

    def _collect_ports(self, state: Dict[str, Any]) -> List[int]:
        ports = state.get("ports", []) or []
        return sorted({int(port) for port in ports if isinstance(port, int) or str(port).isdigit()})

    def _collect_protocols(self, state: Dict[str, Any]) -> List[str]:
        protocols = state.get("protocols", []) or []
        return sorted({str(protocol).lower().strip() for protocol in protocols if protocol})

    def _collect_keywords(self, state: Dict[str, Any]) -> List[str]:
        keywords = extract_keywords(state)
        findings = state.get("findings", []) or []
        for finding in findings:
            keywords.extend(extract_keywords(finding))
        return [keyword for keyword in keywords if keyword]