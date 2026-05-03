from __future__ import annotations

import heapq
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple

from .kb import (
    ValidatorSpec,
    VulnerabilitySpec,
    get_default_vulnerability_specs,
    extract_keywords,
    detect_triggers_from_findings,
    get_chaining_for_trigger,
)


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

        # Create vulnerability nodes and link to validators as mandatory children.
        # A vulnerability node will have child validator nodes when keywords overlap.
        vuln_specs: List[VulnerabilitySpec] = get_default_vulnerability_specs()
        for v in vuln_specs:
            vid = f"vulnerability:{v.id}"
            graph.add_node(DAGNode(id=vid, kind="vulnerability", label=v.title, data={"spec": v}))
            # connect vulnerability node to root
            graph.add_edge(root_id, vid)

            # find matching validators by keyword overlap
            for spec in validator_specs:
                # if any keyword in vulnerability keywords appears in validator keywords
                if not v.keywords or not spec.keywords:
                    continue
                if any(kw in spec.keywords for kw in v.keywords):
                    node_id = f"validator:{spec.id}"
                    # ensure validator node exists and add edge
                    if node_id in graph.nodes:
                        graph.add_edge(vid, node_id)

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


# --- NetworkX-backed runtime graph engine (consolidated from graph_engine.py) ---
try:
    import networkx as nx
except Exception:
    nx = None

from dataclasses import dataclass, field
from typing import Optional, Tuple
import threading


@dataclass
class NodeData:
    id: str
    kind: str
    label: str = ""
    state: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EdgeAction:
    id: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    executed: bool = False
    result: Optional[Dict[str, Any]] = None


class GraphEngine:
    def __init__(self):
        if nx is None:
            raise RuntimeError("networkx is required for GraphEngine. Install networkx.")
        self.graph = nx.DiGraph()
        self.lock = threading.Lock()

    def add_state_node(self, node_id: str, kind: str = "state", label: str = "", **state):
        self.graph.add_node(node_id, data=NodeData(id=node_id, kind=kind, label=label, state=state))

    def add_action_edge(self, src: str, dst: str, edge_id: str, action: str, params: Optional[Dict[str, Any]] = None):
        params = params or {}
        self.graph.add_edge(src, dst, data=EdgeAction(id=edge_id, action=action, params=params))

    def get_ready_edges(self) -> List[Tuple[str, str, EdgeAction]]:
        ready: List[Tuple[str, str, EdgeAction]] = []
        for u, v, d in self.graph.edges(data=True):
            edge: EdgeAction = d.get("data")
            if not edge or edge.executed:
                continue
            node_data: NodeData = self.graph.nodes[u].get("data")
            if node_data is None:
                continue
            if node_data.state.get("active", True):
                ready.append((u, v, edge))
        return ready

    def mark_edge_executed(self, u: str, v: str, result: Optional[Dict[str, Any]] = None):
        with self.lock:
            edge: EdgeAction = self.graph.edges[u, v].get("data")
            if edge:
                edge.executed = True
                edge.result = result or {}

    def inject_loot_into_downstream(self, v: str, loot: Dict[str, Any]):
        with self.lock:
            for _, dst, d in self.graph.out_edges(v, data=True):
                edge: EdgeAction = d.get("data")
                if not edge:
                    continue
                for k, val in loot.items():
                    if k not in edge.params:
                        edge.params[k] = val

    def get_graph_snapshot(self) -> Dict[str, Any]:
        nodes = []
        edges = []
        for n, d in self.graph.nodes(data=True):
            nd: NodeData = d.get("data")
            nodes.append({"id": n, "kind": nd.kind, "label": nd.label, "state": nd.state})
        for u, v, d in self.graph.edges(data=True):
            ea: EdgeAction = d.get("data")
            edges.append({"from": u, "to": v, "id": ea.id, "action": ea.action, "params": ea.params, "executed": ea.executed, "result": ea.result})
        return {"nodes": nodes, "edges": edges}


class GraphEngineAdapter:
    """Adapter to let DAGBrain use a GraphEngine-backed planner while returning
    the legacy DAGGraph structure expected by consumers.
    """

    def __init__(self):
        self.engine: Optional[GraphEngine] = None

    def build(self, state: Dict[str, Any], validator_specs: Iterable[ValidatorSpec]) -> DAGGraph:
        # Build a DAGGraph using the existing GraphBuilder logic, then mirror it
        # into a GraphEngine for runtime execution.
        builder = GraphBuilder()
        dag = builder.build(state, validator_specs)

        # create engine and mirror nodes/edges
        eng = GraphEngine()
        # mirror nodes
        for node_id, node in dag.nodes.items():
            # preserve node data in engine node.state
            eng.add_state_node(node_id, kind=node.kind, label=node.label, **(node.data or {}))

        # mirror edges (simple action placeholder)
        for src, dst in dag.edges:
            edge_id = f"edge_{src}_to_{dst}"
            action = "edge_action"
            # if target is validator, include spec id in params when available
            params = {}
            target_node = dag.nodes.get(dst)
            if target_node and target_node.kind == "validator":
                spec = target_node.data.get("spec")
                if spec is not None:
                    params["validator_id"] = getattr(spec, "id", None)
                action = "run_validator"

            eng.add_action_edge(src, dst, edge_id=edge_id, action=action, params=params)

        # Wire chaining rules from findings into runtime engine as action nodes/edges
        findings = state.get("findings", []) if isinstance(state, dict) else []
        triggers = detect_triggers_from_findings(findings)

        # endpoints as preferred sources; fallback to root
        endpoint_nodes = [nid for nid, n in dag.nodes.items() if n.kind in ("endpoint", "discovery")]
        source_node = endpoint_nodes[0] if endpoint_nodes else next(iter(dag.nodes.keys()), "root")

        for trigger in triggers:
            chain = get_chaining_for_trigger(trigger)
            prev_node_id = None
            for idx, step in enumerate(chain):
                action_name = step.get("action")
                action_node_id = f"action:{trigger}:{idx}:{action_name}"
                eng.add_state_node(action_node_id, kind="action", label=action_name, trigger=trigger)

                # connect from source or previous
                src = prev_node_id or source_node
                edge_id = f"edge_{src}_to_{action_node_id}"
                eng.add_action_edge(src, action_node_id, edge_id=edge_id, action=action_name, params={"trigger": trigger})

                # if next_if exists, create a mapping for the conditional follow-up
                next_if = step.get("next_if") or {}
                for produced_key, next_action in (next_if.items()):
                    # create a follow-up action node
                    next_node_id = f"action:{trigger}:{idx+1}:{next_action}"
                    eng.add_state_node(next_node_id, kind="action", label=next_action, trigger=trigger)
                    eng.add_action_edge(action_node_id, next_node_id, edge_id=f"edge_{action_node_id}_to_{next_node_id}", action=next_action, params={"conditional_on": produced_key})
                    prev_node_id = next_node_id

                if not next_if:
                    prev_node_id = action_node_id

        self.engine = eng
        return dag

    def topological_sort(self, graph: DAGGraph) -> List[str]:
        # reuse GraphBuilder's topological sort
        builder = GraphBuilder()
        return builder.topological_sort(graph)
