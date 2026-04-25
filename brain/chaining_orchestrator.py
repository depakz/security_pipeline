from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import networkx as nx

from brain.fact_store import Fact, FactCategory, FactStore


@dataclass
class TriggerResult:
    action: str
    target: str
    input_fact_key: str
    output: Dict[str, Any]


class ChainingOrchestrator:
    """Fact-driven attack chaining orchestrator.

    Implemented logic:
    - Credential fact -> trigger auth validator + FTP validator
    - Internal IP fact discovered in SSRF context -> trigger internal scan callback
    - Persist attack-path graph using networkx
    """

    def __init__(
        self,
        fact_store: Optional[FactStore] = None,
        auth_validator: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        ftp_validator: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        internal_scan_callback: Optional[Callable[[str], Dict[str, Any]]] = None,
    ):
        self.fact_store = fact_store or FactStore()
        self.auth_validator = auth_validator
        self.ftp_validator = ftp_validator
        self.internal_scan_callback = internal_scan_callback

        self.attack_graph = nx.DiGraph()
        self._seen_actions = set()

    def _add_fact_node(self, fact: Fact) -> str:
        node_id = f"fact:{fact.category.value}:{fact.key}"
        self.attack_graph.add_node(
            node_id,
            node_type="fact",
            category=fact.category.value,
            key=fact.key,
            confidence=fact.confidence,
        )

        if fact.source_validator_id:
            src = f"validator:{fact.source_validator_id}"
            self.attack_graph.add_node(src, node_type="validator", validator_id=fact.source_validator_id)
            self.attack_graph.add_edge(src, node_id, relation="discovered")

        return node_id

    def _record_action(self, source_node: str, action: str, target: str, output: Dict[str, Any]) -> None:
        action_node = f"action:{action}:{target}"
        self.attack_graph.add_node(action_node, node_type="action", action=action, target=target)
        self.attack_graph.add_edge(source_node, action_node, relation="triggered")

        ok = bool((output or {}).get("success", (output or {}).get("validated", False)))
        outcome_node = f"result:{action}:{target}"
        self.attack_graph.add_node(outcome_node, node_type="result", success=ok)
        self.attack_graph.add_edge(action_node, outcome_node, relation="produced")

    def _has_ssrf_context(self) -> bool:
        vulns = self.fact_store.get_facts_by_category(FactCategory.CONFIRMED_VULNERABILITY)
        for v in vulns:
            vv = (v.value or {}).get("type", "") if isinstance(v.value, dict) else ""
            if isinstance(vv, str) and "ssrf" in vv.lower():
                return True
            if "ssrf" in (v.key or "").lower():
                return True
        return False

    def run(self) -> List[TriggerResult]:
        results: List[TriggerResult] = []

        # 1) Credential -> AuthValidator + FTPValidator
        credentials = self.fact_store.get_facts_by_category(FactCategory.CREDENTIAL)
        for cred_fact in credentials:
            source_node = self._add_fact_node(cred_fact)
            cred_value = cred_fact.value if isinstance(cred_fact.value, dict) else {"raw": cred_fact.value}

            if self.auth_validator:
                key = ("auth_validator", cred_fact.key)
                if key not in self._seen_actions:
                    self._seen_actions.add(key)
                    out = self.auth_validator(cred_value) or {}
                    self._record_action(source_node, "auth_validator", cred_fact.key, out)
                    results.append(TriggerResult("auth_validator", cred_fact.key, cred_fact.key, out))

            if self.ftp_validator:
                key = ("ftp_validator", cred_fact.key)
                if key not in self._seen_actions:
                    self._seen_actions.add(key)
                    out = self.ftp_validator(cred_value) or {}
                    self._record_action(source_node, "ftp_validator", cred_fact.key, out)
                    results.append(TriggerResult("ftp_validator", cred_fact.key, cred_fact.key, out))

        # 2) Internal IP from SSRF -> trigger new scan
        if self.internal_scan_callback and self._has_ssrf_context():
            internal_hosts = self.fact_store.get_facts_by_category(FactCategory.INTERNAL_HOST)
            for host_fact in internal_hosts:
                source_node = self._add_fact_node(host_fact)

                host_val = host_fact.value if isinstance(host_fact.value, dict) else {}
                host = host_val.get("ip") or host_val.get("hostname") or host_fact.key
                host = str(host)
                key = ("internal_scan", host)
                if key in self._seen_actions:
                    continue

                self._seen_actions.add(key)
                out = self.internal_scan_callback(host) or {}
                self._record_action(source_node, "internal_scan", host, out)
                results.append(TriggerResult("internal_scan", host, host_fact.key, out))

        return results

    def save_attack_path(
        self,
        graphml_path: str = "output/attack_path.graphml",
        json_path: str = "output/attack_path.json",
    ) -> Dict[str, str]:
        os.makedirs(os.path.dirname(graphml_path) or ".", exist_ok=True)
        os.makedirs(os.path.dirname(json_path) or ".", exist_ok=True)

        nx.write_graphml(self.attack_graph, graphml_path)

        payload = {
            "nodes": [
                {"id": n, **(self.attack_graph.nodes[n] or {})}
                for n in self.attack_graph.nodes
            ],
            "edges": [
                {"from": u, "to": v, **(d or {})}
                for u, v, d in self.attack_graph.edges(data=True)
            ],
        }
        with open(json_path, "w") as f:
            json.dump(payload, f, indent=2)

        return {"graphml": graphml_path, "json": json_path}
