"""
Enhanced DAGEngine: Intelligent DAG Planning with Dynamic Chain Injection

This module extends the original DAG engine to support:
1. Dynamic exploitation node injection based on successful validations
2. Fact store querying to determine node readiness
3. Endpoint pattern deduplication
4. Attack chain management
"""

from __future__ import annotations

import asyncio
import importlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any, Dict, List, Optional, Callable, Set
from urllib.parse import urlsplit

from engine.models import ExecutionContext
from brain.fact_store import FactStore
from brain.endpoint_normalizer import EndpointNormalizer
from brain.attack_chain_manager import AttackChainManager, ChainedExploitationNode
from engine.validation_engine_enhanced import ValidationResultProcessor
from engine.executor import run_sqlmap, test_xss, run_git_extractor, run_ssh_brute, run_config_reader

from .cve_mapper import CVEMapper
from .graph_builder import DAGGraph, GraphBuilder, GraphEngineAdapter
from .kb import ValidatorSpec, get_default_validator_specs
from validators.access_control import BrokenAccessControlValidator
from validators.auth import AuthValidator
from validators.components import OutdatedComponentsValidator
from validators.crypto import CryptoValidator
from validators.deserialization import InsecureDeserializationValidator
from validators.ftp import FTPAnonymousLoginValidator
from validators.http import MissingSecurityHeadersValidator
from validators.injection import InjectionValidator
from validators.insecure_design import InsecureDesignValidator
from validators.idor import IDORValidator
from validators.integrity import IntegrityValidator
from validators.logging import LoggingValidator
from validators.misconfiguration import SecurityMisconfigurationValidator
from validators.redis import RedisNoAuthValidator
from validators.ssrf import SSRFValidator


VALIDATOR_CLASS_MAP = {
    "validators.redis.RedisNoAuthValidator": RedisNoAuthValidator,
    "validators.http.MissingSecurityHeadersValidator": MissingSecurityHeadersValidator,
    "validators.injection.InjectionValidator": InjectionValidator,
    "validators.insecure_design.InsecureDesignValidator": InsecureDesignValidator,
    "validators.access_control.BrokenAccessControlValidator": BrokenAccessControlValidator,
    "validators.crypto.CryptoValidator": CryptoValidator,
    "validators.auth.AuthValidator": AuthValidator,
    "validators.logging.LoggingValidator": LoggingValidator,
    "validators.misconfiguration.SecurityMisconfigurationValidator": SecurityMisconfigurationValidator,
    "validators.components.OutdatedComponentsValidator": OutdatedComponentsValidator,
    "validators.ssrf.SSRFValidator": SSRFValidator,
    "validators.ftp.FTPAnonymousLoginValidator": FTPAnonymousLoginValidator,
    "validators.integrity.IntegrityValidator": IntegrityValidator,
    "validators.idor.IDORValidator": IDORValidator,
    "validators.deserialization.InsecureDeserializationValidator": InsecureDeserializationValidator,
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
        selected_spec_ids: Set[str] = set()
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
            selected_spec_ids.add(spec.id)

        for spec in self.validator_specs:
            if spec.id in selected_spec_ids:
                continue

            validator_cls = VALIDATOR_CLASS_MAP.get(spec.class_path)
            if not validator_cls:
                continue

            try:
                validator_instance = self._instantiate_validator(validator_cls, spec=spec, context=context)
                can_run = getattr(validator_instance, "can_run", None)
                if callable(can_run) and not can_run(state):
                    continue
                validators.append(validator_instance)
                selected_spec_ids.add(spec.id)
            except Exception:
                continue

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

    def create_concurrent_engine(
        self,
        state: Dict[str, Any],
        max_workers: int = 20,
    ) -> "ConcurrentValidationEngine":
        """Create a concurrent validation engine tied to this planner and state."""
        return ConcurrentValidationEngine(self, state=state, max_workers=max_workers)


class ConcurrentValidationEngine:
    """Async DAG execution engine that runs ready validations concurrently."""

    def __init__(
        self,
        dag_brain: Optional[DAGBrain] = None,
        state: Optional[Dict[str, Any]] = None,
        max_workers: int = 20,
    ):
        self.dag_brain = dag_brain or DAGBrain(use_graph_engine=True)
        self.state = dict(state or {})
        self.max_workers = max(1, int(max_workers or 1))
        self.fact_store = self.dag_brain.fact_store
        self._thread_pool = ThreadPoolExecutor(max_workers=self.max_workers)
        self._execution_cache: set[str] = set()
        self.result_processor = ValidationResultProcessor(
            self.fact_store,
            self.dag_brain.endpoint_normalizer,
            self.dag_brain.attack_chain_manager,
        )
        self._metrics: Dict[str, Any] = {
            "ready_edges_seen": 0,
            "queued_edges": 0,
            "queued_batches": 0,
            "dedupe_skips": 0,
            "executed_edges": 0,
            "executed_batches": 0,
            "batch_durations_ms": [],
            "batch_sizes": [],
        }

    def _normalize_target_key(self, value: Any, state: Dict[str, Any]) -> str:
        raw = str(value or state.get("url") or state.get("target") or "").strip()
        if not raw:
            return "unknown"

        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        host = parsed.hostname or raw.split(":")[0].split("/")[0]
        port = parsed.port
        if port is None:
            if parsed.scheme == "https":
                port = 443
            elif parsed.scheme == "http":
                port = 80

        host_key = host.lower() if isinstance(host, str) else str(host).lower()
        if port is not None:
            return f"{host_key}:{port}"
        return host_key

    def _edge_target_key(self, u: str, v: str, edge, state: Dict[str, Any]) -> str:
        params = dict(edge.params or {})
        for candidate in (params.get("host"), params.get("url"), params.get("endpoint"), params.get("target"), state.get("url"), state.get("target")):
            key = self._normalize_target_key(candidate, state)
            if key != "unknown":
                return key
        return self._normalize_target_key(f"{u}:{v}", state)

    def _edge_batch_key(self, u: str, v: str, edge, state: Dict[str, Any]) -> str:
        """Batch by target + action + validator-type for better execution locality."""
        params = dict(edge.params or {})
        target_key = self._edge_target_key(u, v, edge, state)
        action = str(edge.action or "action")
        validator_id = str(params.get("validator_id") or params.get("id") or "generic")
        return f"{target_key}|{action}|{validator_id}"

    def _dedupe_key(self, u: str, v: str, edge, batch_key: str) -> str:
        params = edge.params or {}
        validator_id = params.get("validator_id") or params.get("id") or ""
        action = edge.action or "action"
        return f"{batch_key}|{action}|{validator_id}|{u}|{v}"

    def _candidate_validation_urls(self, state: Dict[str, Any]) -> List[str]:
        candidates: List[str] = []
        raw_sources = []
        validation_targets = state.get("validation_targets")
        if isinstance(validation_targets, list) and validation_targets:
            raw_sources.extend(validation_targets)
        else:
            raw_sources.append(state.get("url") or state.get("target"))
            raw_sources.extend(state.get("endpoints") or [])

        for candidate in raw_sources:
            if not isinstance(candidate, str):
                continue
            candidate = candidate.strip()
            if not candidate or not candidate.startswith(("http://", "https://")):
                continue
            if candidate not in candidates:
                candidates.append(candidate)

        return candidates[:75] if candidates else [str(state.get("url") or state.get("target") or "")]

    async def run_pipeline(self) -> Dict[str, Any]:
        """Run the DAG pipeline using an asyncio queue and worker pool."""
        pipeline_started = perf_counter()
        state = dict(self.state)
        if not state:
            return {"results": [], "snapshot": {}, "scheduler_metrics": self._finalize_metrics(0.0)}

        self.dag_brain.build_graph(state)
        runtime = getattr(self.dag_brain.graph_builder, "engine", None)
        if runtime is None:
            return {"results": [], "snapshot": {}, "scheduler_metrics": self._finalize_metrics(0.0)}

        spec_map = {spec.id: spec for spec in self.dag_brain.validator_specs}
        queue: asyncio.Queue = asyncio.Queue()
        queued_edge_ids: set[str] = set()
        results: List[Dict[str, Any]] = []

        def enqueue_ready_edges() -> None:
            batched: Dict[str, List[Any]] = {}
            for u, v, edge in runtime.get_ready_edges():
                self._metrics["ready_edges_seen"] += 1
                edge_id = getattr(edge, "id", f"{u}->{v}")
                if edge_id in queued_edge_ids:
                    self._metrics["dedupe_skips"] += 1
                    continue
                batch_key = self._edge_batch_key(u, v, edge, state)
                dedupe_key = self._dedupe_key(u, v, edge, batch_key)
                if dedupe_key in self._execution_cache:
                    self._metrics["dedupe_skips"] += 1
                    continue
                queued_edge_ids.add(edge_id)
                batched.setdefault(batch_key, []).append((u, v, edge, dedupe_key))

            for batch_key, items in batched.items():
                queue.put_nowait((batch_key, items))
                self._metrics["queued_batches"] += 1
                self._metrics["queued_edges"] += len(items)

        enqueue_ready_edges()
        if queue.empty():
            snapshot = runtime.get_graph_snapshot()
            metrics = self._finalize_metrics((perf_counter() - pipeline_started) * 1000.0)
            if isinstance(snapshot, dict):
                snapshot["scheduler_metrics"] = metrics
            try:
                from utils.session import save_graph_snapshot

                save_graph_snapshot(snapshot)
            except Exception:
                pass
            return {"results": [], "snapshot": snapshot, "scheduler_metrics": metrics}

        async def worker() -> None:
            while True:
                item = await queue.get()
                if item is None:
                    queue.task_done()
                    return

                batch_key, batch_items = item
                try:
                    started = perf_counter()
                    outcome = await asyncio.get_running_loop().run_in_executor(
                        self._thread_pool,
                        self._execute_batch_sync,
                        batch_key,
                        batch_items,
                        state,
                        spec_map,
                        runtime,
                    )
                    duration_ms = (perf_counter() - started) * 1000.0
                    executed_items = outcome.get("items", []) if isinstance(outcome, dict) else []
                    batch_size = int(outcome.get("batch_size", len(batch_items))) if isinstance(outcome, dict) else len(batch_items)
                    results.extend(executed_items)
                    self._metrics["executed_batches"] += 1
                    self._metrics["executed_edges"] += len(executed_items)
                    self._metrics["batch_durations_ms"].append(duration_ms)
                    self._metrics["batch_sizes"].append(batch_size)
                    enqueue_ready_edges()
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self.max_workers)]
        await queue.join()

        for _ in workers:
            await queue.put(None)
        await asyncio.gather(*workers, return_exceptions=True)

        snapshot = runtime.get_graph_snapshot()
        metrics = self._finalize_metrics((perf_counter() - pipeline_started) * 1000.0)
        if isinstance(snapshot, dict):
            snapshot["scheduler_metrics"] = metrics
        try:
            from utils.session import save_graph_snapshot

            save_graph_snapshot(snapshot)
        except Exception:
            pass

        return {"results": results, "snapshot": snapshot, "scheduler_metrics": metrics}

    def _execute_batch_sync(self, batch_key: str, batch_items, state: Dict[str, Any], spec_map: Dict[str, Any], runtime) -> Dict[str, Any]:
        batch_results: List[Dict[str, Any]] = []
        for u, v, edge, dedupe_key in batch_items:
            if dedupe_key in self._execution_cache:
                continue
            self._execution_cache.add(dedupe_key)
            batch_results.append(self._execute_edge_sync(u, v, edge, state, spec_map, runtime, batch_key=batch_key))
        return {"items": batch_results, "batch_size": len(batch_items)}

    def _finalize_metrics(self, total_duration_ms: float) -> Dict[str, Any]:
        batch_durations = self._metrics.get("batch_durations_ms", []) or []
        batch_sizes = self._metrics.get("batch_sizes", []) or []
        ready_edges_seen = int(self._metrics.get("ready_edges_seen", 0) or 0)
        dedupe_skips = int(self._metrics.get("dedupe_skips", 0) or 0)

        dedupe_hit_rate = (dedupe_skips / ready_edges_seen) if ready_edges_seen > 0 else 0.0
        avg_batch_duration_ms = (sum(batch_durations) / len(batch_durations)) if batch_durations else 0.0
        avg_batch_size = (sum(batch_sizes) / len(batch_sizes)) if batch_sizes else 0.0

        return {
            "max_workers": self.max_workers,
            "total_duration_ms": round(float(total_duration_ms), 2),
            "ready_edges_seen": ready_edges_seen,
            "queued_edges": int(self._metrics.get("queued_edges", 0) or 0),
            "queued_batches": int(self._metrics.get("queued_batches", 0) or 0),
            "executed_edges": int(self._metrics.get("executed_edges", 0) or 0),
            "executed_batches": int(self._metrics.get("executed_batches", 0) or 0),
            "dedupe_skips": dedupe_skips,
            "dedupe_hit_rate": round(float(dedupe_hit_rate), 4),
            "avg_batch_duration_ms": round(float(avg_batch_duration_ms), 2),
            "avg_batch_size": round(float(avg_batch_size), 2),
        }

    def _execute_edge_sync(self, u: str, v: str, edge, state: Dict[str, Any], spec_map: Dict[str, Any], runtime, batch_key: str = "") -> Dict[str, Any]:
        action = edge.action
        params = dict(edge.params or {})
        result: Dict[str, Any] = {"success": False, "batch_key": batch_key}

        try:
            if action == "run_validator":
                vid = params.get("validator_id")
                spec = spec_map.get(vid)
                if spec is None:
                    result.update({"error": "unknown_validator", "validator_id": vid})
                else:
                    module_path, cls_name = spec.class_path.rsplit(".", 1)
                    mod = importlib.import_module(module_path)
                    cls = getattr(mod, cls_name)

                    try:
                        inst = cls(context=None)
                    except Exception:
                        inst = cls()

                    candidate_urls = self._candidate_validation_urls(state)
                    processed_results: List[Dict[str, Any]] = []
                    any_can_run = False

                    for candidate_url in candidate_urls:
                        try_state = dict(state)
                        try_state.update(params)
                        try_state["url"] = candidate_url
                        try_state["target"] = candidate_url

                        can_run = True
                        if hasattr(inst, "can_run"):
                            try:
                                can_run = bool(inst.can_run(try_state))
                            except Exception:
                                can_run = False

                        if not can_run:
                            continue

                        any_can_run = True

                        r = inst.run(try_state)
                        if isinstance(r, list):
                            raw_items = [item.to_dict() if hasattr(item, "to_dict") else item for item in r]
                        elif hasattr(r, "to_dict"):
                            raw_items = [r.to_dict()]
                        elif isinstance(r, dict):
                            raw_items = [r]
                        else:
                            raw_items = [{"raw": str(r), "success": False, "vulnerability": vid or spec.id}]

                        for item in raw_items:
                            if not isinstance(item, dict):
                                continue
                            processed_results.append(self.result_processor.process_result(item))

                    if not any_can_run:
                        result.update({"success": False, "skipped": True})
                    else:
                        success_flag = any(bool(item.get("success", False)) for item in processed_results if isinstance(item, dict))
                        result.update({
                            "success": success_flag,
                            "result": processed_results if len(processed_results) != 1 else processed_results[0],
                            "tested_urls": candidate_urls,
                        })

                        loot: Dict[str, Any] = {}
                        for item in processed_results:
                            if not isinstance(item, dict):
                                continue
                            ev = item.get("evidence") or {}
                            extra = ev.get("extra") or {}
                            if isinstance(extra, dict):
                                loot.update(extra)
                            if ev.get("matched"):
                                loot["matched"] = ev.get("matched")
                        if loot:
                            runtime.inject_loot_into_downstream(v, loot)

            elif action == "sqlmap":
                endpoint = params.get("endpoint") or state.get("url") or state.get("target") or ""
                r = run_sqlmap(endpoint)
                result.update({"success": bool(r.get("success")), "result": r})

            elif action == "xss":
                endpoint = params.get("endpoint") or state.get("url") or state.get("target") or ""
                r = test_xss(endpoint)
                result.update({"success": bool(r.get("success")), "result": r})

            elif action == "git_extractor":
                base = params.get("url") or state.get("url") or state.get("target") or ""
                r = run_git_extractor(base)
                result.update({"success": bool(r.get("success")), "result": r})
                loot: Dict[str, Any] = {}
                ev = r.get("evidence") or {}
                if isinstance(ev, dict):
                    if ev.get("paths"):
                        loot["paths"] = ev.get("paths")
                    if ev.get("credentials"):
                        loot["credentials"] = ev.get("credentials")
                if loot:
                    runtime.inject_loot_into_downstream(v, loot)

            elif action == "ssh_brute":
                host = params.get("host") or state.get("target") or ""
                port = params.get("port") or 22
                enable = bool(params.get("enable_bruteforce")) or bool(state.get("allow_destructive", False))
                creds = params.get("credentials") or params.get("creds")
                r = run_ssh_brute(host, int(port), creds=creds, enable_bruteforce=enable)
                result.update({"success": bool(r.get("success")), "result": r})
                ev = r.get("evidence") or {}
                if isinstance(ev, dict) and ev.get("banner"):
                    runtime.inject_loot_into_downstream(v, {"banner": ev.get("banner")})

            elif action == "config_reader":
                target_url = params.get("url") or state.get("url") or ""
                r = run_config_reader(target_url)
                result.update({"success": bool(r.get("success")), "result": r})
                ev = r.get("evidence") or {}
                if isinstance(ev, dict) and ev.get("matched_indicators"):
                    runtime.inject_loot_into_downstream(v, {"secrets": ev.get("matched_indicators")})

            else:
                result.update({"info": "action-executed", "action": action, "params": params})

        except Exception as e:
            result.update({"error": str(e)})

        runtime.mark_edge_executed(u, v, result=result)
        return {"from": u, "to": v, "result": result}
