import json
import sys
import time
import argparse
from datetime import datetime, timezone
import threading
import inspect
from brain.dag_engine import DAGBrain
from brain.exploitability_reporter import ExploitabilityReporter
from engine.validation_engine import StateManager, ValidationEngine
import importlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.session import save_graph_snapshot
import os
from recon.naabu_scan import run_naabu
from recon.httpx_scan import run_httpx
from recon.nuclei_scan import run_nuclei
from recon.gospider_scan import run_gospider
from aggregator.parser import parse_all
from engine.decision import decide_actions
from engine.executor import run_sqlmap, test_xss, run_git_extractor, run_ssh_brute, run_config_reader
from utils.logger import logger
from utils.retry import retry
from utils.session import save_session


def build_validation_state(report):
    scan_info = report.get("scan_info", {}) if isinstance(report, dict) else {}
    target = scan_info.get("target") or ""

    ports = []
    protocols = []
    url = ""
    endpoints = []

    assets = report.get("assets", []) if isinstance(report, dict) else []
    if assets and isinstance(assets, list) and isinstance(assets[0], dict):
        asset = assets[0]
        if not target:
            target = asset.get("host") or ""

        for p in asset.get("ports", []) or []:
            if not isinstance(p, dict):
                continue
            port = p.get("port")
            if isinstance(port, int):
                ports.append(port)

            svc = (p.get("service") or "").strip().lower()
            if svc in ("http", "https"):
                protocols.append("http")

        raw_endpoints = asset.get("endpoints", []) or []
        if isinstance(raw_endpoints, list):
            endpoints = [ep for ep in raw_endpoints if isinstance(ep, str)]

        for ep in endpoints:
            if isinstance(ep, str) and ep.startswith("https://") and target and target in ep:
                url = ep
                break
        if not url:
            for ep in endpoints:
                if isinstance(ep, str) and ep.startswith("http://") and target and target in ep:
                    url = ep
                    break

    if not url and target:
        url = "https://" + target

    findings = report.get("findings", []) if isinstance(report, dict) else []
    if not isinstance(findings, list):
        findings = []
    findings = [f for f in findings if isinstance(f, dict)]

    metadata = {
        "scan_info": scan_info if isinstance(scan_info, dict) else {},
        "summary": report.get("summary", {}) if isinstance(report, dict) else {},
    }

    return {
        "target": target,
        "ports": sorted(set(ports)),
        "protocols": sorted(set(protocols)),
        "url": url,
        "endpoints": endpoints,
        "findings": findings,
        "metadata": metadata,
        # feedback loop state
        "validation_results": [],
        "confirmed_vulns": [],
        "signals": [],
    }

def execute_action(action):
    if action["action"] == "test_sqli":
        return run_sqlmap(action["endpoint"])

    if action["action"] == "test_xss":
        return test_xss(action["endpoint"])

    return {"success": False, "evidence": "Unknown action"}


def run_with_progress(label, func, *args, **kwargs):
    """Run a potentially long task while showing a simple progress spinner.

    This does not estimate percent complete; it confirms the task is still running
    and shows elapsed time.
    """
    if not sys.stdout.isatty():
        return func(*args, **kwargs)

    progress = {"detail": ""}
    try:
        if "progress" in inspect.signature(func).parameters:
            kwargs = dict(kwargs)
            kwargs["progress"] = progress
    except Exception:
        pass

    stop = threading.Event()
    start = time.time()

    def _spin():
        spinner = "|/-\\"
        idx = 0
        while not stop.is_set():
            elapsed = int(time.time() - start)
            ch = spinner[idx % len(spinner)]
            detail = progress.get("detail") or ""
            if len(detail) > 120:
                detail = detail[:117] + "..."
            sys.stdout.write(f"\r[{ch}] {label}... {elapsed}s elapsed{detail}")
            sys.stdout.flush()
            time.sleep(0.5)
            idx += 1

    spin_thread = threading.Thread(target=_spin, daemon=True)
    spin_thread.start()

    try:
        value = func(*args, **kwargs)
    except KeyboardInterrupt:
        stop.set()
        spin_thread.join(timeout=2)
        sys.stdout.write("\r" + (" " * 120) + "\r")
        sys.stdout.flush()
        print(f"{label} interrupted by user")
        raise
    except Exception as e:
        stop.set()
        spin_thread.join(timeout=2)
        sys.stdout.write("\r" + (" " * 120) + "\r")
        sys.stdout.flush()
        elapsed = int(time.time() - start)
        print(f"{label} failed after {elapsed}s: {e}")
        raise
    finally:
        stop.set()
        spin_thread.join(timeout=2)
        sys.stdout.write("\r" + (" " * 120) + "\r")
        sys.stdout.flush()

    elapsed = int(time.time() - start)
    print(f"{label} done in {elapsed}s")
    return value

def main():
    parser = argparse.ArgumentParser(
        description="Run the penetration testing pipeline against a target host or URL."
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target hostname or URL (for example: example.com or https://example.com)",
    )
    parser.add_argument(
        "--cve-report",
        action="store_true",
        help="Generate CVE exploitability report (optional).",
    )
    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(1)

    target = args.target
    scan_start = time.time()
    scan_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    logger.info(f"Starting penetration testing pipeline for target: {target}")

    # Step 1: Reconnaissance
    logger.info("Running Naabu scan...")
    run_with_progress("Naabu scan", run_naabu, target)
    
    logger.info("Running HTTPX scan...")
    run_with_progress("HTTPX scan", run_httpx, target)
    
    logger.info("Running Nuclei scan...")
    run_with_progress("Nuclei scan", run_nuclei, target)
    
    logger.info("Running Gospider scan...")
    run_with_progress("Gospider scan", run_gospider, target)

    # Step 2: Aggregation
    logger.info("Aggregating results...")
    parsed_data = parse_all(
        target,
        scan_time=scan_time,
        scanner="ReconX",
        profile="full_scan",
        duration_seconds=0,
    )

    # finalize duration after recon + aggregation
    try:
        parsed_data.setdefault("scan_info", {})["duration_seconds"] = int(time.time() - scan_start)
    except Exception:
        pass
    
    # Optional: save session
    save_session(parsed_data)

    # Step 3: DAG-driven Validation & Attack Chaining
    try:
        logger.info("Building DAG-driven state machine...")
        state = build_validation_state(parsed_data)

        # Build planner that uses GraphEngineAdapter (mirrors DAG into runtime engine)
        dag_brain = DAGBrain(use_graph_engine=True)
        dag = dag_brain.build_graph(state)
        engine = dag_brain.graph_builder.engine

        # validator spec map from the brain
        specs = dag_brain.validator_specs
        spec_map = {s.id: s for s in specs}

        # Execution loop: run ready edges until exhaustion
        logger.info("Starting DAG execution loop...")
        max_workers = 4
        executor = ThreadPoolExecutor(max_workers=max_workers)

        def execute_edge(u: str, v: str, edge):
            action = edge.action
            params = dict(edge.params or {})
            result = {"success": False}

            try:
                if action == "run_validator":
                    vid = params.get("validator_id")
                    spec = spec_map.get(vid)
                    if spec is None:
                        result.update({"error": "unknown_validator", "validator_id": vid})
                    else:
                        # dynamic import
                        module_path, cls_name = spec.class_path.rsplit(".", 1)
                        mod = importlib.import_module(module_path)
                        cls = getattr(mod, cls_name)
                        # instantiate with context when possible
                        try:
                            inst = cls(context=None)
                        except Exception:
                            inst = cls()

                        # prepare a minimal state for validator
                        try_state = dict(state)
                        # merge params like url/port
                        try_state.update(params)

                        # check can_run
                        can_run = True
                        if hasattr(inst, "can_run"):
                            try:
                                can_run = bool(inst.can_run(try_state))
                            except Exception:
                                can_run = False

                        if not can_run:
                            result.update({"success": False, "skipped": True})
                        else:
                            r = inst.run(try_state)
                            # If result is ValidationResult, convert to dict-like
                            if hasattr(r, "to_dict"):
                                rdict = r.to_dict()
                            elif isinstance(r, dict):
                                rdict = r
                            else:
                                rdict = {"raw": str(r)}

                            result.update({"success": bool(rdict.get("success", False)), "result": rdict})

                            # extract loot if present
                            loot = {}
                            ev = rdict.get("evidence") or {}
                            extra = ev.get("extra") or {}
                            if isinstance(extra, dict):
                                loot.update(extra)
                            # also look for matched tokens
                            if ev.get("matched"):
                                loot["matched"] = ev.get("matched")

                            if loot:
                                engine.inject_loot_into_downstream(v, loot)

                elif action == "git_extractor":
                    base = params.get("url") or state.get("url") or state.get("target")
                    r = run_git_extractor(base or "")
                    result.update({"success": bool(r.get("success")), "result": r})
                    # if found credentials or paths, inject loot
                    loot = {}
                    ev = r.get("evidence") or {}
                    if isinstance(ev, dict):
                        if ev.get("paths"):
                            loot["paths"] = ev.get("paths")
                        if ev.get("credentials"):
                            loot["credentials"] = ev.get("credentials")
                    if loot:
                        engine.inject_loot_into_downstream(v, loot)

                elif action == "ssh_brute":
                    host = params.get("host") or state.get("target")
                    port = params.get("port") or 22
                    # Determine explicit opt-in: env var or param or state.allow_destructive
                    env_ok = os.environ.get("PENTESTER_ENABLE_BRUTEFORCE", "0") == "1"
                    param_ok = bool(params.get("enable_bruteforce"))
                    state_ok = bool(state.get("allow_destructive", False))
                    enable = env_ok or param_ok or state_ok
                    creds = params.get("credentials") or params.get("creds")
                    r = run_ssh_brute(host or "", int(port), creds=creds, enable_bruteforce=enable)
                    result.update({"success": bool(r.get("success")), "result": r})
                    # include banner as loot
                    ev = r.get("evidence") or {}
                    loot = {}
                    if isinstance(ev, dict) and ev.get("banner"):
                        loot["banner"] = ev.get("banner")
                        engine.inject_loot_into_downstream(v, loot)

                elif action == "config_reader":
                    target_url = params.get("url") or state.get("url")
                    r = run_config_reader(target_url or "")
                    result.update({"success": bool(r.get("success")), "result": r})
                    ev = r.get("evidence") or {}
                    loot = {}
                    if isinstance(ev, dict) and ev.get("matched_indicators"):
                        loot["secrets"] = ev.get("matched_indicators")
                        engine.inject_loot_into_downstream(v, loot)

                else:
                    # default: mark as executed with generic result
                    result.update({"info": "action-executed", "action": action, "params": params})

            except Exception as e:
                result.update({"error": str(e)})

            # mark edge executed and attach result
            engine.mark_edge_executed(u, v, result=result)
            return (u, v, result)

        # main loop
        while True:
            ready = engine.get_ready_edges()
            if not ready:
                break

            futures = []
            for u, v, edge in ready:
                futures.append(executor.submit(execute_edge, u, v, edge))

            for fut in as_completed(futures):
                try:
                    u, v, res = fut.result()
                    logger.info(f"Edge executed: {u} -> {v} result: {res.get('success', False)}")
                except Exception as e:
                    logger.info(f"Edge execution failed: {e}")

        # persist final graph snapshot
        snapshot = engine.get_graph_snapshot()
        save_graph_snapshot(snapshot)

    except Exception as e:
        logger.info(f"DAG execution failed: {e}")
        import traceback
        traceback.print_exc()

    # Step 4: Decision Engine
    logger.info("Deciding next actions...")
    actions = decide_actions(parsed_data)
    
    if not actions:
        logger.info("No actionable findings identified.")
        return

    # Step 5: Execution
    logger.info("Executing follow-up tests...")
    results = []
    for action in actions:
        logger.info(f"Executing: {action['action']} on {action.get('endpoint')}")
        result = execute_action(action)
        results.append(result)

    logger.info("Pipeline completed. Summary:")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
