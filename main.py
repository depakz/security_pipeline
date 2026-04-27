import json
import sys
import time
import argparse
import asyncio
from datetime import datetime, timezone
import threading
import inspect
from brain.dag_engine_enhanced import DAGBrain, ConcurrentValidationEngine
from brain.compliance_mapper import ComplianceMapper
from brain.owasp_depth_matrix import build_depth_coverage
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


FINAL_REPORT_FILE = "output/final_report.json"
CONFIRMED_VULNS_FILE = "output/confirmed_vulnerabilities.json"


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

def execute_action(action, cookie=None):
    if action["action"] == "test_sqli":
        return run_sqlmap(action["endpoint"], cookie=cookie)

    if action["action"] == "test_xss":
        return test_xss(action["endpoint"], cookie=cookie)

    return {"success": False, "evidence": "Unknown action"}


def _action_to_vuln_type(action_name: str) -> str:
    mapping = {
        "test_sqli": "sql_injection",
        "test_xss": "cross_site_scripting",
    }
    return mapping.get(action_name, action_name or "unknown")


def _build_confirmed_records(actions, results):
    confirmed = []
    seen = set()

    for action, result in zip(actions or [], results or []):
        if not isinstance(action, dict) or not isinstance(result, dict):
            continue
        if not result.get("success"):
            continue

        action_name = action.get("action") or "unknown"
        endpoint = action.get("endpoint") or ""
        base = action.get("base") or ""
        params = action.get("params") or []
        reason = action.get("reason") or ""
        vuln_type = _action_to_vuln_type(action_name)

        key = (vuln_type, base, tuple(params) if isinstance(params, list) else ())
        if key in seen:
            continue
        seen.add(key)

        confirmed.append(
            {
                "type": vuln_type,
                "source_action": action_name,
                "endpoint": endpoint,
                "base": base,
                "params": params if isinstance(params, list) else [],
                "reason": reason,
                "proof": result.get("evidence", {}),
            }
        )

    return confirmed


def _annotate_records(records):
    annotated = []
    for record in records or []:
        if isinstance(record, dict):
            annotated.append(ComplianceMapper.annotate_record(record))
    return annotated


def _summarize_compliance(records):
    frameworks = {"OWASP": [], "PCI-DSS": [], "SOC2": [], "NIST": []}
    for record in records or []:
        if not isinstance(record, dict):
            continue
        for framework, label in (record.get("compliance_tags") or {}).items():
            bucket = frameworks.setdefault(framework, [])
            if label not in bucket:
                bucket.append(label)
    return frameworks


def _extract_pipeline_validation_records(pipeline_result):
    out = []
    if not isinstance(pipeline_result, dict):
        return out

    for edge_result in pipeline_result.get("results", []) or []:
        if not isinstance(edge_result, dict):
            continue
        result_wrapper = edge_result.get("result")
        if not isinstance(result_wrapper, dict):
            continue

        payload = result_wrapper.get("result")
        if isinstance(payload, dict):
            out.append(payload)
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    out.append(item)

    return out


def save_final_reports(target: str, scan_time: str, parsed_data, actions, results, pipeline_validation_results=None):
    os.makedirs("output", exist_ok=True)

    findings = parsed_data.get("findings", []) if isinstance(parsed_data, dict) else []
    if not isinstance(findings, list):
        findings = []

    summary = parsed_data.get("summary", {}) if isinstance(parsed_data, dict) else {}
    if not isinstance(summary, dict):
        summary = {}

    confirmed = _annotate_records(_build_confirmed_records(actions, results))
    annotated_findings = _annotate_records(findings)
    annotated_results = _annotate_records(results)
    annotated_pipeline_results = _annotate_records(pipeline_validation_results or [])
    all_report_records = annotated_findings + confirmed + annotated_results + annotated_pipeline_results

    compliance_overview = _summarize_compliance(all_report_records)
    owasp_depth_coverage = build_depth_coverage(all_report_records)

    final_report = {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scan_time": scan_time,
        "summary": {
            "potential_findings": len(annotated_findings),
            "confirmed_findings": len(confirmed),
            "critical": summary.get("critical", 0),
            "high": summary.get("high", 0),
            "medium": summary.get("medium", 0),
            "low": summary.get("low", 0),
            "info": summary.get("info", 0),
            "risk_score": summary.get("risk_score", 0),
        },
        "compliance_overview": compliance_overview,
        "owasp_depth_coverage": owasp_depth_coverage,
        "confirmed_vulnerabilities": confirmed,
        "potential_findings": annotated_findings,
        "validator_findings": annotated_pipeline_results,
        "follow_up_actions": actions or [],
        "follow_up_results": annotated_results,
    }

    with open(FINAL_REPORT_FILE, "w") as f:
        json.dump(final_report, f, indent=2)

    with open(CONFIRMED_VULNS_FILE, "w") as f:
        json.dump(
            {
                "target": target,
                "generated_at": final_report["generated_at"],
                "confirmed_count": len(confirmed),
                "confirmed_vulnerabilities": confirmed,
            },
            f,
            indent=2,
        )

    if compliance_overview.get("OWASP"):
        logger.info("OWASP compliance labels: %s", ", ".join(compliance_overview["OWASP"]))
    logger.info(
        "OWASP depth coverage: %.2f%% (%s/%s subcases)",
        float((owasp_depth_coverage.get("summary") or {}).get("overall_subcase_coverage_percent", 0.0) or 0.0),
        int((owasp_depth_coverage.get("summary") or {}).get("subcases_tested", 0) or 0),
        int((owasp_depth_coverage.get("summary") or {}).get("subcases_total", 0) or 0),
    )

    return FINAL_REPORT_FILE, CONFIRMED_VULNS_FILE


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
    parser.add_argument(
        "--cookie",
        help="Cookie header value to include in HTTP-based scans (example: 'PHPSESSID=...; security=low').",
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
    run_with_progress("HTTPX scan", run_httpx, target, cookie=args.cookie)
    
    logger.info("Running Nuclei scan...")
    run_with_progress("Nuclei scan", run_nuclei, target, cookie=args.cookie)
    
    logger.info("Running Gospider scan...")
    run_with_progress("Gospider scan", run_gospider, target, cookie=args.cookie)

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
    pipeline_result = {}
    try:
        logger.info("Building DAG-driven state machine...")
        state = build_validation_state(parsed_data)
        dag_brain = DAGBrain(use_graph_engine=True)
        concurrent_engine = ConcurrentValidationEngine(dag_brain=dag_brain, state=state, max_workers=20)

        logger.info("Starting concurrent DAG execution loop...")
        pipeline_result = asyncio.run(concurrent_engine.run_pipeline())
        snapshot = pipeline_result.get("snapshot", {})
        save_graph_snapshot(snapshot)
        logger.info(
            "Concurrent DAG execution completed with %s executed edges",
            len(pipeline_result.get("results", [])),
        )

    except Exception as e:
        logger.info(f"DAG execution failed: {e}")
        import traceback
        traceback.print_exc()

    # Step 4: Decision Engine
    logger.info("Deciding next actions...")
    actions = decide_actions(parsed_data)
    
    if not actions:
        logger.info("No actionable findings identified.")
        final_report, confirmed_report = save_final_reports(
            target=target,
            scan_time=scan_time,
            parsed_data=parsed_data,
            actions=[],
            results=[],
            pipeline_validation_results=_extract_pipeline_validation_records(pipeline_result),
        )
        logger.info("Saved final report: %s", final_report)
        logger.info("Saved confirmed vulnerabilities report: %s", confirmed_report)
        return

    # Step 5: Execution
    logger.info("Executing follow-up tests...")
    results = []
    for action in actions:
        logger.info(f"Executing: {action['action']} on {action.get('endpoint')}")
        result = execute_action(action, cookie=args.cookie)
        results.append(result)

    logger.info("Pipeline completed. Summary:")
    print(json.dumps(_annotate_records(results), indent=2))

    final_report, confirmed_report = save_final_reports(
        target=target,
        scan_time=scan_time,
        parsed_data=parsed_data,
        actions=actions,
        results=results,
        pipeline_validation_results=_extract_pipeline_validation_records(pipeline_result),
    )
    logger.info("Saved final report: %s", final_report)
    logger.info("Saved confirmed vulnerabilities report: %s", confirmed_report)

if __name__ == "__main__":
    main()
