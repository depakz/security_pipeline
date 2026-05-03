import json
import sys
import time
import argparse
import asyncio
from datetime import datetime, timezone
import threading
import inspect
from urllib.parse import urlsplit
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
from recon.nuclei_scan import run_nuclei, run_nuclei_multi
from recon.site_finder import run_site_finder
from recon.gospider_scan import run_gospider
from recon.headless_browser import run_headless_browser
from aggregator.parser import parse_all
from engine.decision import decide_actions
from engine.executor import run_sqlmap, test_xss, run_git_extractor, run_ssh_brute, run_config_reader
from utils.logger import logger
from utils.retry import retry
from utils.session import save_session
from utils.session import load_session
from utils.session import capture_session_context


FINAL_REPORT_FILE = "output/final_report.json"
CONFIRMED_VULNS_FILE = "output/confirmed_vulnerabilities.json"


def build_validation_state(report, session_context=None):
    scan_info = report.get("scan_info", {}) if isinstance(report, dict) else {}
    session_target = ""
    if isinstance(session_context, dict):
        raw_session_target = session_context.get("target")
        if isinstance(raw_session_target, str):
            session_target = raw_session_target.strip()

    target = session_target or scan_info.get("target") or report.get("target") or ""

    ports = []
    protocols = []
    url = ""
    endpoints = []

    if isinstance(target, str) and target.startswith(("http://", "https://")):
        parsed_target = urlsplit(target)
        if parsed_target.scheme in ("http", "https"):
            protocols.append("http")
        if parsed_target.port is not None:
            ports.append(parsed_target.port)
        elif parsed_target.scheme == "http":
            ports.append(80)
        elif parsed_target.scheme == "https":
            ports.append(443)

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
        url = target if target.startswith(("http://", "https://")) else "https://" + target
    elif not url and session_target:
        url = session_target

    validation_targets = []
    for candidate in [url, target, session_target, *(endpoints or [])]:
        if not isinstance(candidate, str):
            continue
        candidate = candidate.strip()
        if not candidate:
            continue
        if candidate not in validation_targets:
            validation_targets.append(candidate)

    findings = report.get("findings", []) if isinstance(report, dict) else []
    if not isinstance(findings, list):
        findings = []
    findings = [f for f in findings if isinstance(f, dict)]

    metadata = {
        "scan_info": scan_info if isinstance(scan_info, dict) else {},
        "summary": report.get("summary", {}) if isinstance(report, dict) else {},
    }

    resolved_session = session_context if isinstance(session_context, dict) else {}
    cookie = resolved_session.get("cookie") if isinstance(resolved_session.get("cookie"), str) else ""
    headers = resolved_session.get("headers") if isinstance(resolved_session.get("headers"), dict) else {}

    return {
        "target": target,
        "ports": sorted(set(ports)),
        "protocols": sorted(set(protocols)),
        "url": url,
        "endpoints": endpoints,
        "validation_targets": validation_targets,
        "findings": findings,
        "metadata": metadata,
        "cookie": cookie,
        "headers": headers,
        "session_context": resolved_session,
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


def _build_confirmed_validator_records(pipeline_validation_results):
    confirmed = []
    seen = set()

    for record in pipeline_validation_results or []:
        if not isinstance(record, dict):
            continue

        success = bool(record.get("success"))
        validation = record.get("validation") or {}
        if not success and isinstance(validation, dict):
            status = str(validation.get("status") or "").strip().lower()
            success = status == "confirmed"

        if not success:
            continue

        vulnerability = str(record.get("vulnerability") or record.get("validator_id") or "unknown")
        validator_id = str(record.get("validator_id") or "")
        key = (vulnerability, validator_id)
        if key in seen:
            continue
        seen.add(key)

        confirmed.append(
            {
                "type": vulnerability,
                "source_action": "validator",
                "endpoint": record.get("target") or record.get("url") or "",
                "base": record.get("target") or record.get("url") or "",
                "params": [],
                "reason": record.get("impact") or record.get("remediation") or "",
                "proof": record.get("evidence", {}),
                "validator_id": validator_id,
                "validator_class": record.get("validator_class") or "",
                "severity": record.get("severity") or (validation.get("severity") if isinstance(validation, dict) else ""),
                "confidence": validation.get("confidence_score") if isinstance(validation, dict) else None,
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
    confirmed_validator_records = _annotate_records(
        _build_confirmed_validator_records(pipeline_validation_results or [])
    )
    all_report_records = annotated_findings + confirmed + annotated_results + annotated_pipeline_results + confirmed_validator_records
    confirmed_all = confirmed + confirmed_validator_records

    compliance_overview = _summarize_compliance(all_report_records)
    owasp_depth_coverage = build_depth_coverage(all_report_records)

    final_report = {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scan_time": scan_time,
        "summary": {
            "potential_findings": len(annotated_findings),
            "confirmed_findings": len(confirmed_all),
            "critical": summary.get("critical", 0),
            "high": summary.get("high", 0),
            "medium": summary.get("medium", 0),
            "low": summary.get("low", 0),
            "info": summary.get("info", 0),
            "risk_score": summary.get("risk_score", 0),
        },
        "compliance_overview": compliance_overview,
        "owasp_depth_coverage": owasp_depth_coverage,
        "confirmed_vulnerabilities": confirmed_all,
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
                "confirmed_count": len(confirmed_all),
                "confirmed_vulnerabilities": confirmed_all,
            },
            f,
            indent=2,
        )

    if compliance_overview.get("OWASP"):
        logger.info("OWASP compliance labels: %s", ", ".join(compliance_overview["OWASP"]))
    coverage_summary = owasp_depth_coverage.get("summary") or {}
    logger.info(
        "OWASP coverage: %.2f%% categories (%s/10) | %.2f%% subcases (%s/%s)",
        float(coverage_summary.get("owasp_top10_category_coverage_percent", 0.0) or 0.0),
        int(coverage_summary.get("categories_with_any_tested_subcase", 0) or 0),
        float(coverage_summary.get("overall_subcase_coverage_percent", 0.0) or 0.0),
        int(coverage_summary.get("subcases_tested", 0) or 0),
        int(coverage_summary.get("subcases_total", 0) or 0),
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
    parser.add_argument(
        "--login-url",
        help="Optional login URL to capture a fresh session cookie or token before running the pipeline.",
    )
    parser.add_argument(
        "--login-method",
        default="POST",
        help="HTTP method to use for login capture (default: POST).",
    )
    parser.add_argument(
        "--username",
        help="Username for opt-in login capture.",
    )
    parser.add_argument(
        "--password",
        help="Password for opt-in login capture.",
    )
    parser.add_argument(
        "--auth-type",
        default="session",
        choices=["session", "basic", "bearer"],
        help="Authentication style for session capture.",
    )
    parser.add_argument(
        "--bearer-token",
        help="Optional bearer token to seed the session context directly.",
    )
    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(1)

    target = args.target
    scan_start = time.time()
    scan_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    logger.info(f"Starting penetration testing pipeline for target: {target}")

    prior_session = load_session()
    prior_session_context = prior_session.get("session_context") if isinstance(prior_session, dict) else {}
    session_context = capture_session_context(
        target,
        previous=prior_session_context,
        cookie=args.cookie,
        login_url=args.login_url,
        login_method=args.login_method,
        username=args.username,
        password=args.password,
        auth_type=args.auth_type,
        bearer_token=args.bearer_token,
    )
    active_cookie = session_context.get("cookie") or None

    # Step 1: Reconnaissance (discovery phase)
    logger.info("Running Naabu scan...")
    run_with_progress("Naabu scan", run_naabu, target)
    
    logger.info("Running HTTPX scan...")
    run_with_progress("HTTPX scan", run_httpx, target, cookie=active_cookie)
    
    logger.info("Running Gospider scan...")
    run_with_progress("Gospider scan", run_gospider, target, cookie=active_cookie)

    logger.info("Running headless browser discovery...")
    run_with_progress("Headless browser discovery", run_headless_browser, target, cookie=active_cookie)

    logger.info("Running site finder discovery...")
    run_with_progress("Site finder discovery", run_site_finder, target, cookie=active_cookie)

    # Step 2: Aggregation (collect all endpoints)
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

    if session_context:
        parsed_data["session_context"] = session_context
    
    # Optional: save session
    save_session(parsed_data)

    # Step 2b: Run Nuclei across all discovered endpoints now that we know them
    discovered_endpoints = parsed_data.get("assets", [])
    nuclei_targets = [target]  # Start with root
    if discovered_endpoints and isinstance(discovered_endpoints, list):
        for asset in discovered_endpoints:
            if isinstance(asset, dict):
                endpoints = asset.get("endpoints", [])
                if isinstance(endpoints, list):
                    for ep in endpoints:
                        if isinstance(ep, str) and ep not in nuclei_targets:
                            nuclei_targets.append(ep)
    
    logger.info(f"Running Nuclei scan across {len(nuclei_targets)} discovered endpoints...")
    run_with_progress("Nuclei comprehensive scan", run_nuclei_multi, nuclei_targets, cookie=active_cookie)
    
    # Re-aggregate to include Nuclei results
    logger.info("Re-aggregating with Nuclei results...")
    parsed_data = parse_all(
        target,
        scan_time=scan_time,
        scanner="ReconX",
        profile="full_scan",
        duration_seconds=0,
    )

    # Step 3: DAG-driven Validation & Attack Chaining
    pipeline_result = {}
    # Step 3: DAG-driven Validation & Attack Chaining
    pipeline_result = {}
    try:
        logger.info("Building DAG-driven state machine...")
        state = build_validation_state(parsed_data, session_context=session_context)
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
        result = execute_action(action, cookie=active_cookie)
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
