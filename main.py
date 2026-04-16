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
from recon.naabu_scan import run_naabu
from recon.httpx_scan import run_httpx
from recon.nuclei_scan import run_nuclei
from recon.gospider_scan import run_gospider
from aggregator.parser import parse_all
from engine.decision import decide_actions
from engine.executor import run_sqlmap, test_xss
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

    # Step 3: Validation Engine (truth generator)
    try:
        logger.info("Running DAG validation planner (feedback loop)...")
        state = build_validation_state(parsed_data)

        dag_brain = DAGBrain()
        vengine = ValidationEngine()
        state_manager = StateManager()

        max_iterations = 5
        for iteration in range(1, max_iterations + 1):
            plan = dag_brain.plan_validations(state)
            iteration_results = vengine.run(plan, state)
            new_confirmed = state_manager.update(state, iteration_results)

            logger.info(
                f"Validation iteration {iteration}: {len(iteration_results)} results, "
                f"{new_confirmed} new confirmations, {len(plan.validators)} validators planned"
            )

            if new_confirmed == 0:
                break

        validation_results = state.get("validation_results", [])
        with open("output/validations.json", "w") as f:
            json.dump(validation_results, f, indent=4)

        logger.info(f"Validation results saved to output/validations.json ({len(validation_results)} results)")

        # Step 3b: CVE-specific validation and reporting (optional)
        if args.cve_report:
            findings = parsed_data.get("findings", [])
            if findings:
                logger.info("Planning CVE-specific validations...")
                cve_plan = dag_brain.plan_cve_validations(state, findings)

                if cve_plan.cve_to_validators:
                    # Run CVE-specific validators
                    cve_vengine = ValidationEngine()
                    for validator in cve_plan.validator_instances.values():
                        cve_vengine.register(validator)

                    cve_validation_results = cve_vengine.run(state)

                    # Generate exploitability report
                    reporter = ExploitabilityReporter()
                    cve_verdicts = []

                    for cve_id, cve_data in cve_plan.cve_details.items():
                        # Get validators for this CVE
                        validators_for_cve = cve_plan.cve_to_validators.get(cve_id, [])

                        # Get validation results for these validators
                        relevant_results = []
                        validators_set = set(v for v in validators_for_cve if isinstance(v, str))
                        for result in cve_validation_results:
                            if not isinstance(result, dict):
                                continue

                            # Prefer explicit linkage from ValidationEngine.
                            rid = result.get("validator_id")
                            if isinstance(rid, str) and rid in validators_set:
                                relevant_results.append(result)
                                continue

                            # Backward-compatible fallback: try to match by vulnerability name.
                            vuln = result.get("vulnerability")
                            if isinstance(vuln, str):
                                if vuln in validators_set or vuln.replace("-", "_") in validators_set:
                                    relevant_results.append(result)

                        # Generate verdict for this CVE
                        verdict = reporter.generate_verdict(
                            cve_data=cve_data,
                            validation_results=relevant_results,
                            validators_tested=validators_for_cve,
                        )
                        cve_verdicts.append(verdict)

                    # Generate and save full report
                    report = reporter.generate_report(cve_verdicts)
                    with open("output/exploitability_report.json", "w") as f:
                        json.dump(report, f, indent=4)

                    logger.info(
                        f"Exploitability report saved to output/exploitability_report.json "
                        f"({len(cve_plan.cve_to_validators)} CVEs, "
                        f"{len(report.get('exploitable_cves', []))} exploitable, "
                        f"{len(report.get('negligible_cves', []))} negligible)"
                    )
                else:
                    logger.info("No CVEs found in findings for validation")
            else:
                logger.info("No findings to validate for CVEs")
    except Exception as e:
        logger.info(f"Validation engine failed: {e}")
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
