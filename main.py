import json
import sys
import time
from datetime import datetime, timezone
import threading
import inspect
from engine.validation_engine import ValidationEngine
from validators.redis import RedisNoAuthValidator
from validators.http import MissingSecurityHeadersValidator
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

        endpoints = asset.get("endpoints", []) or []
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

    return {
        "target": target,
        "ports": sorted(set(ports)),
        "protocols": sorted(set(protocols)),
        "url": url,
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
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <target>")
        sys.exit(1)

    target = sys.argv[1]
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
        logger.info("Running validation engine...")
        state = build_validation_state(parsed_data)

        vengine = ValidationEngine()
        vengine.register(RedisNoAuthValidator())
        vengine.register(MissingSecurityHeadersValidator())

        validation_results = vengine.run(state)
        with open("output/validations.json", "w") as f:
            json.dump(validation_results, f, indent=4)

        logger.info(f"Validation results saved to output/validations.json ({len(validation_results)} results)")
    except Exception as e:
        logger.info(f"Validation engine failed: {e}")

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
