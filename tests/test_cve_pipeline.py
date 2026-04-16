#!/usr/bin/env python3
"""
Test script to verify CVE detection and validation pipeline
"""

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from brain.dag_engine import DAGBrain
from brain.exploitability_reporter import ExploitabilityReporter
from brain.cve_mapper import CVEMapper

def test_cve_mapping():
    """Test that CVE extraction and mapping works"""
    print("\n=== Testing CVE Mapping ===")
    
    # Simulate findings from Nuclei scan
    findings = [
        {
            "title": "Redis No Authentication - CVE-2025-46817",
            "cve": "CVE-2025-46817",
            "severity": "critical",
            "template": "redis-no-auth",
        },
        {
            "title": "Redis Lua Script Vulnerability - CVE-2025-49844",
            "cve": "CVE-2025-49844",
            "severity": "critical",
            "template": "redis-lua-vuln",
        },
    ]
    
    mapper = CVEMapper()
    cve_to_validators = mapper.map_findings_to_cves(findings)
    
    print(f"Findings: {len(findings)}")
    print(f"CVEs found: {len(cve_to_validators)}")
    for cve_id, validators in cve_to_validators.items():
        cve_data = mapper.get_cve_verdict_data(cve_id)
        print(f"  {cve_id}: {cve_data['title']}")
        print(f"    Validators: {validators}")
        print(f"    Severity: {cve_data['severity']}")
    
    return cve_to_validators


def test_cve_plan():
    """Test CVE-aware validation planning"""
    print("\n=== Testing CVE Validation Planning ===")
    
    findings = [
        {
            "title": "Redis No Authentication - CVE-2025-46817",
            "cve": "CVE-2025-46817",
            "severity": "critical",
        },
    ]
    
    state = {
        "target": "redis.example.com",
        "ports": ["6379"],
        "protocols": ["tcp"],
        "url": "redis.example.com:6379",
    }
    
    dag_brain = DAGBrain()
    cve_plan = dag_brain.plan_cve_validations(state, findings)
    
    print(f"CVEs to validate: {len(cve_plan.cve_to_validators)}")
    print(f"Validators to run: {list(cve_plan.validator_instances.keys())}")
    print(f"CVE details: {json.dumps(cve_plan.cve_details, indent=2)}")
    
    return cve_plan


def test_verdict_generation():
    """Test exploitability verdict generation"""
    print("\n=== Testing Verdict Generation ===")
    
    cve_details = {
        "CVE-2025-46817": {
            "cve_id": "CVE-2025-46817",
            "title": "Redis < 8.2.1 lua script - Integer Overflow",
            "description": "Authenticated user can use specially crafted Lua script to cause integer overflow and RCE",
            "severity": "critical",
        },
    }
    
    # Simulate validation results
    validation_results = [
        {
            "vulnerability": "redis_no_auth",
            "validation": {
                "status": "confirmed",
                "confidence": 0.95,
            },
            "evidence": {
                "port": 6379,
                "auth_required": False,
                "response": "PING",
            },
            "severity": "critical",
        },
    ]
    
    reporter = ExploitabilityReporter()
    
    # Generate verdict for each CVE
    verdicts = []
    for cve_id, cve_data in cve_details.items():
        verdict = reporter.generate_verdict(
            cve_data=cve_data,
            validation_results=validation_results,
            validators_tested=list(cve_details.keys()),
        )
        verdicts.append(verdict)
    
    # Generate full report
    report = reporter.generate_report(verdicts)
    
    print(f"Report summary:")
    print(f"  Exploitable CVEs: {len(report.get('exploitable_cves', []))}")
    print(f"  False Positive CVEs: {len(report.get('false_positive_cves', []))}")
    print(f"  Negligible CVEs: {len(report.get('negligible_cves', []))}")
    print(f"  Untested CVEs: {len(report.get('untested_cves', []))}")
    
    if report.get('exploitable_cves'):
        print(f"\nExploitable CVEs:")
        for record in report['exploitable_cves']:
            print(f"  {record['cve_id']}: {record['title']}")
            print(f"    Verdict: {record['verdict']} (confidence: {record.get('confidence', 'N/A')})")
    
    return report


if __name__ == "__main__":
    print("Testing CVE Pipeline Integration")
    print("=" * 50)
    
    try:
        cve_map = test_cve_mapping()
        cve_plan = test_cve_plan()
        report = test_verdict_generation()
        
        print("\n" + "=" * 50)
        print("✅ All tests passed!")
        print("=" * 50)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
