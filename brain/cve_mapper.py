"""
CVE to Validator Mapping
Maps CVE IDs discovered by Nuclei to applicable validators for verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class CVESpec:
    """CVE specification with validation mapping"""
    cve_id: str
    title: str
    description: str
    severity: str
    applicable_validators: List[str]  # List of validator IDs that can verify this CVE
    keywords: List[str] = None


# Redis CVE mappings
REDIS_CVE_SPECS: List[CVESpec] = [
    CVESpec(
        cve_id="CVE-2025-46817",
        title="Redis < 8.2.1 lua script - Integer Overflow",
        description="Authenticated user can use specially crafted Lua script to cause integer overflow and RCE",
        severity="critical",
        applicable_validators=["redis_no_auth"],
        keywords=["redis", "lua", "integer overflow", "rce", "8.2.1"],
    ),
    CVESpec(
        cve_id="CVE-2025-49844",
        title="Redis Lua Parser < 8.2.2 - Use After Free",
        description="Authenticated user can manipulate garbage collector via crafted Lua scripts for RCE",
        severity="critical",
        applicable_validators=["redis_no_auth"],
        keywords=["redis", "lua", "use after free", "rce", "8.2.2"],
    ),
    CVESpec(
        cve_id="CVE-2025-46819",
        title="Redis < 8.2.1 Lua Long-String Delimiter - Out-of-Bounds Read",
        description="Authenticated user can read out-of-bounds data or crash server via Lua scripts",
        severity="high",
        applicable_validators=["redis_no_auth"],
        keywords=["redis", "lua", "out of bounds", "dos", "8.2.1"],
    ),
    CVESpec(
        cve_id="CVE-2025-46818",
        title="Redis Lua Sandbox < 8.2.2 - Cross-User Escape",
        description="Authenticated user can escape Lua sandbox and run code in context of another user",
        severity="high",
        applicable_validators=["redis_no_auth"],
        keywords=["redis", "lua", "sandbox escape", "privilege escalation", "8.2.2"],
    ),
]

# All CVE specs (can expand with more)
ALL_CVE_SPECS: List[CVESpec] = REDIS_CVE_SPECS


def get_cve_specs() -> Dict[str, CVESpec]:
    """Get all CVE specs indexed by CVE ID"""
    return {spec.cve_id: spec for spec in ALL_CVE_SPECS}


def extract_cve_ids(finding: Dict[str, Any]) -> List[str]:
    """Extract CVE IDs from a finding record"""
    cve_ids = []
    
    # Check direct CVE field
    if "cve" in finding:
        cves = finding.get("cve")
        if isinstance(cves, list):
            cve_ids.extend([c for c in cves if isinstance(c, str) and c.startswith("CVE-")])
        elif isinstance(cves, str) and cves.startswith("CVE-"):
            cve_ids.append(cves)
    
    # Check title for CVE patterns
    title = finding.get("title", "").upper()
    for spec in ALL_CVE_SPECS:
        if spec.cve_id in title:
            cve_ids.append(spec.cve_id)
    
    return list(set(cve_ids))  # Remove duplicates


def find_applicable_validators(cve_id: str) -> List[str]:
    """
    Find validators applicable for a given CVE ID.
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2025-46817)
    
    Returns:
        List of validator IDs that can verify this CVE
    """
    cve_specs = get_cve_specs()
    cve_spec = cve_specs.get(cve_id)
    
    if cve_spec:
        return cve_spec.applicable_validators
    
    return []


def get_cve_info(cve_id: str) -> Optional[CVESpec]:
    """Get CVE spec by ID"""
    return get_cve_specs().get(cve_id)


class CVEMapper:
    """Maps findings to CVEs and determines which validators should run"""
    
    def __init__(self):
        self.cve_specs = get_cve_specs()
    
    def map_findings_to_cves(self, findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Map findings to CVE IDs and their applicable validators.
        
        Args:
            findings: List of finding dicts from scanner results
        
        Returns:
            Dict mapping CVE ID → list of validator IDs to run
        """
        cve_to_validators: Dict[str, List[str]] = {}
        
        for finding in findings:
            cve_ids = extract_cve_ids(finding)
            for cve_id in cve_ids:
                if cve_id in self.cve_specs:
                    validators = self.cve_specs[cve_id].applicable_validators
                    if cve_id not in cve_to_validators:
                        cve_to_validators[cve_id] = []
                    cve_to_validators[cve_id].extend(validators)
        
        # Remove duplicates in each list
        for cve_id in cve_to_validators:
            cve_to_validators[cve_id] = list(set(cve_to_validators[cve_id]))
        
        return cve_to_validators
    
    def get_cve_verdict_data(self, cve_id: str) -> Dict[str, Any]:
        """Get CVE title and metadata for reporting"""
        spec = self.cve_specs.get(cve_id)
        if spec:
            return {
                "cve_id": spec.cve_id,
                "title": spec.title,
                "description": spec.description,
                "severity": spec.severity,
            }
        return {
            "cve_id": cve_id,
            "title": "Unknown CVE",
            "description": "",
            "severity": "unknown",
        }
