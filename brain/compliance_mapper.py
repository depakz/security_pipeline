"""Compliance mapping layer for converting technical findings into audit-friendly business risk labels."""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, Mapping


class ComplianceMapper:
    """Map technical vulnerability types to common compliance frameworks."""

    MAPPING: Dict[str, Dict[str, str]] = {
        "Broken Access Control": {
            "OWASP": "A01:2021-Broken Access Control",
            "PCI-DSS": "Requirement 7.2 / 8.3",
            "SOC2": "CC6.1 (Logical Access Controls)",
            "NIST": "SP 800-53 (AC-3 Access Enforcement)",
        },
        "Cryptographic Failures": {
            "OWASP": "A02:2021-Cryptographic Failures",
            "PCI-DSS": "Requirement 3.4 / 4.1",
            "SOC2": "CC6.7 (Encryption and Transmission Protection)",
            "NIST": "SP 800-53 (SC-8 Transmission Confidentiality and Integrity)",
        },
        "Identification and Authentication Failures": {
            "OWASP": "A07:2021-Identification and Authentication Failures",
            "PCI-DSS": "Requirement 8.2",
            "SOC2": "CC6.1 (Access Protection)",
            "NIST": "SP 800-53 (IA-2 Identification and Authentication)",
        },
        "Security Logging and Monitoring Failures": {
            "OWASP": "A09:2021-Security Logging and Monitoring Failures",
            "PCI-DSS": "Requirement 10.2 / 10.6",
            "SOC2": "CC7.2 (Change Detection) / CC7.3 (Monitoring)",
            "NIST": "SP 800-53 (AU-2 Event Logging / AU-6 Audit Review)",
        },
        "Security Misconfiguration": {
            "OWASP": "A05:2021-Security Misconfiguration",
            "PCI-DSS": "Requirement 2.2 / 6.5",
            "SOC2": "CC7.1 (System Operations)",
            "NIST": "SP 800-53 (CM-6 Configuration Settings)",
        },
        "Vulnerable and Outdated Components": {
            "OWASP": "A06:2021-Vulnerable and Outdated Components",
            "PCI-DSS": "Requirement 6.3.3 / 6.3.4",
            "SOC2": "CC8.1 (Change Management)",
            "NIST": "SP 800-53 (SI-2 Flaw Remediation)",
        },
        "SSRF": {
            "OWASP": "A10:2021-Server-Side Request Forgery",
            "PCI-DSS": "Requirement 6.4.1",
            "SOC2": "CC7.1 (System Monitoring)",
            "NIST": "SP 800-53 (SI-4 Information System Monitoring)",
        },
        "Injection": {
            "OWASP": "A03:2021-Injection",
            "PCI-DSS": "Requirement 6.2",
            "SOC2": "CC7.2 (Change Detection)",
            "NIST": "SP 800-53 (SI-10 Input Validation)",
        },
        "Insecure Design": {
            "OWASP": "A04:2021-Insecure Design",
            "PCI-DSS": "Requirement 6.2",
            "SOC2": "CC7.2 (Change Detection)",
            "NIST": "SP 800-53 (SA-15 Development Process, Standards, and Tools)",
        },
        "Exposed Credentials": {
            "OWASP": "A07:2021-Identification and Authentication Failures",
            "PCI-DSS": "Requirement 8.2",
            "SOC2": "CC6.1 (Access Protection)",
            "NIST": "SP 800-53 (IA-2 Identification and Authentication)",
        },
        "Insecure Deserialization": {
            "OWASP": "A08:2021-Software and Data Integrity Failures",
            "PCI-DSS": "Requirement 6.2",
            "SOC2": "CC7.2 (Change Detection)",
            "NIST": "SP 800-53 (SI-7 Software, Firmware, and Information Integrity)",
        },
        "Unsigned Packages": {
            "OWASP": "A08:2021-Software and Data Integrity Failures",
            "PCI-DSS": "Requirement 6.2",
            "SOC2": "CC7.2 (Change Detection)",
            "NIST": "SP 800-53 (SI-7 Software, Firmware, and Information Integrity)",
        },
    }

    DEFAULT_MAPPING: Dict[str, str] = {
        "OWASP": "General Security Requirement",
        "PCI-DSS": "Review Required",
        "SOC2": "Control Review Required",
        "NIST": "Control Review Required",
    }

    @classmethod
    def _normalize_key(cls, vulnerability_type: str) -> str:
        value = (vulnerability_type or "").strip().lower()
        if not value:
            return ""
        if "access control" in value or "idor" in value or "forbidden bypass" in value or "broken access" in value:
            return "Broken Access Control"
        if "crypt" in value or "tls" in value or "ssl" in value or "cipher" in value:
            return "Cryptographic Failures"
        if "misconfig" in value or "trace" in value or "options" in value or "default config" in value:
            return "Security Misconfiguration"
        if "outdated" in value or "component" in value or "cve" in value or "vulnerable package" in value:
            return "Vulnerable and Outdated Components"
        if "auth" in value or "login" in value or "credential" in value or "password" in value:
            return "Identification and Authentication Failures"
        if "log" in value or "monitor" in value or "audit" in value:
            return "Security Logging and Monitoring Failures"
        if "ssrf" in value:
            return "SSRF"
        if "inject" in value or "sqli" in value or "xss" in value or "command" in value:
            return "Injection"
        if "design" in value or "workflow" in value or "state" in value or "transition" in value:
            return "Insecure Design"
        if "credential" in value or "password" in value or "token" in value:
            return "Exposed Credentials"
        if "deserialization" in value or "serialization" in value:
            return "Insecure Deserialization"
        if "package" in value or "signature" in value or "integrity" in value:
            return "Unsigned Packages"
        return vulnerability_type.strip()

    @classmethod
    @lru_cache(maxsize=128)
    def get_compliance_tags(cls, vulnerability_type: str) -> Dict[str, str]:
        """Return compliance framework labels for a technical vulnerability type."""
        key = cls._normalize_key(vulnerability_type)
        if not key:
            return dict(cls.DEFAULT_MAPPING)
        return dict(cls.MAPPING.get(key, cls.DEFAULT_MAPPING))

    @classmethod
    def get_business_risk_summary(cls, vulnerability_type: str) -> str:
        """Return a short auditor-friendly summary string."""
        tags = cls.get_compliance_tags(vulnerability_type)
        return " | ".join(f"{framework}: {label}" for framework, label in tags.items())

    @classmethod
    def annotate_record(cls, record: Mapping[str, Any]) -> Dict[str, Any]:
        """Attach compliance metadata to a record without mutating the input."""
        item = dict(record)
        vulnerability_type = str(
            item.get("vulnerability_type")
            or item.get("vulnerability")
            or item.get("title")
            or ""
        )
        item["compliance_tags"] = cls.get_compliance_tags(vulnerability_type)
        item["business_risk"] = cls.get_business_risk_summary(vulnerability_type)
        return item
