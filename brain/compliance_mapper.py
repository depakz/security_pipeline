"""Compliance mapping layer for converting technical findings into audit-friendly business risk labels."""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, Mapping


class ComplianceMapper:
    """Map technical vulnerability types to common compliance frameworks."""

    MAPPING: Dict[str, Dict[str, str]] = {
        "SSRF": {
            "OWASP": "A10:2021-Server-Side Request Forgery",
            "PCI-DSS": "Requirement 6.4.1",
            "SOC2": "CC7.1 (System Monitoring)",
            "NIST": "SP 800-53 (SI-4 Information System Monitoring)",
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
        if "ssrf" in value:
            return "SSRF"
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
