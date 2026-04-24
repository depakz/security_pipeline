"""
FactStore: Centralized State Manager for Attack Prerequisites

This module provides a centralized fact store that tracks discovered prerequisites,
credentials, internal hosts, active sessions, and confirmed vulnerabilities.
Every node in the DAG can query this store to determine readiness and fetch facts
needed for sophisticated attack chaining.

Design Pattern: Singleton-like, thread-safe access to shared state.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime
from enum import Enum


class FactCategory(Enum):
    """Categories of facts that can be stored in the fact store."""
    CREDENTIAL = "credential"
    INTERNAL_HOST = "internal_host"
    ACTIVE_SESSION = "active_session"
    CONFIRMED_VULNERABILITY = "confirmed_vulnerability"
    SERVICE_INFO = "service_info"
    ENDPOINT_PATTERN = "endpoint_pattern"
    EXPLOITATION_ARTIFACT = "exploitation_artifact"
    METADATA_ENDPOINT = "metadata_endpoint"


@dataclass
class Fact:
    """Represents a discovered prerequisite or artifact."""
    category: FactCategory
    key: str  # Unique identifier (e.g., hostname, CVE-ID, cred_type)
    value: Any  # The actual fact data
    confidence: float = 0.8  # 0.0-1.0: how confident we are
    source_validator_id: Optional[str] = None  # Which validator discovered this
    source_chain: Optional[List[str]] = None  # Chain of vulnerabilities leading here
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "key": self.key,
            "value": self.value,
            "confidence": self.confidence,
            "source_validator_id": self.source_validator_id,
            "source_chain": self.source_chain or [],
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class PrerequisiteQuery:
    """Query object for checking if prerequisites are met."""
    required_facts: Dict[FactCategory, List[str]] = field(default_factory=dict)
    min_confidence: float = 0.7
    all_required: bool = True  # If True, all facts must exist; if False, any fact suffices

    def is_satisfied_by(self, fact_store: FactStore) -> bool:
        """Check if this query is satisfied by the fact store."""
        if not self.required_facts:
            return True

        facts_found = 0
        facts_needed = sum(len(keys) for keys in self.required_facts.values())

        for category, keys in self.required_facts.items():
            for key in keys:
                fact = fact_store.get_fact(category, key)
                if fact and fact.confidence >= self.min_confidence:
                    facts_found += 1

        if self.all_required:
            return facts_found == facts_needed
        else:
            return facts_found > 0


class FactStore:
    """
    Centralized state manager for discovered prerequisites and attack artifacts.

    Thread-safe singleton for storing:
    - discovered_creds (username/password, API keys, tokens)
    - internal_hosts (discovered internal IPs/hostnames)
    - active_sessions (authenticated session identifiers)
    - confirmed_vulnerabilities (validated exploitable conditions)
    - service_info (banners, versions, configurations)
    - endpoint_patterns (normalized URL patterns)
    - exploitation_artifacts (command outputs, file contents, etc.)
    """

    _instance: Optional[FactStore] = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._facts: Dict[FactCategory, Dict[str, Fact]] = {
            category: {} for category in FactCategory
        }
        self._lock = threading.Lock()
        self._initialized = True

    @staticmethod
    def reset():
        """Clear the singleton for testing."""
        FactStore._instance = None

    def add_fact(self, fact: Fact) -> None:
        """Add or update a fact in the store."""
        with self._lock:
            self._facts[fact.category][fact.key] = fact

    def add_credential(
        self,
        username: str,
        password: Optional[str] = None,
        token: Optional[str] = None,
        source_validator_id: Optional[str] = None,
        confidence: float = 0.95,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Fact:
        """Convenience method to add discovered credentials."""
        key = f"{username}:{password or token or 'unknown'}"
        fact = Fact(
            category=FactCategory.CREDENTIAL,
            key=key,
            value={"username": username, "password": password, "token": token},
            confidence=confidence,
            source_validator_id=source_validator_id,
            metadata=metadata or {},
        )
        self.add_fact(fact)
        return fact

    def add_internal_host(
        self,
        hostname: str,
        ip_address: Optional[str] = None,
        services: Optional[List[str]] = None,
        source_validator_id: Optional[str] = None,
        confidence: float = 0.85,
    ) -> Fact:
        """Convenience method to add discovered internal hosts."""
        fact = Fact(
            category=FactCategory.INTERNAL_HOST,
            key=hostname,
            value={"hostname": hostname, "ip": ip_address, "services": services or []},
            confidence=confidence,
            source_validator_id=source_validator_id,
        )
        self.add_fact(fact)
        return fact

    def add_confirmed_vulnerability(
        self,
        vuln_id: str,
        vuln_type: str,
        target: str,
        confidence: float = 0.9,
        source_validator_id: Optional[str] = None,
        source_chain: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Fact:
        """Add a confirmed exploitable vulnerability."""
        fact = Fact(
            category=FactCategory.CONFIRMED_VULNERABILITY,
            key=vuln_id,
            value={"type": vuln_type, "target": target},
            confidence=confidence,
            source_validator_id=source_validator_id,
            source_chain=source_chain or [],
            metadata=metadata or {},
        )
        self.add_fact(fact)
        return fact

    def add_active_session(
        self,
        session_id: str,
        session_token: str,
        target: str,
        auth_type: str = "session",
        source_validator_id: Optional[str] = None,
    ) -> Fact:
        """Add an established authenticated session."""
        fact = Fact(
            category=FactCategory.ACTIVE_SESSION,
            key=session_id,
            value={
                "session_token": session_token,
                "target": target,
                "auth_type": auth_type,
            },
            confidence=0.95,
            source_validator_id=source_validator_id,
        )
        self.add_fact(fact)
        return fact

    def add_exploitation_artifact(
        self,
        artifact_id: str,
        artifact_type: str,  # e.g., "ssh_key", "file_content", "shell_output"
        content: str,
        source_vulnerability: str,
        confidence: float = 0.95,
    ) -> Fact:
        """Add exploitation output (e.g., extracted SSH keys, file contents)."""
        fact = Fact(
            category=FactCategory.EXPLOITATION_ARTIFACT,
            key=artifact_id,
            value={"type": artifact_type, "content": content},
            confidence=confidence,
            metadata={"source_vulnerability": source_vulnerability},
        )
        self.add_fact(fact)
        return fact

    def get_fact(self, category: FactCategory, key: str) -> Optional[Fact]:
        """Retrieve a fact by category and key."""
        with self._lock:
            return self._facts[category].get(key)

    def get_facts_by_category(self, category: FactCategory) -> List[Fact]:
        """Get all facts in a category."""
        with self._lock:
            return list(self._facts[category].values())

    def query(
        self,
        category: FactCategory,
        predicate=None,
        min_confidence: float = 0.0,
    ) -> List[Fact]:
        """
        Query facts with optional filtering.

        Args:
            category: Fact category to search
            predicate: Optional callable(fact) -> bool for filtering
            min_confidence: Minimum confidence threshold

        Returns:
            List of matching facts
        """
        with self._lock:
            results = []
            for fact in self._facts[category].values():
                if fact.confidence < min_confidence:
                    continue
                if predicate is None or predicate(fact):
                    results.append(fact)
            return results

    def prerequisites_met(self, query: PrerequisiteQuery) -> bool:
        """Check if prerequisites for a DAG node are met."""
        return query.is_satisfied_by(self)

    def get_chain_facts(self, source_validator_id: str) -> List[Fact]:
        """Get all facts discovered from a specific validator (for attack chaining)."""
        results = []
        for category in FactCategory:
            for fact in self.get_facts_by_category(category):
                if fact.source_validator_id == source_validator_id:
                    results.append(fact)
        return results

    def clear(self) -> None:
        """Clear all facts (primarily for testing)."""
        with self._lock:
            for category in self._facts:
                self._facts[category].clear()

    def export(self) -> Dict[str, Any]:
        """Export all facts as serializable dictionary."""
        with self._lock:
            return {
                category.value: {
                    key: fact.to_dict()
                    for key, fact in self._facts[category].items()
                }
                for category in FactCategory
            }

    def get_summary(self) -> Dict[str, int]:
        """Get count of facts by category."""
        with self._lock:
            return {
                category.value: len(self._facts[category])
                for category in FactCategory
            }

    def get_facts_with_confidence(
        self, min_confidence: float = 0.7
    ) -> Dict[str, List[Fact]]:
        """Get all facts meeting minimum confidence threshold, grouped by category."""
        with self._lock:
            return {
                category.value: [
                    fact for fact in self._facts[category].values()
                    if fact.confidence >= min_confidence
                ]
                for category in FactCategory
            }

    def get_exploitation_chain(self, target_vuln_id: str) -> Optional[List[str]]:
        """
        Retrieve the complete attack chain leading to a vulnerability.
        Useful for understanding how a vulnerability was reachable.
        """
        fact = self.get_fact(FactCategory.CONFIRMED_VULNERABILITY, target_vuln_id)
        if fact:
            return fact.source_chain
        return None
