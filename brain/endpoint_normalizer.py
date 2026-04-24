"""
EndpointNormalizer: Parameter-Based Deduplication for Intelligent Scanning

This module groups endpoints by their parameter patterns to avoid redundant
vulnerability scanning on endpoints that share the same structure.

Example:
    /item.php?id=1 and /item.php?id=2 both normalize to /item.php?id={int}
    /search.php?q=apple and /search.php?q=banana normalize to /search.php?q={str}

Design: Stateful pattern cache with collision detection for confidence scoring.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


@dataclass
class EndpointPattern:
    """Represents a normalized endpoint pattern."""
    pattern: str  # Normalized form (e.g., /item.php?id={int})
    original_endpoints: List[str] = field(default_factory=list)
    vulnerability_type: Optional[str] = None  # e.g., "xss", "sqli", "lfi"
    scan_result_cache: Dict[str, any] = field(default_factory=dict)  # Results of scans performed
    is_scanned: bool = False
    confidence_reduction: float = 0.0  # Penalty applied if pattern wasn't exact

    def to_dict(self) -> Dict:
        return {
            "pattern": self.pattern,
            "original_endpoints": self.original_endpoints,
            "vulnerability_type": self.vulnerability_type,
            "is_scanned": self.is_scanned,
            "confidence_reduction": self.confidence_reduction,
        }


class EndpointNormalizer:
    """
    Intelligent endpoint normalizer that groups URLs by parameter patterns.

    This reduces redundant scanning by:
    1. Grouping endpoints with identical structures (/item.php?id={int})
    2. Tracking which patterns have already been scanned
    3. Providing confidence penalties when pattern assumptions don't hold
    """

    # Patterns for parameter type detection
    INT_PATTERN = re.compile(r"^\d+$")
    UUID_PATTERN = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
    )
    EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    MD5_PATTERN = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
    SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
    HEX_PATTERN = re.compile(r"^[a-f0-9]+$", re.IGNORECASE)

    def __init__(self):
        self.patterns: Dict[str, EndpointPattern] = {}
        self.endpoint_to_pattern: Dict[str, str] = {}  # Maps original endpoint → normalized pattern

    def infer_parameter_type(self, value: str) -> str:
        """Infer the type of a parameter value."""
        if self.INT_PATTERN.match(value):
            return "{int}"
        if self.UUID_PATTERN.match(value):
            return "{uuid}"
        if self.EMAIL_PATTERN.match(value):
            return "{email}"
        if self.SHA256_PATTERN.match(value):
            return "{sha256}"
        if self.MD5_PATTERN.match(value):
            return "{md5}"
        if self.HEX_PATTERN.match(value) and len(value) > 4:
            return "{hex}"
        return "{str}"

    def normalize_url(self, url: str) -> str:
        """
        Normalize a URL by replacing parameter values with type placeholders.

        Args:
            url: Original URL (e.g., https://example.com/item.php?id=123&name=test)

        Returns:
            Normalized pattern (e.g., /item.php?id={int}&name={str})
        """
        try:
            parsed = urlparse(url)
            path = parsed.path
            query_string = parsed.query

            if not query_string:
                return path

            # Parse query parameters
            params = parse_qs(query_string, keep_blank_values=True)
            normalized_params = {}

            for key, values in params.items():
                if values:
                    # Use first value for type inference
                    value = values[0] if isinstance(values, list) else values
                    param_type = self.infer_parameter_type(str(value))
                    normalized_params[key] = param_type

            # Reconstruct query string with normalized values
            if normalized_params:
                normalized_query = urlencode(
                    {k: v for k, v in normalized_params.items()}, doseq=True
                )
                return f"{path}?{normalized_query}"
            else:
                return path

        except Exception:
            # Fallback: return path only
            return urlparse(url).path

    def register_endpoint(
        self,
        endpoint: str,
        vulnerability_type: Optional[str] = None,
    ) -> Tuple[str, bool]:
        """
        Register an endpoint and return its normalized pattern.

        Args:
            endpoint: Original endpoint URL
            vulnerability_type: Type of vulnerability being tested (e.g., "xss")

        Returns:
            Tuple of (normalized_pattern, is_already_scanned)
        """
        # Check if already registered
        if endpoint in self.endpoint_to_pattern:
            pattern_key = self.endpoint_to_pattern[endpoint]
            pattern = self.patterns.get(pattern_key)
            is_scanned = pattern.is_scanned if pattern else False
            return pattern_key, is_scanned

        # Normalize the endpoint
        normalized = self.normalize_url(endpoint)
        pattern_key = f"{normalized}::{vulnerability_type}" if vulnerability_type else normalized

        # Check if pattern already exists
        if pattern_key in self.patterns:
            pattern = self.patterns[pattern_key]
            pattern.original_endpoints.append(endpoint)
            self.endpoint_to_pattern[endpoint] = pattern_key
            return pattern_key, pattern.is_scanned

        # Create new pattern
        pattern = EndpointPattern(
            pattern=normalized,
            original_endpoints=[endpoint],
            vulnerability_type=vulnerability_type,
        )
        self.patterns[pattern_key] = pattern
        self.endpoint_to_pattern[endpoint] = pattern_key

        return pattern_key, False

    def mark_pattern_scanned(
        self,
        pattern_key: str,
        result: Dict = None,
        confidence_adjustment: float = 0.0,
    ) -> None:
        """
        Mark a pattern as having been scanned.

        Args:
            pattern_key: The normalized pattern identifier
            result: Scan result to cache
            confidence_adjustment: Adjustment to apply (e.g., -0.1 if pattern variance detected)
        """
        if pattern_key in self.patterns:
            pattern = self.patterns[pattern_key]
            pattern.is_scanned = True
            if result:
                pattern.scan_result_cache = result
            pattern.confidence_reduction = confidence_adjustment

    def should_skip_scan(
        self,
        endpoint: str,
        vulnerability_type: Optional[str] = None,
    ) -> bool:
        """
        Determine if an endpoint should be skipped due to deduplication.

        Args:
            endpoint: Endpoint to check
            vulnerability_type: Type of vulnerability being tested

        Returns:
            True if pattern has already been scanned
        """
        pattern_key, is_scanned = self.register_endpoint(endpoint, vulnerability_type)
        return is_scanned

    def get_confidence_adjustment(self, pattern_key: str) -> float:
        """
        Get confidence score adjustment for a pattern.

        High-confidence patterns (exact type matches) get 0.0 adjustment.
        Lower-confidence patterns (string fallback) get -0.1 adjustment.

        Args:
            pattern_key: The normalized pattern identifier

        Returns:
            Confidence adjustment factor (-1.0 to 0.0)
        """
        if pattern_key in self.patterns:
            return self.patterns[pattern_key].confidence_reduction
        return 0.0

    def get_pattern_stats(self) -> Dict[str, any]:
        """Get statistics about registered patterns."""
        total_patterns = len(self.patterns)
        scanned_patterns = sum(1 for p in self.patterns.values() if p.is_scanned)
        total_endpoints = sum(
            len(p.original_endpoints) for p in self.patterns.values()
        )
        deduplication_ratio = (
            (total_endpoints - total_patterns) / total_endpoints
            if total_endpoints > 0
            else 0.0
        )

        return {
            "total_patterns": total_patterns,
            "scanned_patterns": scanned_patterns,
            "total_endpoints": total_endpoints,
            "deduplication_ratio": deduplication_ratio,
            "patterns_by_vuln_type": self._count_by_vuln_type(),
        }

    def _count_by_vuln_type(self) -> Dict[str, int]:
        """Count patterns by vulnerability type."""
        counts = {}
        for pattern in self.patterns.values():
            vuln_type = pattern.vulnerability_type or "generic"
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        return counts

    def get_pattern_candidates(self, base_pattern: str) -> List[str]:
        """
        Get all original endpoints that match a normalized pattern.

        Useful for: If you want to pick a specific endpoint from a pattern group
        to perform detailed exploitation.

        Args:
            base_pattern: Normalized pattern (e.g., /item.php?id={int})

        Returns:
            List of original endpoints matching the pattern
        """
        results = []
        for pattern_key, pattern in self.patterns.items():
            if pattern.pattern == base_pattern:
                results.extend(pattern.original_endpoints)
        return results

    def get_or_create_exploitation_variant(
        self,
        pattern_key: str,
        variant_endpoint: str,
    ) -> str:
        """
        After confirming a vulnerability on a pattern, get a specific endpoint
        variant for targeted exploitation (e.g., with different ID values for
        extracting different data).

        Args:
            pattern_key: The normalized pattern
            variant_endpoint: Specific endpoint to use for exploitation

        Returns:
            The variant endpoint (or first candidate if not in pattern group)
        """
        if pattern_key in self.patterns:
            pattern = self.patterns[pattern_key]
            if variant_endpoint in pattern.original_endpoints:
                return variant_endpoint
            elif pattern.original_endpoints:
                return pattern.original_endpoints[0]
        return variant_endpoint

    def clear(self) -> None:
        """Clear all patterns (for testing)."""
        self.patterns.clear()
        self.endpoint_to_pattern.clear()

    def export(self) -> Dict[str, List[Dict]]:
        """Export all patterns as serializable structure."""
        return {
            pattern_key: pattern.to_dict()
            for pattern_key, pattern in self.patterns.items()
        }
