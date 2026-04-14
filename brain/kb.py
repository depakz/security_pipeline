from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List


@dataclass(frozen=True)
class ValidatorSpec:
    id: str
    name: str
    class_path: str
    description: str
    severity: str = "info"
    keywords: List[str] = field(default_factory=list)
    required_ports: List[int] = field(default_factory=list)
    required_protocols: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class VulnerabilitySpec:
    id: str
    title: str
    description: str
    severity: str = "info"
    keywords: List[str] = field(default_factory=list)


DEFAULT_VALIDATOR_SPECS: List[ValidatorSpec] = [
    ValidatorSpec(
        id="redis_no_auth",
        name="RedisNoAuthValidator",
        class_path="validators.redis.RedisNoAuthValidator",
        description="Checks whether Redis is reachable on port 6379 without authentication.",
        severity="high",
        keywords=["redis", "6379", "unauthenticated", "no auth"],
        required_ports=[6379],
    ),
    ValidatorSpec(
        id="missing_security_headers",
        name="MissingSecurityHeadersValidator",
        class_path="validators.http.MissingSecurityHeadersValidator",
        description="Checks for missing security headers on HTTP endpoints.",
        severity="info",
        keywords=["http", "headers", "csp", "x-frame-options"],
        required_protocols=["http"],
    ),
]


DEFAULT_VULNERABILITY_SPECS: List[VulnerabilitySpec] = [
    VulnerabilitySpec(
        id="redis-no-auth",
        title="Unauthenticated Redis Access",
        description="Redis exposed on 6379 and accepting unauthenticated connections.",
        severity="high",
        keywords=["redis", "6379", "auth"],
    ),
    VulnerabilitySpec(
        id="missing-security-headers",
        title="Missing Security Headers",
        description="HTTP response missing baseline defensive headers.",
        severity="info",
        keywords=["headers", "csp", "x-frame-options", "http"],
    ),
]


def get_default_validator_specs() -> List[ValidatorSpec]:
    return list(DEFAULT_VALIDATOR_SPECS)


def get_default_vulnerability_specs() -> List[VulnerabilitySpec]:
    return list(DEFAULT_VULNERABILITY_SPECS)


def extract_keywords(value: Any) -> List[str]:
    keywords: List[str] = []
    if isinstance(value, str):
        keywords.append(value.lower())
    elif isinstance(value, dict):
        for item in value.values():
            keywords.extend(extract_keywords(item))
    elif isinstance(value, list):
        for item in value:
            keywords.extend(extract_keywords(item))
    elif value is not None:
        keywords.append(str(value).lower())
    return keywords