"""Central attack variant catalog for deeper OWASP validator coverage."""

from __future__ import annotations

from typing import Dict, List


ATTACK_VARIANT_CATALOG: Dict[str, Dict[str, List[str]]] = {
    "A02": {
        "sensitive_headers": [
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
            "X-API-Key",
            "X-Auth-Token",
            "X-Access-Token",
            "X-Amz-Security-Token",
        ],
        "weak_tls_versions": ["TLSv1", "TLSv1.1"],
    },
    "A03": {
        "sqli_payloads": ["1'", "1\"", "1' OR '1'='1", "1) OR (1=1--"],
        "xss_payloads": [
            "<svg onload=alert(1)>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
        ],
        "command_payloads": ["||echo SECURITY_PIPELINE_A03", ";echo SECURITY_PIPELINE_A03", "$(echo SECURITY_PIPELINE_A03)"],
        "file_payloads": ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc/passwd"],
        "template_payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
        "ldap_payloads": ["*)(uid=*)", "*)(|(uid=*))", "*)(cn=*)"],
    },
    "A05": {
        "method_variants": ["OPTIONS", "TRACE"],
        "debug_markers": ["stack trace", "exception in thread", "debug=true", "directory listing"],
    },
    "A06": {
        "version_headers": ["Server", "X-Powered-By", "Via"],
        "cve_pattern_hints": ["CVE-"],
    },
    "A10": {
        "ssrf_params": ["url", "uri", "dest", "destination", "next", "redirect", "path", "callback", "endpoint", "target", "host"],
        "loopback_targets": [
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://localhost",
            "http://127.1",
            "http://2130706433",
            "http://0.0.0.0",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",
        ],
    },
}


def get_attack_variants(category: str, key: str, defaults: List[str]) -> List[str]:
    section = ATTACK_VARIANT_CATALOG.get(category, {})
    variants = section.get(key)
    if not isinstance(variants, list) or not variants:
        return list(defaults)
    return [item for item in variants if isinstance(item, str) and item.strip()]
