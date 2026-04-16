from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit, urlunsplit


_FILELIKE_PARAM_NAMES = {
    "file",
    "path",
    "page",
    "content",
    "template",
    "include",
    "view",
}

_SQLI_LIKELY_PARAM_NAMES = {
    "id",
    "uid",
    "user",
    "username",
    "account",
    "acct",
    "order",
    "product",
    "item",
    "category",
    "q",
    "query",
    "search",
}

_XSS_LIKELY_PARAM_NAMES = {
    "q",
    "query",
    "search",
    "s",
    "term",
    "message",
    "msg",
    "comment",
    "name",
    "email",
}


def _split_http_url(url: str) -> Optional[Tuple[str, Tuple[str, ...], List[Tuple[str, str]]]]:
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        return None

    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return None

    base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k]
    params = tuple(sorted({k for k, _ in pairs}))
    return base, params, pairs


def deduplicate_targets(urls: Iterable[str]) -> List[Dict[str, Any]]:
    """Group URLs into unique attack units by (base URL, parameter names)."""
    seen = set()
    unique: List[Dict[str, Any]] = []

    for url in urls:
        split = _split_http_url(url)
        if split is None:
            continue

        base, params, pairs = split
        key = (base, params)
        if key in seen:
            continue

        seen.add(key)
        unique.append(
            {
                "base": base,
                "params": params,
                "sample_url": url,
                "pairs": pairs,
            }
        )

    return unique


def _choose_attacks_for_unit(unit: Dict[str, Any]) -> List[str]:
    params = set(unit.get("params") or ())
    if not params:
        return []

    pairs = unit.get("pairs") or []
    if not isinstance(pairs, list):
        pairs = []

    values_by_param: Dict[str, List[str]] = {}
    for k, v in pairs:
        if not isinstance(k, str):
            continue
        values_by_param.setdefault(k, []).append("" if v is None else str(v))

    numeric_param_present = any(any(val.isdigit() for val in vals) for vals in values_by_param.values())

    # Routing / include params are usually not SQLi targets; keep the cheap XSS probe only.
    if params & _FILELIKE_PARAM_NAMES:
        return ["test_xss"]

    attacks: List[str] = []
    if params & _SQLI_LIKELY_PARAM_NAMES or numeric_param_present:
        attacks.append("test_sqli")

    # Default to XSS unless we have a strong reason not to.
    if params & _XSS_LIKELY_PARAM_NAMES or "test_sqli" not in attacks:
        attacks.append("test_xss")

    # Stable order
    return [a for a in ("test_sqli", "test_xss") if a in attacks]


def decide_actions(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    seen_actions = set()

    def add_action(action: str, endpoint: str, *, reason: str = "") -> None:
        split = _split_http_url(endpoint)
        if split is None:
            return
        base, params, _pairs = split

        key = (action, base, params)
        if key in seen_actions:
            return
        seen_actions.add(key)

        record: Dict[str, Any] = {
            "action": action,
            "endpoint": endpoint,
            "base": base,
            "params": list(params),
        }
        if reason:
            record["reason"] = reason
        actions.append(record)

    # 1) Forced actions derived from normalized findings (higher confidence)
    candidate_urls: List[str] = []
    forced_by_unit: Dict[Tuple[str, Tuple[str, ...]], List[str]] = {}

    for finding in (data.get("findings", []) or []):
        if not isinstance(finding, dict):
            continue

        title = (finding.get("title") or "").lower()
        tags = finding.get("tags") or []
        tags_l = [t.lower() for t in tags if isinstance(t, str)]

        evidence = finding.get("evidence") or {}
        endpoint = ""
        if isinstance(evidence, dict):
            endpoint = evidence.get("matched_url") or ""

        split = _split_http_url(endpoint)
        if split is None:
            continue

        base, params, _pairs = split
        unit_key = (base, params)

        forced = forced_by_unit.setdefault(unit_key, [])
        if "xss" in title or "xss" in tags_l:
            if "test_xss" not in forced:
                forced.append("test_xss")
        if "sql" in title or "sqli" in title or "sql" in tags_l or "sqli" in tags_l:
            if "test_sqli" not in forced:
                forced.append("test_sqli")

        candidate_urls.append(endpoint)

    # 2) Actions derived from discovered endpoints (gospider)
    for asset in (data.get("assets", []) or []):
        if not isinstance(asset, dict):
            continue
        for endpoint in (asset.get("endpoints", []) or []):
            if not isinstance(endpoint, str) or "?" not in endpoint:
                continue
            candidate_urls.append(endpoint)

    # 3) Deduplicate endpoints by structure and choose attacks per unit
    for unit in deduplicate_targets(candidate_urls):
        base = unit.get("base")
        params = unit.get("params") or ()
        key = (base, tuple(params) if isinstance(params, (list, tuple)) else ())

        forced = forced_by_unit.get((base, tuple(params))) if isinstance(base, str) else None
        if forced:
            for action in forced:
                add_action(action, unit.get("sample_url", ""), reason="finding")
            continue

        for action in _choose_attacks_for_unit(unit):
            add_action(action, unit.get("sample_url", ""), reason="dedup")

    return actions
