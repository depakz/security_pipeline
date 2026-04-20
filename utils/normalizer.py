from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlparse, urlsplit


_TAG_ORDER = ["admin_panel", "auth", "api", "params", "file", "debug"]
_TAG_ORDER_INDEX = {tag: idx for idx, tag in enumerate(_TAG_ORDER)}

_STATIC_EXTENSIONS = {
    ".css",
    ".js",
    ".mjs",
    ".cjs",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".bmp",
    ".tif",
    ".tiff",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
}

_FILELIKE_PARAM_NAMES = {
    "file",
    "path",
    "page",
    "content",
    "template",
    "include",
    "view",
    "download",
    "upload",
}


def extract_target_host(target: str) -> str:
    """Best-effort target host extractor (accepts host or URL)."""

    if not isinstance(target, str):
        return ""

    t = target.strip()
    if not t:
        return ""

    if "://" in t:
        try:
            parsed = urlparse(t)
            return (parsed.hostname or "").strip(".")
        except Exception:
            t = t.split("://", 1)[-1]

    # host[:port][/path]
    host = t.split("/", 1)[0].split(":", 1)[0]
    return host.strip(".")


def in_scope_hostname(hostname: str, target_host: str) -> bool:
    if not hostname or not target_host:
        return False
    h = str(hostname).lower().strip(".")
    t = str(target_host).lower().strip(".")
    return h == t or h.endswith("." + t)


def normalize_path(path: str) -> str:
    """Normalize URL paths to avoid duplicates like /a and /a/."""

    if not isinstance(path, str):
        return "/"

    p = path.strip()
    if not p:
        p = "/"

    if not p.startswith("/"):
        p = "/" + p

    # Collapse multiple slashes
    p = re.sub(r"/{2,}", "/", p)

    # Remove trailing slash except root
    if p != "/" and p.endswith("/"):
        p = p.rstrip("/")

    return p


def extract_param_names(query: str) -> List[str]:
    if not isinstance(query, str) or not query:
        return []

    names = {k for k, _ in parse_qsl(query, keep_blank_values=True) if k}
    return sorted(names)


def is_noise_url(url_or_path: str) -> bool:
    """Return True for static assets (.css/.js/images/fonts) that should be dropped."""

    if not isinstance(url_or_path, str):
        return True

    s = url_or_path.strip()
    if not s:
        return True

    try:
        parts = urlsplit(s)
        path = parts.path or s
    except Exception:
        path = s

    path = normalize_path(path)

    # Quick common static files
    lower_path = path.lower()
    if lower_path in ("/favicon.ico",):
        return True

    # Check extension
    last_segment = lower_path.rsplit("/", 1)[-1]
    if "." in last_segment:
        ext = "." + last_segment.rsplit(".", 1)[-1]
        if ext in _STATIC_EXTENSIONS:
            return True

    return False


def extract_tags(path: str, params: Sequence[str]) -> List[str]:
    tags: Set[str] = set()

    p = (path or "").lower()

    if "admin" in p or p.startswith("/admin"):
        tags.add("admin_panel")

    if any(token in p for token in ("/login", "/signin", "/sign-in", "/logout", "/auth", "/register")):
        tags.add("auth")

    if p.startswith("/api") or "/api/" in p:
        tags.add("api")

    if params:
        tags.add("params")

    params_l = {str(param).lower() for param in params if isinstance(param, str)}

    if "upload" in p or "file" in p or (params_l & _FILELIKE_PARAM_NAMES):
        tags.add("file")

    if any(token in p for token in ("debug", "trace", "stacktrace", "test")):
        tags.add("debug")

    return sorted(tags, key=lambda t: (_TAG_ORDER_INDEX.get(t, 999), t))


def normalize_endpoints(
    raw_urls: Iterable[str],
    *,
    target: str = "",
    default_method: str = "GET",
) -> List[Dict[str, Any]]:
    """Convert raw URLs into deduped endpoint objects.

    Output schema:
      { "url": "/path", "method": "GET", "params": [..], "tags": [..] }

    Dedup key: (method, normalized_path). Params/tags are unioned across duplicates.
    """

    target_host = extract_target_host(target)

    by_key: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for item in raw_urls or []:
        if not isinstance(item, str):
            continue
        s = item.strip()
        if not s:
            continue

        if is_noise_url(s):
            continue

        hostname = ""
        path = ""
        query = ""

        # Absolute URL
        if "://" in s:
            try:
                parts = urlsplit(s)
                if parts.scheme and parts.scheme.lower() not in ("http", "https"):
                    continue
                hostname = parts.hostname or ""
                path = parts.path or ""
                query = parts.query or ""
            except Exception:
                continue

            if target_host and hostname and not in_scope_hostname(hostname, target_host):
                continue

        else:
            # Path-only form: /api/user?id=1
            try:
                parts = urlsplit(s)
                path = parts.path or ""
                query = parts.query or ""
            except Exception:
                # Fallback: treat whole thing as path
                path = s
                query = ""

        norm_path = normalize_path(path)
        params = extract_param_names(query)
        tags = extract_tags(norm_path, params)

        method = (default_method or "GET").upper().strip() or "GET"
        key = (method, norm_path)

        entry = by_key.get(key)
        if entry is None:
            entry = {
                "url": norm_path,
                "method": method,
                "params": [],
                "tags": [],
            }
            by_key[key] = entry

        # union params/tags
        existing_params = set(entry.get("params") or [])
        for p in params:
            if p not in existing_params:
                existing_params.add(p)
        entry["params"] = sorted(existing_params)

        existing_tags = set(entry.get("tags") or [])
        for t in tags:
            if t not in existing_tags:
                existing_tags.add(t)
        entry["tags"] = sorted(existing_tags, key=lambda t: (_TAG_ORDER_INDEX.get(t, 999), t))

    # stable output ordering
    out = list(by_key.values())
    out.sort(key=lambda e: (str(e.get("url") or ""), str(e.get("method") or "")))
    return out
