from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

OUTPUT_FILE = "output/site_finder.json"

COMMON_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/favicon.ico",
    "/manifest.json",
    "/api",
    "/api/",
    "/graphql",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui/",
    "/openapi.json",
    "/openapi.yaml",
    "/health",
    "/status",
    "/login",
    "/signin",
    "/signup",
    "/register",
    "/admin",
    "/dashboard",
    "/search",
    "/feed",
    "/rss",
    "/actuator",
    "/phpinfo.php",
    "/server-status",
    "/crossdomain.xml",
    "/humans.txt",
    "/.git/HEAD",
    "/.env",
]

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
PATH_RE = re.compile(r"(?:href|src|action|data-src|poster)=['\"]([^'\"]+)['\"]", re.IGNORECASE)
JS_PATH_RE = re.compile(r"(?:['\"])(/[^'\"\s]{1,200})(?:['\"])")


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: Set[str] = set()
        self.scripts: Set[str] = set()
        self.forms: Set[str] = set()
        self.meta_refresh: Set[str] = set()

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_map = {k.lower(): v for k, v in attrs if k and v}
        for key in ("href", "src", "action", "data-src", "poster"):
            value = attr_map.get(key)
            if value:
                self.links.add(value)
                if key == "src" and tag.lower() == "script":
                    self.scripts.add(value)
                if key == "action" and tag.lower() == "form":
                    self.forms.add(value)
        if tag.lower() == "meta":
            http_equiv = (attr_map.get("http-equiv") or "").lower()
            content = attr_map.get("content") or ""
            if http_equiv == "refresh":
                m = re.search(r"url=(.+)$", content, re.IGNORECASE)
                if m:
                    self.meta_refresh.add(m.group(1).strip())

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs)


def _resolve_binary(_: str):
    return None


def _base_variants(target: str) -> List[str]:
    if not isinstance(target, str) or not target:
        return []
    if target.startswith(("http://", "https://")):
        parts = urlsplit(target)
        root = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
        if parts.path and parts.path not in ("", "/"):
            return [target, root]
        return [root]
    return [f"https://{target}", f"http://{target}"]


def _normalize_url(url: str, base_url: str) -> Optional[str]:
    if not isinstance(url, str):
        return None
    candidate = url.strip()
    if not candidate:
        return None
    if candidate.startswith(("javascript:", "mailto:", "tel:", "data:")):
        return None
    if candidate.startswith("//"):
        base = urlsplit(base_url)
        return f"{base.scheme}:{candidate}"
    if candidate.startswith(("http://", "https://")):
        return candidate
    return urljoin(base_url, candidate)


def _same_origin(url: str, base_url: str) -> bool:
    try:
        candidate = urlsplit(url)
        base = urlsplit(base_url)
        return candidate.scheme in ("http", "https") and candidate.netloc == base.netloc
    except Exception:
        return False


def _fetch(url: str, cookie: Optional[str] = None) -> Tuple[str, str, Dict[str, Any]]:
    headers = {"User-Agent": "security-pipeline-site-finder/1.0"}
    if isinstance(cookie, str) and cookie.strip():
        headers["Cookie"] = cookie.strip()
    response = requests.get(url, headers=headers, allow_redirects=True)
    body = response.text or ""
    return body, response.url or url, dict(response.headers)


def _discover_from_text(text: str, base_url: str) -> Set[str]:
    discovered: Set[str] = set()
    if not text:
        return discovered

    for match in URL_RE.findall(text):
        normalized = _normalize_url(match, base_url)
        if normalized:
            discovered.add(normalized)

    for match in PATH_RE.findall(text):
        normalized = _normalize_url(match, base_url)
        if normalized:
            discovered.add(normalized)

    for match in JS_PATH_RE.findall(text):
        normalized = _normalize_url(match, base_url)
        if normalized:
            discovered.add(normalized)

    return discovered


def run_site_finder(target: str, cookie: Optional[str] = None) -> str:
    endpoints: Set[str] = set()
    hostnames: Set[str] = set()
    sources: List[Dict[str, Any]] = []
    visited: Set[str] = set()

    bases = _base_variants(target)
    queue: List[str] = list(bases)

    for base_url in bases:
        parsed = urlsplit(base_url)
        if parsed.hostname:
            hostnames.add(parsed.hostname)

    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        try:
            body, final_url, headers = _fetch(current, cookie=cookie)
        except Exception as exc:
            sources.append({"url": current, "error": str(exc)})
            continue

        endpoints.add(final_url)
        host = urlsplit(final_url).hostname
        if host:
            hostnames.add(host)

        if body:
            parser = _LinkParser()
            try:
                parser.feed(body)
            except Exception:
                pass

            discovered = set()
            discovered.update(_discover_from_text(body, final_url))
            for link in parser.links | parser.scripts | parser.forms | parser.meta_refresh:
                normalized = _normalize_url(link, final_url)
                if normalized:
                    discovered.add(normalized)

            for link in discovered:
                if _same_origin(link, final_url):
                    endpoints.add(link)
                    if link not in visited and len(visited) < 50:
                        queue.append(link)

        for path in COMMON_PATHS:
            candidate = urljoin(final_url, path)
            endpoints.add(candidate)

        sources.append(
            {
                "url": current,
                "final_url": final_url,
                "headers": headers,
                "links_discovered": len(endpoints),
            }
        )

        if len(visited) >= 25:
            break

    normalized_endpoints = sorted({ep for ep in endpoints if isinstance(ep, str) and ep.startswith(("http://", "https://"))})
    data = {
        "target": target,
        "endpoints": normalized_endpoints,
        "hostnames": sorted(hostnames),
        "sources": sources,
        "discovered_count": len(normalized_endpoints),
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)

    return OUTPUT_FILE
