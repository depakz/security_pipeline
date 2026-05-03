from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

OUTPUT_FILE = "output/headless_browser.json"
MAX_VISITED_PAGES = 20
MAX_DISCOVERED_URLS = 500


def _normalize_target(target: str) -> List[str]:
    if not isinstance(target, str) or not target.strip():
        return []
    value = target.strip()
    if value.startswith(("http://", "https://")):
        return [value]
    return [f"https://{value}", f"http://{value}"]


def _same_origin(base_url: str, candidate_url: str) -> bool:
    try:
        base = urlparse(base_url)
        candidate = urlparse(candidate_url)
        return bool(base.scheme and base.netloc and candidate.scheme and candidate.netloc and base.scheme == candidate.scheme and base.netloc == candidate.netloc)
    except Exception:
        return False


def _looks_like_navigation_value(value: str) -> bool:
    if not value:
        return False
    value = value.strip()
    if not value:
        return False
    if value.startswith(("http://", "https://", "/", "./", "../", "#")):
        return True
    if value.startswith("javascript:"):
        return False
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_#?&=.-:")
    return all(char in allowed_chars for char in value)


def _resolve_candidate(current_url: str, raw_value: str) -> Optional[str]:
    if not raw_value or not _looks_like_navigation_value(raw_value):
        return None
    raw_value = raw_value.strip()
    if raw_value.startswith("javascript:"):
        return None
    try:
        resolved = urljoin(current_url, raw_value)
        return resolved
    except Exception:
        return None


def _dedupe_append(store: List[str], seen: Set[str], value: str) -> None:
    if not value or value in seen:
        return
    seen.add(value)
    store.append(value)


def _infer_technologies(page_payload: Dict[str, Any]) -> List[str]:
    techs: List[str] = []
    seen: Set[str] = set()

    def add(value: str) -> None:
        normalized = value.strip().lower()
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        techs.append(value)

    body_text = str(page_payload.get("body_text") or "").lower()
    candidates = [str(item).lower() for item in (page_payload.get("candidates") or []) if isinstance(item, str)]

    if any("/_next/" in candidate for candidate in candidates) or "__next_data__" in body_text:
        add("Next.js")
    if any("nuxt" in candidate for candidate in candidates) or "__nuxt__" in body_text:
        add("Nuxt.js")
    if "angular" in body_text or any("angular" in candidate for candidate in candidates):
        add("Angular")
    if "react" in body_text or any("react" in candidate for candidate in candidates):
        add("React")
    if "vue" in body_text or any("vue" in candidate for candidate in candidates):
        add("Vue")
    if any("express" in candidate for candidate in candidates):
        add("Express")

    return techs


def _collect_with_playwright(start_url: str, cookie: Optional[str] = None, timeout_ms: int = 15000) -> Dict[str, Any]:
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError  # type: ignore
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception as exc:
        return {
            "target": start_url,
            "error": f"playwright_unavailable: {exc}",
            "endpoints": [],
            "visited_urls": [],
            "page_summaries": [],
        }

    queue = deque([start_url])
    visited: List[str] = []
    visited_seen: Set[str] = set()
    endpoints: List[str] = []
    endpoints_seen: Set[str] = set()
    page_summaries: List[Dict[str, Any]] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        if cookie:
            try:
                parsed = urlparse(start_url)
                context.add_cookies(
                    [
                        {
                            "name": cookie.split("=", 1)[0].split(";", 1)[0].strip(),
                            "value": cookie.split("=", 1)[1].split(";", 1)[0].strip() if "=" in cookie else cookie.strip(),
                            "domain": parsed.hostname or "localhost",
                            "path": "/",
                        }
                    ]
                )
            except Exception:
                pass

        page = context.new_page()
        page.set_default_timeout(timeout_ms)

        try:
            while queue and len(visited) < MAX_VISITED_PAGES and len(endpoints) < MAX_DISCOVERED_URLS:
                current_url = queue.popleft()
                if current_url in visited_seen:
                    continue
                visited_seen.add(current_url)
                visited.append(current_url)

                try:
                    page.goto(current_url, wait_until="networkidle", timeout=timeout_ms)
                except PlaywrightTimeoutError:
                    try:
                        page.goto(current_url, wait_until="load", timeout=timeout_ms)
                    except Exception:
                        pass
                except Exception:
                    continue

                try:
                    payload = page.evaluate(
                        """
                        () => {
                          const collected = new Set();
                          const add = (value) => {
                            if (typeof value === 'string' && value.trim()) {
                              collected.add(value.trim());
                            }
                          };

                          const selectors = [
                            'a[href]',
                            'area[href]',
                            'link[href]',
                            'script[src]',
                            'form[action]',
                            '[data-href]',
                            '[data-url]',
                            '[routerlink]',
                            '[router-link]'
                          ];

                          selectors.forEach((selector) => {
                            document.querySelectorAll(selector).forEach((element) => {
                              ['href', 'src', 'action', 'data-href', 'data-url', 'routerlink', 'router-link'].forEach((attribute) => {
                                if (element.hasAttribute && element.hasAttribute(attribute)) {
                                  add(element.getAttribute(attribute));
                                }
                              });
                            });
                          });

                          document.querySelectorAll('[onclick]').forEach((element) => {
                            const onclick = element.getAttribute('onclick') || '';
                            if (/location|router|navigate|pushState|replaceState/i.test(onclick)) {
                              add(onclick);
                            }
                          });

                          if (window.__NEXT_DATA__) {
                            try {
                              add(window.__NEXT_DATA__.page || '');
                            } catch (_) {}
                          }

                          if (window.__NUXT__) {
                            try {
                              add(window.__NUXT__.route || '');
                            } catch (_) {}
                          }

                          return {
                            title: document.title || '',
                            url: location.href,
                            body_text: document.body ? (document.body.innerText || '').slice(0, 5000) : '',
                            candidates: Array.from(collected),
                          };
                        }
                        """
                    )
                except Exception:
                    payload = {"title": "", "url": current_url, "body_text": "", "candidates": []}

                title = str(payload.get("title") or "")
                final_url = str(payload.get("url") or current_url)
                candidates = payload.get("candidates") if isinstance(payload, dict) else []
                route_candidates: List[str] = []
                inferred_techs = _infer_technologies(payload if isinstance(payload, dict) else {})

                if isinstance(candidates, list):
                    for raw_candidate in candidates:
                        if not isinstance(raw_candidate, str):
                            continue
                        resolved = _resolve_candidate(final_url, raw_candidate)
                        if not resolved:
                            continue
                        if not _same_origin(start_url, resolved):
                            continue
                        if resolved not in visited_seen:
                            route_candidates.append(resolved)
                        _dedupe_append(endpoints, endpoints_seen, resolved)

                page_summaries.append(
                    {
                        "url": final_url,
                        "title": title,
                        "candidates_found": len(route_candidates),
                        "candidate_urls": route_candidates[:50],
                        "technologies": inferred_techs,
                    }
                )

                for route_url in route_candidates:
                    if route_url not in visited_seen:
                        queue.append(route_url)

                if len(endpoints) >= MAX_DISCOVERED_URLS:
                    break

        finally:
            context.close()
            browser.close()

    return {
        "target": start_url,
        "endpoints": endpoints,
        "visited_urls": visited,
        "page_summaries": page_summaries,
        "technologies": sorted({tech for summary in page_summaries for tech in summary.get("technologies", []) if isinstance(tech, str)}),
        "engine": "playwright",
    }


def run_headless_browser(target: str, cookie: Optional[str] = None) -> str:
    """Discover SPA routes using a headless browser and persist them for aggregation."""
    output_dir = Path(OUTPUT_FILE).resolve().parent
    output_dir.mkdir(parents=True, exist_ok=True)

    candidates = _normalize_target(target)
    data: Dict[str, Any]

    last_error: Optional[str] = None
    for candidate in candidates:
        data = _collect_with_playwright(candidate, cookie=cookie)
        if data.get("endpoints"):
            break
        last_error = str(data.get("error") or last_error or "no_endpoints_discovered")
    else:
        data = _collect_with_playwright(candidates[0] if candidates else str(target), cookie=cookie) if candidates else {"target": target, "endpoints": [], "visited_urls": [], "page_summaries": []}

    if not data.get("endpoints") and last_error:
        data["error"] = last_error

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)

    return OUTPUT_FILE
