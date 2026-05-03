import json
import os
import base64
from datetime import datetime, timezone
from dataclasses import asdict, is_dataclass
from typing import Dict, Any

import requests

SESSION_FILE = "output/session.json"
SESSION_GRAPH_JSON = "output/session_graph.json"
SESSION_GRAPH_DOT = "output/session_graph.dot"


def _normalize_cookie(cookie: Any) -> str:
    if not isinstance(cookie, str):
        return ""
    return cookie.strip()


def build_session_context(target: str, cookie: Any = None, headers: Any = None, previous: Any = None) -> Dict[str, Any]:
    previous_context = previous if isinstance(previous, dict) else {}

    resolved_cookie = _normalize_cookie(cookie) or _normalize_cookie(previous_context.get("cookie"))
    resolved_headers = previous_context.get("headers") if isinstance(previous_context.get("headers"), dict) else {}
    if isinstance(headers, dict):
        merged_headers = dict(resolved_headers)
        for key, value in headers.items():
            if isinstance(key, str) and isinstance(value, str):
                merged_headers[key] = value
        resolved_headers = merged_headers

    if resolved_cookie and "Cookie" not in resolved_headers:
        resolved_headers["Cookie"] = resolved_cookie

    session_context = {
        "target": target,
        "cookie": resolved_cookie,
        "headers": resolved_headers,
        "source": "cli" if _normalize_cookie(cookie) else previous_context.get("source", "previous_session"),
        "captured_at": previous_context.get("captured_at") or previous_context.get("generated_at") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "persisted": True,
    }

    for key in ("username", "auth_type", "login_url", "login_method", "token", "bearer_token"):
        value = previous_context.get(key)
        if value:
            session_context[key] = value

    return session_context


def capture_session_context(
    target: str,
    previous: Any = None,
    cookie: Any = None,
    login_url: Any = None,
    login_method: str = "POST",
    username: Any = None,
    password: Any = None,
    auth_type: str = "session",
    bearer_token: Any = None,
    login_payload: Any = None,
    extra_headers: Any = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    previous_context = previous if isinstance(previous, dict) else {}
    session_context = build_session_context(target, cookie=cookie, headers=extra_headers, previous=previous_context)

    resolved_login_url = login_url if isinstance(login_url, str) and login_url.strip() else previous_context.get("login_url")
    resolved_username = username if isinstance(username, str) and username else previous_context.get("username")
    resolved_password = password if isinstance(password, str) and password else previous_context.get("password")
    resolved_auth_type = (auth_type or previous_context.get("auth_type") or "session").strip().lower()
    resolved_method = (login_method or previous_context.get("login_method") or "POST").strip().upper()
    resolved_bearer = bearer_token if isinstance(bearer_token, str) and bearer_token.strip() else previous_context.get("bearer_token")

    if resolved_login_url:
        session_context["login_url"] = resolved_login_url
        session_context["login_method"] = resolved_method
        session_context["auth_type"] = resolved_auth_type
        if resolved_username:
            session_context["username"] = resolved_username

    if resolved_bearer:
        session_context["bearer_token"] = resolved_bearer.strip()
        session_context["token"] = resolved_bearer.strip()

    if resolved_auth_type == "basic" and resolved_username is not None and resolved_password is not None:
        basic_value = base64.b64encode(f"{resolved_username}:{resolved_password}".encode("utf-8", errors="ignore")).decode("ascii")
        session_context.setdefault("headers", {})["Authorization"] = f"Basic {basic_value}"
        session_context["source"] = "basic_auth"
        return session_context

    if not resolved_login_url:
        return session_context

    request_headers = dict(session_context.get("headers") or {})
    request_headers.setdefault("User-Agent", "security-pipeline-validator/1.0")
    response = None

    try:
        with requests.Session() as http_session:
            if resolved_cookie:
                http_session.headers.update({"Cookie": resolved_cookie})

            if isinstance(login_payload, dict) and login_payload:
                payload = login_payload
            elif resolved_username is not None or resolved_password is not None:
                payload = {"username": resolved_username or "", "password": resolved_password or ""}
            else:
                payload = {}

            request_kwargs = {
                "headers": request_headers,
                "timeout": timeout,
                "allow_redirects": True,
            }
            if resolved_method == "GET":
                request_kwargs["params"] = payload or None
            else:
                request_kwargs["data"] = payload or None

            response = http_session.request(resolved_method, resolved_login_url, **request_kwargs)

            response_cookies = http_session.cookies.get_dict() or {}
            cookie_parts = [f"{name}={value}" for name, value in response_cookies.items() if name and value is not None]
            if cookie_parts:
                session_context["cookie"] = "; ".join(cookie_parts)
                session_context.setdefault("headers", {})["Cookie"] = session_context["cookie"]

            response_text = ""
            try:
                response_json = response.json()
            except Exception:
                response_json = None

            if isinstance(response_json, dict):
                for key in ("access_token", "token", "jwt", "session_token"):
                    candidate = response_json.get(key)
                    if isinstance(candidate, str) and candidate.strip():
                        resolved_bearer = candidate.strip()
                        break
            else:
                response_text = response.text or ""
                for key in ("access_token", "token", "jwt", "session_token"):
                    marker = f'"{key}"'
                    if marker in response_text:
                        import re

                        match = re.search(rf'"{key}"\s*:\s*"([^"]+)"', response_text)
                        if match:
                            resolved_bearer = match.group(1).strip()
                            break

            if resolved_bearer:
                session_context["bearer_token"] = resolved_bearer
                session_context["token"] = resolved_bearer
                session_context.setdefault("headers", {})["Authorization"] = f"Bearer {resolved_bearer}"

            session_context["source"] = "captured_login"
            session_context["captured_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            session_context["login_status"] = getattr(response, "status_code", None)
            return session_context

    except Exception as exc:
        session_context["login_error"] = str(exc)
        session_context.setdefault("headers", {}).setdefault("Cookie", session_context.get("cookie", ""))
        session_context["login_status"] = getattr(response, "status_code", None) if response is not None else None
        return session_context


def _json_default(value: Any):
    """Fallback serializer for non-JSON-native values.

    Handles dataclass instances (e.g. ValidatorSpec/VulnerabilitySpec),
    objects exposing `to_dict()`, and set/tuple values.
    """
    if is_dataclass(value):
        return asdict(value)

    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            return to_dict()
        except Exception:
            pass

    if isinstance(value, (set, tuple)):
        return list(value)

    return str(value)


def save_session(data: Dict[str, Any]):
    os.makedirs(os.path.dirname(SESSION_FILE), exist_ok=True)
    with open(SESSION_FILE, "w") as f:
        json.dump(data, f, indent=4, default=_json_default)


def load_session():
    if not os.path.exists(SESSION_FILE):
        return {}
    with open(SESSION_FILE) as f:
        return json.load(f)


def save_graph_snapshot(snapshot: Dict[str, Any]):
    """Save a graph snapshot as JSON and a simple DOT representation.

    The DOT output is a lightweight manual serialization so pydot/graphviz
    are not required at runtime.
    """
    os.makedirs(os.path.dirname(SESSION_GRAPH_JSON), exist_ok=True)
    with open(SESSION_GRAPH_JSON, "w") as f:
        json.dump(snapshot, f, indent=4, default=_json_default)

    # Emit a simple DOT file
    try:
        lines = ["digraph session_graph {\n"]
        for node in snapshot.get("nodes", []):
            nid = node.get("id")
            label = node.get("label") or nid
            lines.append(f'  "{nid}" [label="{label}"];\n')
        for edge in snapshot.get("edges", []):
            src = edge.get("from")
            dst = edge.get("to")
            eid = edge.get("id")
            action = edge.get("action")
            lines.append(f'  "{src}" -> "{dst}" [label="{eid}: {action}"];\n')
        lines.append("}\n")

        with open(SESSION_GRAPH_DOT, "w") as f:
            f.writelines(lines)
    except Exception:
        # don't fail session save just for dot export
        pass
