import json
import os
from dataclasses import asdict, is_dataclass
from typing import Dict, Any

SESSION_FILE = "output/session.json"
SESSION_GRAPH_JSON = "output/session_graph.json"
SESSION_GRAPH_DOT = "output/session_graph.dot"


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
        json.dump(data, f, indent=4)


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
