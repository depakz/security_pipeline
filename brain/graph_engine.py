"""Compatibility shim exposing GraphEngine from graph_builder.

The runtime GraphEngine implementation was consolidated into
`brain/graph_builder.py`. This module preserves the old import path
(`brain.graph_engine.GraphEngine`) by importing the implementation from
`graph_builder` so older code that imports `graph_engine` keeps working.
"""

try:
    from .graph_builder import GraphEngine  # type: ignore
except Exception:
    GraphEngine = None
