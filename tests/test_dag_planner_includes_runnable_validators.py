from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from brain.dag_engine_enhanced import DAGBrain


def test_plan_validations_includes_runnable_http_validators() -> None:
    brain = DAGBrain(use_graph_engine=True)
    state = {"target": "http://example.test", "url": "http://example.test", "protocols": ["http"]}

    plan = brain.plan_validations(state)
    validator_names = {validator.__class__.__name__ for validator in plan.validators}

    assert "InsecureDeserializationValidator" in validator_names
    assert "LoggingValidator" in validator_names
    assert "SSRFValidator" in validator_names
    assert "MissingSecurityHeadersValidator" in validator_names