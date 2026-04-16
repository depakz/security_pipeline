from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from engine.models import ExecutionContext


def _is_confirmed(result: Dict[str, Any]) -> bool:
    if result.get("success") is True:
        return True
    status = ((result.get("validation") or {}).get("status") or "").strip().lower()
    return status == "confirmed"


def _confirmed_key(result: Dict[str, Any]) -> Tuple[Any, Any]:
    return (result.get("validator_id"), result.get("vulnerability"))


class ValidationEngine:
    def __init__(self):
        self.validators: List[Any] = []

    def register(self, validator) -> None:
        self.validators.append(validator)

    def run(self, plan_or_state: Any, state: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Backward-compatible runner:

        - run(state_dict)              # uses registered validators
        - run(plan, state_dict)        # uses plan.validators
        """
        plan_mode = state is not None
        if state is None:
            state = plan_or_state
            validators = list(self.validators)
            validators.sort(key=lambda v: int(getattr(v, "priority", 0) or 0), reverse=True)
        else:
            plan = plan_or_state
            validators = list(getattr(plan, "validators", []) or [])

        if not isinstance(state, dict):
            return []

        context = ExecutionContext.from_state(state)
        findings: List[Dict[str, Any]] = []

        confirmed_validator_ids = set()
        if plan_mode:
            confirmed_vulns = state.get("confirmed_vulns") or []
            if isinstance(confirmed_vulns, list):
                for r in confirmed_vulns:
                    if not isinstance(r, dict) or not _is_confirmed(r):
                        continue
                    vid = r.get("validator_id")
                    if isinstance(vid, str) and vid:
                        confirmed_validator_ids.add(vid)

        for validator in validators:
            try:
                if not hasattr(validator, "can_run") or not hasattr(validator, "run"):
                    continue

                validator_id = getattr(validator, "validator_id", None) or getattr(validator, "id", None)
                validator_class = validator.__class__.__name__

                # Ensure validators have access to the same execution context.
                for attr in ("context", "execution_context"):
                    try:
                        if getattr(validator, attr, None) is None:
                            setattr(validator, attr, context)
                    except Exception:
                        pass

                # Keep feedback-loop iterations cheap: don't rerun already-confirmed validators.
                if plan_mode and isinstance(validator_id, str) and validator_id in confirmed_validator_ids:
                    continue

                if not validator.can_run(state):
                    continue

                result = validator.run(state)
                if not result:
                    continue

                results = result if isinstance(result, list) else [result]
                for r in results:
                    out = r.to_dict() if hasattr(r, "to_dict") else r
                    if not isinstance(out, dict):
                        continue

                    if validator_id:
                        out.setdefault("validator_id", validator_id)
                    out.setdefault("validator_class", validator_class)

                    if "success" not in out:
                        out["success"] = _is_confirmed(out)

                    pr = getattr(validator, "priority", None)
                    if pr is not None:
                        out.setdefault("priority", pr)

                    findings.append(out)

            except Exception as e:
                findings.append(
                    {
                        "success": False,
                        "vulnerability": validator.__class__.__name__,
                        "validator_id": getattr(validator, "validator_id", None) or getattr(validator, "id", None),
                        "validator_class": validator.__class__.__name__,
                        "error": str(e),
                    }
                )

        return findings


class StateManager:
    def update(self, state: Dict[str, Any], results: List[Dict[str, Any]]) -> int:
        """Update state with results; return number of newly confirmed vulns."""
        if not isinstance(state, dict):
            return 0

        history = state.setdefault("validation_results", [])
        if not isinstance(history, list):
            history = []
            state["validation_results"] = history

        for r in results:
            if isinstance(r, dict):
                history.append(r)

        confirmed = state.setdefault("confirmed_vulns", [])
        if not isinstance(confirmed, list):
            confirmed = []
            state["confirmed_vulns"] = confirmed

        seen = set()
        for r in confirmed:
            if isinstance(r, dict) and _is_confirmed(r):
                seen.add(_confirmed_key(r))

        new_confirmed = 0
        for r in results:
            if not isinstance(r, dict) or not _is_confirmed(r):
                continue
            key = _confirmed_key(r)
            if key in seen:
                continue
            confirmed.append(r)
            seen.add(key)
            new_confirmed += 1

        signals = state.setdefault("signals", [])
        if not isinstance(signals, list):
            signals = []
            state["signals"] = signals
        for r in results:
            if not isinstance(r, dict) or not _is_confirmed(r):
                continue
            vuln = r.get("vulnerability")
            if isinstance(vuln, str) and vuln not in signals:
                signals.append(vuln)

        return new_confirmed
