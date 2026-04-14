from __future__ import annotations

from typing import Any, Dict, List


class ValidationEngine:
    def __init__(self):
        self.validators = []

    def register(self, validator) -> None:
        self.validators.append(validator)

    def run(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for validator in self.validators:
            try:
                if not hasattr(validator, "can_run") or not hasattr(validator, "run"):
                    continue

                if validator.can_run(state):
                    result = validator.run(state)

                    if not result:
                        continue

                    if isinstance(result, list):
                        for r in result:
                            findings.append(r.to_dict() if hasattr(r, "to_dict") else r)
                    else:
                        findings.append(result.to_dict() if hasattr(result, "to_dict") else result)

            except Exception as e:
                findings.append(
                    {
                        "vulnerability": validator.__class__.__name__,
                        "error": str(e),
                    }
                )

        return findings
