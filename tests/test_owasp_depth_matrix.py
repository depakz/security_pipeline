from __future__ import annotations

from brain.owasp_depth_matrix import OWASP_SUBCASE_CATALOG, build_depth_coverage


def test_build_depth_coverage_reaches_full_score_with_explicit_markers() -> None:
    records = []
    for category, subcases in OWASP_SUBCASE_CATALOG.items():
        records.append(
            {
                "vulnerability": f"{category.lower()}-validator",
                "evidence": {
                    "request": {"target": "https://example.test"},
                    "response": {},
                    "matched": subcases[0],
                    "extra": {"coverage_markers": list(subcases)},
                },
                "compliance_tags": {"OWASP": category},
            }
        )

    coverage = build_depth_coverage(records)

    assert coverage["summary"]["owasp_top10_category_coverage_percent"] == 100.0
    assert coverage["summary"]["overall_subcase_coverage_percent"] == 100.0
    assert coverage["summary"]["subcases_tested"] == coverage["summary"]["subcases_total"]
    assert coverage["summary"]["categories_with_any_tested_subcase"] == 10
    assert coverage["summary"]["categories_without_tested_subcases"] == 0
