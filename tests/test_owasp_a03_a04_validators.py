from __future__ import annotations

import os
import sys
from urllib.parse import unquote

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from brain.dag_engine import VALIDATOR_CLASS_MAP as BASE_VALIDATOR_MAP
from brain.dag_engine_enhanced import VALIDATOR_CLASS_MAP as ENHANCED_VALIDATOR_MAP
from brain.kb import get_default_validator_specs
from validators.injection import InjectionValidator
from validators.insecure_design import InsecureDesignValidator


class _FakeResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code
        self.headers = {"Content-Type": "text/html"}


def test_a03_validator_confirms_sqli_and_xss(monkeypatch) -> None:
    validator = InjectionValidator()

    def fake_get(url, headers=None, timeout=None, allow_redirects=True):
        if "1%27" in url or "1'" in url:
            return _FakeResponse("You have an error in your SQL syntax near '1'", 500)
        if "%3Csvg+onload%3Dalert%281%29%3E" in url or "<svg onload=alert(1)>" in url:
            return _FakeResponse("<svg onload=alert(1)>", 200)
        return _FakeResponse("baseline", 200)

    monkeypatch.setattr("validators.injection.requests.get", fake_get)

    result = validator.run({"url": "https://example.test/search?q=test"})

    assert isinstance(result, list)
    assert any(item.vulnerability == "a03-injection-sqli" for item in result)
    assert any(item.vulnerability == "a03-injection-xss" for item in result)


def test_a03_validator_confirms_command_injection(monkeypatch) -> None:
    validator = InjectionValidator()

    def fake_get(url, headers=None, timeout=None, allow_redirects=True):
        if "SECURITY_PIPELINE_A03" in url:
            return _FakeResponse("command output: SECURITY_PIPELINE_A03", 200)
        return _FakeResponse("baseline", 200)

    monkeypatch.setattr("validators.injection.requests.get", fake_get)

    result = validator.run({"url": "https://example.test/run?cmd=whoami"})

    if isinstance(result, list):
        assert any(item.vulnerability == "a03-injection-command" for item in result)
    else:
        assert result.vulnerability == "a03-injection-command"


def test_a03_validator_confirms_file_template_and_ldap_injection(monkeypatch) -> None:
    validator = InjectionValidator()

    def fake_get(url, headers=None, timeout=None, allow_redirects=True):
        decoded = unquote(url)
        if "../../../../etc/passwd" in decoded:
            return _FakeResponse("root:x:0:0:root:/root:/bin/bash", 200)
        if "{{7*7}}" in decoded:
            return _FakeResponse("49", 200)
        if "*)(uid=*)" in decoded:
            return _FakeResponse("LDAP error: invalid dn", 500)
        return _FakeResponse("baseline", 200)

    monkeypatch.setattr("validators.injection.requests.get", fake_get)

    result = validator.run({"url": "https://example.test/view?file=read"})

    assert isinstance(result, list)
    vulnerabilities = {item.vulnerability for item in result}
    assert "a03-injection-file" in vulnerabilities
    assert "a03-injection-template" in vulnerabilities
    assert "a03-injection-ldap" in vulnerabilities


def test_a04_validator_confirms_workflow_bypass(monkeypatch) -> None:
    validator = InsecureDesignValidator()

    def fake_get(url, headers=None, timeout=None, allow_redirects=True):
        if "approved" in url:
            return _FakeResponse("order completed successfully", 200)
        if "completed" in url:
            return _FakeResponse("order completed successfully", 200)
        return _FakeResponse("access denied: invalid state", 403)

    monkeypatch.setattr("validators.insecure_design.requests.get", fake_get)

    result = validator.run({"url": "https://example.test/order?step=draft", "workflow_bypass_values": ["approved", "completed"]})

    assert result.success is True
    assert result.vulnerability == "a04-insecure-design"
    assert result.evidence_bundle is not None
    assert result.evidence.extra["workflow_attempts"]


def test_a04_validator_uses_workflow_templates(monkeypatch) -> None:
    validator = InsecureDesignValidator()

    def fake_get(url, headers=None, timeout=None, allow_redirects=True):
        if "paid" in url:
            return _FakeResponse("payment received", 200)
        return _FakeResponse("payment denied: invalid state", 403)

    monkeypatch.setattr("validators.insecure_design.requests.get", fake_get)

    result = validator.run({
        "url": "https://example.test/checkout?status=pending",
        "workflow_templates": [
            {
                "name": "custom_payment",
                "baseline": "pending",
                "bypass_values": ["paid"],
                "param_names": ["status"],
            }
        ],
    })

    assert result.success is True
    assert result.evidence.extra["template"] == "custom_payment"


def test_registry_contains_a03_a04_validators() -> None:
    spec_ids = {spec.id for spec in get_default_validator_specs()}
    assert "injection_validator" in spec_ids
    assert "insecure_design_validator" in spec_ids
    assert "validators.injection.InjectionValidator" in BASE_VALIDATOR_MAP
    assert "validators.insecure_design.InsecureDesignValidator" in BASE_VALIDATOR_MAP
    assert "validators.injection.InjectionValidator" in ENHANCED_VALIDATOR_MAP
    assert "validators.insecure_design.InsecureDesignValidator" in ENHANCED_VALIDATOR_MAP
