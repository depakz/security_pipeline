# CVE-to-Validator Mapping System - Quick Reference

## What This System Does

```
Scan → Find CVEs → Map to Validators → Test Validators → Generate Report
```

**Goal**: For each CVE found in scan results, determine if it's actually exploitable by running automated tests.

**Output**: A report showing each CVE with a verdict:
- ✅ **exploitable** (90%+ confidence) - Real vulnerability confirmed
- ⚠️ **negligible** (high severity but unconfirmed) - Likely false positive or patched
- ❌ **false_positive** (low severity and unconfirmed) - Probably scanner error
- ❓ **untested** (no validators exist) - Can't verify yet

## Key Files

| File | Purpose |
|------|---------|
| `brain/cve_mapper.py` | Extracts CVE IDs from findings & maps to validators |
| `brain/dag_engine.py` | Plans which validators to run (DAG-based) |
| `brain/exploitability_reporter.py` | Generates verdicts (exploitable vs negligible) |
| `main.py` | Orchestrates the entire pipeline |
| `output/exploitability_report.json` | Final report with all verdicts |

## Data Flow

```
Nuclei Scan Results
        ↓
     [Findings with CVE IDs]
        ↓
CVE Mapper (extract CVE-2025-46817)
        ↓
     [CVE → Validator mapping]
        ↓
DAG Brain (create validator instances)
        ↓
Validation Engine (run tests)
        ↓
     [Validation results: confirmed/failed]
        ↓
Exploitability Reporter (compute verdict)
        ↓
[Report: CVE X is exploitable]
```

## Current CVE Support

### Redis CVEs (vulnerable to `redis_no_auth`)

| CVE | Severity | Status |
|-----|----------|--------|
| CVE-2025-46817 | critical | Lua integer overflow |
| CVE-2025-49844 | critical | Lua use-after-free |
| CVE-2025-46819 | high | Lua OOB read |
| CVE-2025-46818 | high | Lua sandbox escape |

## Verdict Decision Logic

```python
if any_validator_confirmed:
    verdict = "exploitable"
    confidence = validator_confidence (0.0-1.0)
    
elif all_validators_failed:
    if severity in [critical, high]:
        verdict = "negligible"      # False positive
    else:
        verdict = "false_positive"  # Likely scanner error
    confidence = 0.0
    
else:
    verdict = "untested"
    confidence = 0.0
```

## Example Report

```json
{
    "summary": {
        "total_cves": 1,
        "exploitable": 1,
        "false_positives": 0,
        "negligible": 0,
        "untested": 0
    },
    "exploitable_cves": [
        {
            "cve_id": "CVE-2025-46817",
            "title": "Redis < 8.2.1 lua script - Integer Overflow",
            "severity": "critical",
            "verdict": "exploitable",
            "confidence": 0.95,
            "validators_tested": ["redis_no_auth"],
            "evidence": {
                "confirmed": 1,
                "items": [
                    {
                        "source": "redis_no_auth",
                        "status": "confirmed",
                        "evidence": {
                            "port": 6379,
                            "auth_required": false
                        }
                    }
                ]
            }
        }
    ]
}
```

## Running the System

### Full Pipeline
```bash
python3 main.py --target example.com
```

Outputs:
- `output/validations.json` - Standard validator results
- `output/exploitability_report.json` - **CVE verdicts (NEW)**

### Integration Test
```bash
python3 test_cve_pipeline.py
```

Tests CVE extraction, mapping, validator planning, verdict generation, and report aggregation.

## Architecture

### 1. CVE Mapper (`brain/cve_mapper.py`)
- Extracts CVE IDs from findings
- Maps CVE ID → list of validator IDs
- Stores CVE metadata (title, severity, etc.)

### 2. DAG Brain (`brain/dag_engine.py`)
- `plan_validations()` - Standard validator planning
- `plan_cve_validations()` - CVE-specific planning (NEW)
- Creates validator instances only for needed validators

### 3. Exploitability Reporter (`brain/exploitability_reporter.py`)
- `generate_verdict()` - Single CVE verdict
- `generate_report()` - Aggregate report
- Logic: confirmed=exploitable, unconfirmed+high_severity=negligible

### 4. Validation Engine (`engine/validation_engine.py`)
- Runs validators
- Returns: vulnerability, validation status, evidence, confidence

## Extending the System

### Add a New CVE Type

1. Define CVESpec in `brain/cve_mapper.py`:
```python
CVESpec(
    cve_id="CVE-YYYY-XXXXX",
    title="Title",
    description="Description",
    severity="critical|high|medium|low",
    applicable_validators=["validator_id"],
    keywords=["keyword1", "keyword2"],
)
```

2. Create validator in `validators/new_validator.py`:
```python
class NewValidator:
    def validate(self, state):
        return {
            "vulnerability": "validator_id",
            "validation": {"status": "confirmed", "confidence": 0.95},
            "evidence": {...},
            "severity": "critical"
        }
```

3. Register in `brain/dag_engine.py`:
```python
VALIDATOR_CLASS_MAP = {
    "validators.new_validator.NewValidator": NewValidator,
}
```

4. Add to knowledge base in `brain/kb.py`:
```python
ValidatorSpec(
    id="validator_id",
    required_ports=[port],
    required_protocols=["protocol"],
    keywords=["keywords"],
    class_path="validators.new_validator.NewValidator",
)
```

## Output Locations

```
pentester/
├── output/
│   ├── exploitability_report.json    ← CVE verdicts (NEW)
│   ├── validations.json              ← Validator results
│   ├── nuclei.json                   ← Raw CVE scan results
│   ├── naabu.json                    ← Port scan results
│   ├── httpx.json                    ← HTTP probe results
│   └── gospider.json                 ← Web crawl results
```

## Verdict Meanings

| Verdict | Meaning | Action |
|---------|---------|--------|
| **exploitable** | Vulnerability confirmed by validator | Immediate remediation needed |
| **negligible** | High/critical CVE but can't confirm | Likely patched or mitigated |
| **false_positive** | Low severity CVE not confirmed | Scanner likely wrong |
| **untested** | No validators available for this CVE | Manual review needed |

## Confidence Levels

- **0.95**: Validator successfully connected and confirmed vulnerability
- **0.90**: Validator found strong evidence but not 100% certain
- **0.5**: Partial evidence, needs human review
- **0.0**: No confirmation or validator failed

## Related Documentation

- [CVE_VALIDATION_GUIDE.md](CVE_VALIDATION_GUIDE.md) - Detailed component documentation
- [SYSTEM_ARCHITECTURE.md](SYSTEM_ARCHITECTURE.md) - Full system design
- [CVE_EXAMPLE.md](CVE_EXAMPLE.md) - Step-by-step Redis CVE example
