# CVE Detection & Exploitability Validation Pipeline

## Overview

This system implements a complete pipeline for detecting CVEs in scan results, mapping them to applicable validators, running validation tests, and generating exploitability reports.

### Pipeline Flow

```
Nuclei Scan Results → CVE Extraction → CVE-to-Validator Mapping → Validator Execution → Exploitability Report
```

## Components

### 1. CVE Mapper (`brain/cve_mapper.py`)

**Purpose**: Extracts CVE IDs from scan findings and maps them to applicable validators.

**Key Features**:
- `CVESpec` dataclass: Stores CVE metadata (ID, title, severity, applicable validators)
- `CVEMapper.map_findings_to_cves()`: Extracts CVE IDs from findings and returns validator list
- `extract_cve_ids()`: Parses "cve" field and title for CVE patterns (CVE-YYYY-XXXXX)
- `get_cve_verdict_data()`: Returns CVE metadata for reporting

**Example**:
```python
findings = [
    {
        "title": "Redis No Authentication - CVE-2025-46817",
        "cve": "CVE-2025-46817",
        "severity": "critical",
    }
]

mapper = CVEMapper()
cve_to_validators = mapper.map_findings_to_cves(findings)
# Returns: {"CVE-2025-46817": ["redis_no_auth"]}
```

### 2. DAG Brain Integration (`brain/dag_engine.py`)

**Purpose**: Plans which validators to execute based on CVEs found.

**New Method**: `plan_cve_validations(state, findings)`
- Extracts CVEs from findings using `CVEMapper`
- Creates validator instances only for needed validators
- Retrieves CVE metadata for each discovered CVE
- Returns `CVEValidationPlan` with:
  - `cve_to_validators`: CVE ID → validator list
  - `cve_details`: CVE metadata (title, severity, etc.)
  - `validator_instances`: Ready-to-use validator objects

**Example**:
```python
dag_brain = DAGBrain()
cve_plan = dag_brain.plan_cve_validations(state, findings)

# cve_plan.cve_to_validators = {"CVE-2025-46817": ["redis_no_auth"]}
# cve_plan.validator_instances = {"redis_no_auth": RedisNoAuthValidator()}
# cve_plan.cve_details has CVE title, severity, etc.
```

### 3. Exploitability Reporter (`brain/exploitability_reporter.py`)

**Purpose**: Generates verdicts on whether CVEs are exploitable or false positives.

**Key Components**:
- `CVEVerdictRecord`: Dataclass storing verdict results
- `ExploitabilityReporter.generate_verdict()`: Creates verdict for single CVE
- `ExploitabilityReporter.generate_report()`: Aggregates verdicts into report

**Verdict Types**:
- **exploitable**: Any validator confirmed the vulnerability exists and is exploitable
- **false_positive**: Severity is low or medium, and no validator confirmed
- **negligible**: Severity is high/critical but no validator could confirm it (likely patched)
- **untested**: No validators ran

**Example**:
```python
cve_data = {
    "cve_id": "CVE-2025-46817",
    "title": "Redis < 8.2.1 lua script - Integer Overflow",
    "severity": "critical",
}

validation_results = [
    {
        "vulnerability": "redis_no_auth",
        "validation": {"status": "confirmed", "confidence": 0.95},
        "evidence": {"port": 6379, "auth_required": False},
    },
]

reporter = ExploitabilityReporter()
verdict = reporter.generate_verdict(cve_data, validation_results, ["redis_no_auth"])
# verdict.verdict = "exploitable"
# verdict.confidence = 0.95
```

## Integration in main.py

The pipeline runs in Step 3b (after standard validation):

```python
# Step 3b: CVE-specific validation and reporting
findings = parsed_data.get("findings", [])
if findings:
    # Plan CVE validations
    cve_plan = dag_brain.plan_cve_validations(state, findings)
    
    # Run validators for discovered CVEs
    cve_vengine = ValidationEngine()
    for validator in cve_plan.validator_instances.values():
        cve_vengine.register(validator)
    cve_validation_results = cve_vengine.run(state)
    
    # Generate report
    reporter = ExploitabilityReporter()
    cve_verdicts = []
    for cve_id, cve_data in cve_plan.cve_details.items():
        validators_for_cve = cve_plan.cve_to_validators.get(cve_id, [])
        relevant_results = [r for r in cve_validation_results 
                           if r.get("vulnerability") in validators_for_cve]
        verdict = reporter.generate_verdict(cve_data, relevant_results, validators_for_cve)
        cve_verdicts.append(verdict)
    
    report = reporter.generate_report(cve_verdicts)
    
    # Save report
    with open("output/exploitability_report.json", "w") as f:
        json.dump(report, f, indent=4)
```

## Report Output Format

The exploitability report is saved to `output/exploitability_report.json`:

```json
{
    "summary": {
        "total_cves": 2,
        "exploitable": 1,
        "false_positives": 0,
        "negligible": 1,
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
            "validation_results": [...],
            "evidence": {
                "confirmed": 1,
                "failed": 0,
                "items": [...]
            }
        }
    ],
    "false_positive_cves": [],
    "negligible_cves": [
        {
            "cve_id": "CVE-2025-46819",
            "title": "Redis < 8.2.1 Lua Long-String Delimiter - Out-of-Bounds Read",
            "severity": "high",
            "verdict": "negligible",
            "confidence": 0.0,
            ...
        }
    ],
    "untested_cves": [],
    "all_verdicts": [...]
}
```

## Known CVE Specs

### Redis CVEs (in `cve_mapper.py`)

| CVE ID | Title | Severity | Validator |
|--------|-------|----------|-----------|
| CVE-2025-46817 | Redis < 8.2.1 lua script - Integer Overflow | critical | redis_no_auth |
| CVE-2025-49844 | Redis Lua Parser < 8.2.2 - Use After Free | critical | redis_no_auth |
| CVE-2025-46819 | Redis < 8.2.1 Lua Long-String Delimiter - OOB Read | high | redis_no_auth |
| CVE-2025-46818 | Redis Lua Sandbox < 8.2.2 - Cross-User Escape | high | redis_no_auth |

## Extending with New CVEs

To add support for new CVEs:

1. **Define CVESpec** in `brain/cve_mapper.py`:
```python
CVESpec(
    cve_id="CVE-YYYY-XXXXX",
    title="Description",
    description="Full details",
    severity="critical|high|medium|low",
    applicable_validators=["validator_id"],
    keywords=["keyword1", "keyword2"],
)
```

2. **Create corresponding validator** in `validators/` if needed

3. **Register mapping** in `cve_mapper.py` ALL_CVE_SPECS

## Testing

Run the pipeline integration test:

```bash
python3 test_cve_pipeline.py
```

This verifies:
- CVE extraction from findings
- CVE-to-validator mapping
- Validator instantiation
- Verdict generation
- Report aggregation

## Workflow Summary

1. **Scan Phase**: Nuclei and other tools find vulnerabilities and report CVE IDs
2. **Extract Phase**: CVE mapper extracts IDs from findings
3. **Map Phase**: CVE mapper looks up applicable validators for each CVE
4. **Plan Phase**: DAG brain creates validator instances for needed validators
5. **Execute Phase**: Validators run tests to confirm vulnerability
6. **Report Phase**: Reporter generates verdict (exploitable/negligible/false_positive)
7. **Output Phase**: Report saved to `output/exploitability_report.json`

## Decision Logic

The verdict is determined by:

```
if any_validator_confirmed:
    verdict = "exploitable"
    confidence = highest_validator_confidence
elif all_validators_failed:
    if severity in ["critical", "high"]:
        verdict = "negligible"  # Likely patched/mitigated
    else:
        verdict = "false_positive"
    confidence = 0.0
else:
    verdict = "untested"
    confidence = 0.0
```

This ensures:
- **Confirmed vulnerabilities** are marked exploitable with high confidence
- **High-severity unconfirmed findings** are treated as negligible (likely false positives from scanner)
- **Low-severity findings** that weren't confirmed are marked false positive
- **Unvalidated CVEs** have verdict "untested" with zero confidence
