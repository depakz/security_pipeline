# Example: Redis CVE Detection & Validation

This document walks through a complete example of detecting a Redis CVE and validating its exploitability.

## Scenario

We scan a target running Redis 8.2.0 (vulnerable to CVE-2025-46817). The system should:
1. Detect the CVE via Nuclei scan
2. Extract the CVE ID from findings
3. Map to the `redis_no_auth` validator
4. Run the validator to confirm Redis is accessible without authentication
5. Generate a report showing the CVE is exploitable

## Step-by-Step Execution

### Step 1: Nuclei Scan Detects CVE

**Nuclei Output** (sample `output/nuclei.json`):
```json
{
    "template": "redis-cve-detection",
    "template_id": "redis-cve-detection",
    "info": {
        "name": "Redis CVE Detection",
        "severity": "critical"
    },
    "type": "http",
    "host": "redis.example.com",
    "port": 6379,
    "matched": true,
    "cve": "CVE-2025-46817",
    "extracted_results": [
        "Redis 8.2.0 detected"
    ]
}
```

### Step 2: Aggregator Parses Findings

**Parser Output** (in `parsed_data["findings"]`):
```python
{
    "title": "Redis CVE-2025-46817 - Lua Script Integer Overflow",
    "cve": "CVE-2025-46817",
    "severity": "critical",
    "template": "redis-cve-detection",
    "host": "redis.example.com",
    "port": 6379,
    "source": "nuclei",
}
```

### Step 3: CVE Mapper Extracts & Maps

**Input to CVE Mapper**:
```python
findings = [
    {
        "title": "Redis CVE-2025-46817 - Lua Script Integer Overflow",
        "cve": "CVE-2025-46817",
        "severity": "critical",
        ...
    }
]

mapper = CVEMapper()
cve_to_validators = mapper.map_findings_to_cves(findings)
```

**Output**:
```python
{
    "CVE-2025-46817": ["redis_no_auth"]
}

cve_details = {
    "CVE-2025-46817": {
        "cve_id": "CVE-2025-46817",
        "title": "Redis < 8.2.1 lua script - Integer Overflow",
        "description": "Authenticated user can use specially crafted Lua script to cause integer overflow and RCE",
        "severity": "critical"
    }
}
```

### Step 4: DAG Brain Plans Validators

**Input to DAG Brain**:
```python
state = {
    "target": "redis.example.com",
    "ports": [6379],
    "protocols": ["tcp"],
    "url": "redis.example.com:6379"
}

findings = [...]  # from aggregator

cve_plan = dag_brain.plan_cve_validations(state, findings)
```

**Output CVEValidationPlan**:
```python
CVEValidationPlan(
    cve_to_validators={
        "CVE-2025-46817": ["redis_no_auth"]
    },
    cve_details={
        "CVE-2025-46817": {
            "cve_id": "CVE-2025-46817",
            "title": "Redis < 8.2.1 lua script - Integer Overflow",
            "description": "...",
            "severity": "critical"
        }
    },
    validator_instances={
        "redis_no_auth": RedisNoAuthValidator()
    }
)
```

### Step 5: Validation Engine Runs Validator

**Validator Code** (`validators/redis.py`):
```python
class RedisNoAuthValidator:
    def validate(self, state):
        try:
            import redis
            conn = redis.Redis(
                host=extract_host(state["target"]),
                port=state["ports"][0],
                decode_responses=True
            )
            response = conn.ping()
            
            if response == "PONG":
                return {
                    "vulnerability": "redis_no_auth",
                    "validation": {
                        "status": "confirmed",
                        "confidence": 0.95
                    },
                    "evidence": {
                        "port": state["ports"][0],
                        "auth_required": False,
                        "response": response,
                        "version": conn.info()["redis_version"]
                    },
                    "severity": "critical"
                }
        except redis.ConnectionError:
            return {
                "vulnerability": "redis_no_auth",
                "validation": {
                    "status": "failed",
                    "confidence": 0.0
                },
                "evidence": {
                    "port": state["ports"][0],
                    "auth_required": True,
                    "error": "Connection refused"
                },
                "severity": "critical"
            }
```

**Validation Result**:
```json
{
    "vulnerability": "redis_no_auth",
    "validation": {
        "status": "confirmed",
        "confidence": 0.95
    },
    "evidence": {
        "port": 6379,
        "auth_required": false,
        "response": "PONG",
        "version": "8.2.0"
    },
    "severity": "critical"
}
```

### Step 6: Exploitability Reporter Generates Verdict

**Input to Reporter**:
```python
reporter = ExploitabilityReporter()

cve_data = {
    "cve_id": "CVE-2025-46817",
    "title": "Redis < 8.2.1 lua script - Integer Overflow",
    "description": "Authenticated user can use specially crafted Lua script to cause integer overflow and RCE",
    "severity": "critical"
}

validation_results = [
    {
        "vulnerability": "redis_no_auth",
        "validation": {
            "status": "confirmed",
            "confidence": 0.95
        },
        "evidence": {...},
        "severity": "critical"
    }
]

validators_tested = ["redis_no_auth"]

verdict = reporter.generate_verdict(cve_data, validation_results, validators_tested)
```

**Verdict Generation Logic**:
```python
# Check if any validator confirmed
confirmed_count = 1  # redis_no_auth confirmed
failed_count = 0

if confirmed_count > 0:
    verdict = "exploitable"
    confidence = 0.95  # from validator
else:
    verdict = "negligible" or "false_positive"
    confidence = 0.0
```

**Output Verdict Record**:
```python
CVEVerdictRecord(
    cve_id="CVE-2025-46817",
    title="Redis < 8.2.1 lua script - Integer Overflow",
    severity="critical",
    validators_tested=["redis_no_auth"],
    validation_results=[...],
    verdict="exploitable",
    confidence=0.95,
    evidence={
        "confirmed": 1,
        "failed": 0,
        "items": [
            {
                "source": "redis_no_auth",
                "status": "confirmed",
                "evidence": {"port": 6379, "auth_required": False}
            }
        ]
    }
)
```

### Step 7: Report Generation

**Input**:
```python
cve_verdicts = [
    CVEVerdictRecord(...with verdict="exploitable"...)
]

report = reporter.generate_report(cve_verdicts)
```

**Output Report**:
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
            "validation_results": [
                {
                    "vulnerability": "redis_no_auth",
                    "validation": {
                        "status": "confirmed",
                        "confidence": 0.95
                    },
                    "evidence": {
                        "port": 6379,
                        "auth_required": false,
                        "response": "PONG",
                        "version": "8.2.0"
                    },
                    "severity": "critical"
                }
            ],
            "evidence": {
                "confirmed": 1,
                "failed": 0,
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
            },
            "remediation": ""
        }
    ],
    "false_positive_cves": [],
    "negligible_cves": [],
    "untested_cves": [],
    "all_verdicts": [...]
}
```

## Report Interpretation

The report shows:

✅ **EXPLOITABLE**: CVE-2025-46817
- Redis on port 6379 is accessible **without authentication**
- Confidence: 95% (validator successfully connected and received PONG)
- A malicious user can exploit this CVE's integer overflow in Lua scripts
- **Risk Level**: CRITICAL

## What Happens Next?

Based on this verdict, the system can:

1. **Decision Engine** (`engine/decision.py`):
   - Marks Redis as exploitable
   - Decides to run exploit attempts

2. **Executor** (`engine/executor.py`):
   - Attempts to execute Lua scripts on Redis
   - Tests for actual RCE capability
   - Logs evidence for report

3. **Final Report**:
   - Documents exploited vulnerability
   - Provides remediation: "Require authentication on Redis"
   - Recommends immediate patching to Redis 8.2.1+

## Alternative Scenarios

### Scenario B: CVE Unconfirmed (Network Isolation)

If the validator cannot connect:
```json
"verdict": "negligible",
"confidence": 0.0,
"evidence": {
    "confirmed": 0,
    "failed": 1,
    "items": [{"status": "not_confirmed"}]
}
```

Reason: High severity CVE but validator couldn't confirm → likely mitigated by network policies

### Scenario C: False Positive (Low Severity)

If a low-severity CVE isn't confirmed:
```json
"verdict": "false_positive",
"confidence": 0.0,
"evidence": {
    "confirmed": 0,
    "failed": 1
}
```

Reason: Low severity + unconfirmed = likely scanner error

### Scenario D: Untested (No Validators)

If no validators exist for a CVE:
```json
"verdict": "untested",
"confidence": 0.0,
"evidence": {
    "reason": "No validators ran"
}
```

Reason: CVE detected but no test available yet

## Code Integration in main.py

In Phase 3b of `main.py`:

```python
# CVE-specific validation and reporting
findings = parsed_data.get("findings", [])  # Step 2 output

# Step 3b: Plan & execute CVE validations
cve_plan = dag_brain.plan_cve_validations(state, findings)

# Run validators
cve_validation_results = cve_vengine.run(state)

# Generate verdicts
reporter = ExploitabilityReporter()
cve_verdicts = []
for cve_id, cve_data in cve_plan.cve_details.items():
    validators_for_cve = cve_plan.cve_to_validators[cve_id]
    relevant_results = filter(cve_validation_results, validators_for_cve)
    verdict = reporter.generate_verdict(cve_data, relevant_results, validators_for_cve)
    cve_verdicts.append(verdict)

# Save report
report = reporter.generate_report(cve_verdicts)
json.dump(report, open("output/exploitability_report.json", "w"))
```

## Testing This Example

Run the pipeline:
```bash
python3 main.py --target redis.example.com
```

Check the report:
```bash
cat output/exploitability_report.json
```

Or run the integration test:
```bash
python3 test_cve_pipeline.py
```
