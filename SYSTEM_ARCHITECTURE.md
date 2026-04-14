# Pentester Project - Complete Architecture

## System Overview

This is a comprehensive vulnerability detection and exploitation assessment system that:
1. Scans a target for vulnerabilities using multiple reconnaissance tools
2. Detects CVEs in scan results
3. Maps CVEs to applicable validators
4. Runs validators to confirm exploitability
5. Generates a report showing CVE status (exploitable vs negligible/false positive)

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 1: RECONNAISSANCE (Parallel Scans)                         │
├─────────────────────────────────────────────────────────────────┤
│ • Naabu (Port Scanning)          → ports, services              │
│ • HTTPX (HTTP Probing)           → web servers, headers         │
│ • Nuclei (Vulnerability Scanning) → CVE IDs, templates          │
│ • Gospider (Web Crawling)        → URLs, endpoints              │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 2: AGGREGATION (Parser)                                   │
├─────────────────────────────────────────────────────────────────┤
│ Combines results from all tools into unified findings structure  │
│ • findings[]  - all vulnerabilities                             │
│ • ports[]     - open ports discovered                           │
│ • services[]  - service info                                    │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 3: VALIDATION (DAG-based Planning)                        │
├─────────────────────────────────────────────────────────────────┤
│ Sub-Phase 3a: Standard Validation                               │
│   • DAG Brain plans validators by ports/protocols               │
│   • Runs registered validators                                  │
│   • Saves results to output/validations.json                    │
│                                                                  │
│ Sub-Phase 3b: CVE-Specific Validation (NEW)                    │
│   • CVE Mapper extracts CVE IDs from findings                   │
│   • Maps each CVE to applicable validators                      │
│   • DAG Brain creates validator instances for CVEs              │
│   • Runs only relevant validators per CVE                       │
│   • ExploitabilityReporter generates verdicts                   │
│   • Saves report to output/exploitability_report.json           │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 4: DECISION & EXECUTION                                   │
├─────────────────────────────────────────────────────────────────┤
│ • Decides next actions based on validation results              │
│ • Executes exploitation attempts (sqlmap, XSS tests)            │
│ • Generates final report                                        │
└─────────────────────────────────────────────────────────────────┘
```

## Module Structure

### Core Modules

```
pentester/
├── main.py                          # Main pipeline orchestrator
│
├── recon/                           # Reconnaissance tools
│   ├── naabu_scan.py               # Port scanning
│   ├── httpx_scan.py               # HTTP probing
│   ├── nuclei_scan.py              # CVE detection ← CVE source
│   └── gospider_scan.py            # Web crawling
│
├── aggregator/
│   └── parser.py                   # Combines scan results
│
├── brain/                           # Intelligence & planning
│   ├── dag_engine.py               # DAG-based validator planning
│   │                               # NEW: plan_cve_validations()
│   ├── cve_mapper.py               # NEW: CVE ID extraction & mapping
│   ├── exploitability_reporter.py  # NEW: Verdict generation
│   ├── graph_builder.py            # DAG graph construction
│   ├── kb.py                       # Knowledge base (validators, CVEs)
│   └── [session files]
│
├── engine/                          # Execution engines
│   ├── validation_engine.py        # Validator registry & runner
│   ├── decision.py                 # Decision logic
│   ├── executor.py                 # Exploit execution
│   └── models.py                   # Data models
│
├── validators/                      # Concrete validators
│   ├── redis.py                    # Redis no-auth validator
│   └── http.py                     # Security headers validator
│
├── utils/                           # Utilities
│   ├── logger.py                   # Logging
│   ├── retry.py                    # Retry logic
│   └── session.py                  # Session management
│
└── output/                          # Report outputs
    ├── validations.json            # Standard validation results
    ├── exploitability_report.json  # ← NEW: CVE verdicts
    ├── gospider.json
    ├── httpx.json
    ├── naabu.json
    └── nuclei.json
```

## Data Flow: CVE Detection to Report

### 1. CVE Discovery (Nuclei Scan)

**Input**: Target domain/IP  
**Output**: Findings with CVE IDs

```python
finding = {
    "title": "Redis No Authentication - CVE-2025-46817",
    "cve": "CVE-2025-46817",
    "severity": "critical",
    "template": "redis-no-auth",
    "host": "redis.example.com",
    "port": 6379,
}
```

### 2. CVE Extraction (CVE Mapper)

**Input**: Findings list  
**Output**: CVE ID → Validator mapping

```python
cve_to_validators = mapper.map_findings_to_cves(findings)
# {"CVE-2025-46817": ["redis_no_auth"]}
```

### 3. Validator Planning (DAG Brain)

**Input**: State, findings  
**Output**: Validator instances ready to run

```python
cve_plan = dag_brain.plan_cve_validations(state, findings)
# cve_plan.cve_to_validators = {"CVE-2025-46817": ["redis_no_auth"]}
# cve_plan.validator_instances = {"redis_no_auth": RedisNoAuthValidator()}
```

### 4. Validator Execution (Validation Engine)

**Input**: Validator instances, state  
**Output**: Validation results

```python
validation_results = [
    {
        "vulnerability": "redis_no_auth",
        "validation": {
            "status": "confirmed",
            "confidence": 0.95,
        },
        "evidence": {
            "port": 6379,
            "auth_required": False,
            "response": "PING",
        },
    },
]
```

### 5. Verdict Generation (Exploitability Reporter)

**Input**: CVE metadata, validation results  
**Output**: Exploitability verdict

```python
verdict = reporter.generate_verdict(
    cve_data={"cve_id": "CVE-2025-46817", "severity": "critical", ...},
    validation_results=validation_results,
    validators_tested=["redis_no_auth"],
)
# verdict.verdict = "exploitable"
# verdict.confidence = 0.95
```

### 6. Report Aggregation

**Input**: List of verdicts  
**Output**: Final report with summary

```json
{
    "summary": {
        "total_cves": 1,
        "exploitable": 1,
        "negligible": 0,
        "false_positives": 0,
        "untested": 0
    },
    "exploitable_cves": [
        {
            "cve_id": "CVE-2025-46817",
            "title": "Redis < 8.2.1 lua script - Integer Overflow",
            "verdict": "exploitable",
            "confidence": 0.95,
            ...
        }
    ],
    "all_verdicts": [...]
}
```

## Key Classes & Interfaces

### CVE Mapper (`brain/cve_mapper.py`)

```python
class CVEMapper:
    def map_findings_to_cves(findings: List[Dict]) -> Dict[str, List[str]]:
        # CVE ID → validator IDs
    
    def get_cve_verdict_data(cve_id: str) -> Dict[str, Any]:
        # CVE metadata for reporting
```

### DAG Brain (`brain/dag_engine.py`)

```python
class DAGBrain:
    def plan_validations(state: Dict) -> DAGPlan:
        # Standard validator planning
    
    def plan_cve_validations(state: Dict, findings: List) -> CVEValidationPlan:
        # CVE-specific validator planning
        # NEW METHOD
```

### Exploitability Reporter (`brain/exploitability_reporter.py`)

```python
class ExploitabilityReporter:
    def generate_verdict(
        cve_data: Dict,
        validation_results: List,
        validators_tested: List,
    ) -> CVEVerdictRecord:
        # Single CVE verdict
    
    def generate_report(cve_verdicts: List[CVEVerdictRecord]) -> Dict:
        # Aggregated report with summary
```

## Verdict Decision Logic

```
Input: Validation results for a CVE

if any_validator_confirmed_vulnerability:
    verdict = "exploitable"
    confidence = highest_confidence_from_validators
    
elif all_validators_failed:
    if cve_severity in [critical, high]:
        verdict = "negligible"      # Likely patched/mitigated
    else:
        verdict = "false_positive"  # Low severity, unconfirmed
    confidence = 0.0
    
else:
    verdict = "untested"
    confidence = 0.0
```

## CVE Database

Currently supported CVEs (in `brain/cve_mapper.py`):

### Redis CVEs
- **CVE-2025-46817**: Lua script integer overflow (critical)
- **CVE-2025-49844**: Lua parser use-after-free (critical)
- **CVE-2025-46819**: Lua long-string delimiter OOB read (high)
- **CVE-2025-46818**: Lua sandbox cross-user escape (high)

All map to `redis_no_auth` validator.

## Extending the System

### To Add a New CVE Type

1. **Define CVESpec** in `brain/cve_mapper.py`:
   ```python
   CVESpec(
       cve_id="CVE-YYYY-XXXXX",
       title="Vulnerability title",
       description="Full description",
       severity="critical|high|medium|low",
       applicable_validators=["validator_id"],
       keywords=["keyword1", "keyword2"],
   )
   ```

2. **Implement validator** if needed (in `validators/`):
   ```python
   class MyValidator:
       def validate(self, state) -> Dict:
           # Test for vulnerability
           return {"status": "confirmed|failed", "confidence": 0.0-1.0}
   ```

3. **Register validator** in `dag_engine.py` VALIDATOR_CLASS_MAP

### To Add a New Reconnaissance Tool

1. Create scanner module in `recon/`
2. Add to scan pipeline in `main.py`
3. Update parser to handle output format

## Testing

Run integration test:
```bash
python3 test_cve_pipeline.py
```

This verifies:
- CVE extraction from findings
- CVE → validator mapping
- Validator instantiation
- Verdict generation
- Report generation

## Output Files

| File | Purpose | Format |
|------|---------|--------|
| `output/validations.json` | Standard validator results | JSON |
| `output/exploitability_report.json` | CVE verdicts | JSON |
| `output/gospider.json` | Spider crawl results | JSON |
| `output/httpx.json` | HTTP probe results | JSON |
| `output/naabu.json` | Port scan results | JSON |
| `output/nuclei.json` | CVE scan results | JSON |
| `output/session.json` | Session state | JSON |

## Design Principles

1. **Separation of Concerns**: Scanning, aggregation, validation, and reporting are separate phases
2. **DAG-based Planning**: Validator dependencies ordered via topological sort
3. **CVE-centric Validation**: Each CVE has explicit mapping to validators
4. **Confidence Scoring**: Verdicts include confidence levels (0.0-1.0)
5. **Extensibility**: Easy to add new CVE specs and validators
6. **Clear Reporting**: Verdicts categorized (exploitable/negligible/false_positive/untested)

## Future Enhancements

- [ ] Web UI for report visualization
- [ ] Automated exploit execution for confirmed vulnerabilities
- [ ] Machine learning for false positive detection
- [ ] Integration with threat intelligence feeds
- [ ] Multi-target scanning with aggregation
- [ ] Scheduled scanning with trend analysis
- [ ] Slack/email alerts for critical CVEs
