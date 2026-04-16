# Pentester Project Architecture Analysis

## Current System Overview

### Project Structure
Your project is a **penetration testing automation pipeline** that:
1. **Scans targets** using specialized tools (naabu, httpx, gospider, nuclei)
2. **Parses scan results** into a unified format (aggregator)
3. **Validates findings** using specialized validator classes (Redis, HTTP headers, etc.)
4. **Makes decisions** on what exploitation/testing to run (SQLi, XSS tests)
5. **Executes actions** (sqlmap, XSS testing, redis checks)

### Key Components

#### 1. **Recon Layer** (`recon/`)
- `naabu_scan.py` - Port scanning
- `httpx_scan.py` - HTTP service probing
- `gospider_scan.py` - Web crawling & endpoint discovery
- `nuclei_scan.py` - Vulnerability template scanning
- **Output**: JSON files with discovered hosts, ports, endpoints, vulnerabilities

#### 2. **Aggregator Layer** (`aggregator/`)
- `parser.py` - Unifies scan results from multiple tools
- Normalizes findings into a common schema with:
  - Assets (hosts, ports, endpoints)
  - Findings (title, tags, severity, evidence)
  - Validation results

#### 3. **Validation Engine** (`engine/`)
- `validation_engine.py` - Registry pattern for validators
- `models.py` - Data structures (Evidence, ValidationResult)
- `decision.py` - Maps findings → exploitation actions
- `executor.py` - Runs actual exploitation (sqlmap, XSS)

#### 4. **Validators** (`validators/`)
- `redis.py` - Tests for unauthenticated Redis
- `http.py` - Checks missing security headers
- Each validator has:
  - `can_run(state)` - Check if validator applies
  - `run(state)` - Execute validation logic

## Current Flow

```
Target
  ↓
[Recon Tools] → naabu.json, httpx.json, gospider.json, nuclei.json
  ↓
[Parser/Aggregator] → Normalized findings + assets
  ↓
[Validation Engine] → Check each registered validator
  ↓
[Decision Engine] → Map findings to exploitation actions
  ↓
[Executor] → Run sqlmap, XSS tests, etc.
  ↓
Result: findings.json, actions, validations.json
```

## Current Problems to Solve with Static Matching

### 1. **Hardcoded Validator Registration**
Currently, validators are manually registered in `main.py`. No intelligent matching between:
- Scan findings → Applicable validators
- Vulnerability types → Exploit chains

### 2. **Static Decision Logic**
`decision.py` uses simple string matching (keywords like "xss", "sql").
Misses context:
- Related vulnerabilities requiring chained tests
- Port/service correlation with validators
- Multi-stage validation dependencies

### 3. **No Knowledge Base**
No semantic understanding of:
- What makes a validator applicable to a vulnerability
- Relationships between vulnerabilities
- Common attack chains and patterns

### 4. **Scalability Issues**
Adding new validators requires:
- Manual code changes
- String matching updates
- No way to share knowledge about validator capabilities

## Proposed DAG System Architecture

### Overview

```
┌─────────────────────────────────────────────────────┐
│                    DAG BRAIN                         │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐│
│  │  Knowledge   │  │   Executor   │  │ Validator ││
│  │    Graph     │  │              │  │   Chain   ││
│  ├──────────────┤  ├──────────────┤  ├───────────┤│
│  │ Validators   │  │ Dependency   │  │Multi-step ││
│  │ (Nodes)      │→ │ Resolution   │→ │ Testing   ││
│  │ Findings     │  │              │  │           ││
│  │ (Edges)      │  │ Topological  │  │Exploit    ││
│  │ Chains       │  │ Sorting      │  │Sequences  ││
│  └──────────────┘  └──────────────┘  └───────────┘│
│                                                     │
│  Uses: DAG structure (networkx) + constraint      │
│  resolution + execution planning                   │
│                                                     │
└─────────────────────────────────────────────────────┘
                          ↑
                    Scan Results
                    (Findings)
                          ↓
            [Decision Engine with DAG]
                          ↓
            Optimized Execution Order
                          ↓
                    Actions to Execute
```

### Key Components

#### 1. **Knowledge Base (`brain/kb.py`)**
- DAG node definitions (validators with metadata)
- Vulnerability catalog
- Dependency constraints
- Prerequisite relationships
- Conflict detection

#### 2. **Graph Builder (`brain/graph_builder.py`)**
- Construct DAG from findings and validators
- Add nodes for each applicable validator
- Create edges for dependencies
- Detect and resolve conflicts

#### 3. **Executor (`brain/executor.py`)**
- Topological sort for execution order
- Parallel execution when possible
- Dependency tracking
- Failure handling and backtracking

#### 4. **Analyzer (`brain/analyzer.py`)**
- Find attack paths through the graph
- Calculate execution chains
- Identify critical path
- Estimate impact/coverage

#### 5. **Integration (`brain/integration.py`)**
- Connect to existing ValidationEngine
- Map findings to DAG nodes
- Execute planned chains
- Collect and aggregate results

### Data Structures

```yaml
# Validator Metadata
Validator:
  id: "redis_no_auth"
  name: "RedisNoAuthValidator"
  description: "Checks for unauthenticated Redis access on port 6379"
  requirements:
    ports: [6379]
    services: ["redis"]
  outputs:
    vulnerability: "redis-no-auth"
    severity: "high"
  can_chain_with: ["redis_key_extraction", "redis_command_exec"]
  keywords: ["redis", "auth", "6379", "no auth", "noauth"]

# Vulnerability Metadata  
Vulnerability:
  id: "redis-no-auth"
  name: "Unauthenticated Redis Access"
  cve: "CVE-XXXX-XXXX"
  severity: "high"
  description: "Redis server accessible without credentials"
  finding_keywords: ["redis", "6379", "unauthenticated"]
  applicable_validators: ["redis_no_auth", "redis_bruteforce"]
  next_steps: ["extract_keys", "execute_commands"]
  
# Attack Chain
AttackChain:
  id: "redis_exploitation"
  severity: "high"
  steps:
    1: "redis_no_auth" → confirms access
    2: "redis_key_extraction" → gets data
    3: "redis_persistence" → maintains access
  conditions:
    - Redis port open
    - No authentication required
```

## Implementation Strategy

### Phase 1: Core DAG System
1. Create knowledge base with validator metadata
2. Build DAG graph and dependency resolution
3. Implement topological sorting and execution planning
4. Test with existing validators

### Phase 2: Integration
1. Create DAG-aware decision engine
2. Update validation_engine.py integration
3. Replace hardcoded logic in decision.py
4. Add action chain execution

### Phase 3: Enhancement
1. Add vulnerability catalogs
2. Implement attack chains
3. Add conflict detection
4. Create graph visualization and feedback loop

## Benefits

✅ **Automatic validator discovery** - No manual registration
✅ **Semantic understanding** - Context-aware decisions
✅ **Scalable** - Add validators without code changes
✅ **Chainable** - Multi-step exploitation sequences
✅ **Learnable** - Feedback improves recommendations
✅ **Auditable** - See why each validator was chosen

## Files to Create

```
brain/
  ├── __init__.py
  ├── kb.py              # Knowledge base definitions
  ├── graph_builder.py    # DAG construction
  ├── dag_engine.py       # Main DAG orchestrator
  └── data/
      ├── validators.yaml
      ├── vulnerabilities.yaml
      └── chains.yaml
```

## Usage Example

```python
from brain.dag_engine import DAGBrain
from engine.validation_engine import ValidationEngine

# Initialize
brain = DAGBrain()
vengine = ValidationEngine()

# Example findings from the scanner
state = {
  "target": "example.com",
  "ports": [6379, 80, 443],
  "protocols": ["http"],
  "findings": [
    {"title": "Redis service exposed"},
    {"title": "Missing security headers"},
  ],
}

# Build the DAG and get the execution order
plan = brain.plan_validations(state)

# Register validators in DAG order and run them
for validator in plan.validators:
  vengine.register(validator)

validation_results = vengine.run(state)
```
