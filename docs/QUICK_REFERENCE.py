"""
QUICK REFERENCE: Expert-Level Attack Chaining Engine

╔═══════════════════════════════════════════════════════════════════════╗
║         ADVANCED RED-TEAMING ENGINE - QUICK REFERENCE CARD           ║
╚═══════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════════
COMPONENT OVERVIEW
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────┬──────────────┬─────────────────────────────────┐
│ Component               │ File         │ Purpose                         │
├─────────────────────────┼──────────────┼─────────────────────────────────┤
│ FactStore              │ fact_store.py│ Centralized state manager      │
│ EndpointNormalizer     │endpoint_norm │ Parameter deduplication        │
│ AttackChainManager     │attack_chain  │ Chain orchestration            │
│ DAGBrain (Enhanced)    │dag_engine_en │ Fact-aware DAG planning        │
│ ValidationEngine       │validation_en │ Automated fact extraction      │
│ (Enhanced)             │              │ & chain triggering             │
└─────────────────────────┴──────────────┴─────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
INITIALIZATION (Copy & Paste)
═══════════════════════════════════════════════════════════════════════════════

from brain.fact_store import FactStore
from brain.endpoint_normalizer import EndpointNormalizer
from brain.attack_chain_manager import AttackChainManager
from brain.dag_engine_enhanced import DAGBrain
from engine.validation_engine_enhanced import ValidationEngine, StateManager

# Step 1: Create shared components
fact_store = FactStore()
endpoint_normalizer = EndpointNormalizer()
attack_chain_manager = AttackChainManager(fact_store)

# Step 2: Initialize engines with components
dag_engine = DAGBrain(
    fact_store=fact_store,
    endpoint_normalizer=endpoint_normalizer
)
val_engine = ValidationEngine(
    fact_store=fact_store,
    endpoint_normalizer=endpoint_normalizer,
    attack_chain_manager=attack_chain_manager
)
state_manager = StateManager(fact_store=fact_store)

# Step 3: Register chain injection callback (optional)
def on_chain_inject(node):
    print(f"[CHAIN] Injecting: {node.exploit_type}")
    # Queue node for execution here

dag_engine.register_chain_injection_callback(on_chain_inject)

═══════════════════════════════════════════════════════════════════════════════
FACT STORE API
═══════════════════════════════════════════════════════════════════════════════

# Add Facts
fact_store.add_credential(
    username="admin",
    password="secret",
    source_validator_id="cred_leak",
    confidence=0.98
)
fact_store.add_internal_host("192.168.1.10", source_validator_id="ssrf")
fact_store.add_confirmed_vulnerability("sqli_form", "sql_injection", "/login.php")
fact_store.add_active_session("session_123", "token_xyz", target="admin_panel")
fact_store.add_exploitation_artifact("shell_1", "shell_output", "uid=0 root")

# Query Facts
creds = fact_store.get_facts_by_category(FactCategory.CREDENTIAL)
all_facts = fact_store.query(
    FactCategory.CREDENTIAL,
    predicate=lambda f: f.confidence >= 0.9,
    min_confidence=0.7
)

# Check Prerequisites
from brain.fact_store import PrerequisiteQuery
query = PrerequisiteQuery(
    required_facts={
        FactCategory.CONFIRMED_VULNERABILITY: ["ssrf"],
        FactCategory.EXPLOITATION_ARTIFACT: ["metadata_token"]
    }
)
if fact_store.prerequisites_met(query):
    print("Ready for lateral movement")

# Export & Clear
exported = fact_store.export()  # Full state as dict
summary = fact_store.get_summary()  # Count by category
fact_store.clear()  # Clear all facts

═══════════════════════════════════════════════════════════════════════════════
ENDPOINT NORMALIZER API
═══════════════════════════════════════════════════════════════════════════════

normalizer = EndpointNormalizer()

# Register Endpoint
pattern_key, already_scanned = normalizer.register_endpoint(
    "/item.php?id=123&name=test",
    vulnerability_type="xss"
)

# Check if Should Skip
if normalizer.should_skip_scan("/item.php?id=456&name=apple", "xss"):
    print("Pattern already scanned, skipping")

# Mark Pattern Scanned
normalizer.mark_pattern_scanned(pattern_key)

# Get Statistics
stats = normalizer.get_pattern_stats()
# Returns: {
#   "total_patterns": 15,
#   "scanned_patterns": 8,
#   "total_endpoints": 47,
#   "deduplication_ratio": 0.68
# }

# Get Pattern Candidates
endpoints = normalizer.get_pattern_candidates("/item.php?id={int}")

═══════════════════════════════════════════════════════════════════════════════
ATTACK CHAINS (5 Built-in)
═══════════════════════════════════════════════════════════════════════════════

Chain A: Port → Service → Creds → Auth Attack
  Trigger: port_discovery → unauth_service → cred_leak
  Result: Authenticated RCE

Chain B: SSRF → Metadata → Token Theft
  Trigger: ssrf_validator
  Result: IAM credentials extracted

Chain C: XSS + CSRF → Session Hijacking
  Trigger: xss_validator + csrf_validator
  Result: Session hijacking payload

Chain D: LFI → Source → Creds
  Trigger: lfi_validator
  Result: Hardcoded credentials extracted

Chain E: RCE → Shell → Privesc
  Trigger: rce_validator
  Result: Privilege escalation

# Enable/Disable Chains
chain_manager.enable_chain("chain_a")
chain_manager.disable_chain("chain_d")

# Get Active Chains
active = chain_manager.get_active_chains()
for chain in active:
    print(f"Chain {chain.name} is triggerable")

# Get Pending Exploitations
pending = chain_manager.get_pending_exploitation_nodes()

═══════════════════════════════════════════════════════════════════════════════
VALIDATION RESULT PROCESSING
═══════════════════════════════════════════════════════════════════════════════

# High-Confidence Validation with Execution Proof
from engine.models import ValidationResult, Evidence, EvidenceBundle

result = ValidationResult(
    success=True,
    confidence=0.95,
    confidence_score=0.95,  # 0.0-1.0
    severity="critical",
    vulnerability="remote_code_execution",
    evidence=Evidence(
        request="POST /shell.php",
        response="uid=0",
        matched="uid=0"
    ),
    evidence_bundle=EvidenceBundle(
        raw_request="POST /shell.php\nid",
        raw_response="uid=0(root) gid=0(root)",
        matched_indicator="uid=0",
        execution_proof={"shell_output": "uid=0..."},
        tool_logs=[{"tool": "shell", "output": "..."}]
    ),
    execution_proved=True,  # Actual code execution!
    chain_source="upload_validator"  # Parent vulnerability
)

# Process Result (automatically extract facts & trigger chains)
processed = val_engine.result_processor.process_result(result)
# processed["extracted_facts"] = [...] ← Facts added to store
# processed["injected_nodes"] = [...]  ← Chains triggered

═══════════════════════════════════════════════════════════════════════════════
VALIDATION ENGINE PIPELINE
═══════════════════════════════════════════════════════════════════════════════

# Step 1: Plan
state = {
    "target": "altoro.testfire.net",
    "endpoints": ["/login.php", "/search.php"],
    "protocols": ["http", "https"]
}
plan = dag_engine.plan_validations(state)

# Step 2: Run
results = val_engine.run(plan, state)
# Each result includes:
#   - success, confidence_score, severity
#   - evidence, evidence_bundle
#   - extracted_facts: newly discovered facts
#   - injected_nodes: exploitation nodes to queue

# Step 3: Update State
new_confirmed = state_manager.update(state, results)
state["fact_store_state"] = fact_store.export()

# Step 4: Check for Chains
for result in results:
    if result.get("injected_nodes"):
        print(f"Chain triggered: {result['injected_nodes']}")

═══════════════════════════════════════════════════════════════════════════════
COMMON PATTERNS
═══════════════════════════════════════════════════════════════════════════════

Pattern 1: Check Prerequisites Before Exploitation
────────────────────────────────────────────────────
from brain.fact_store import PrerequisiteQuery, FactCategory

query = PrerequisiteQuery(
    required_facts={
        FactCategory.ACTIVE_SESSION: ["admin_session"]
    },
    min_confidence=0.9
)
if fact_store.prerequisites_met(query):
    # Launch admin-only exploit


Pattern 2: Custom Fact Extraction
──────────────────────────────────
def extract_custom_facts(result):
    facts = []
    if "custom_indicator" in result.get("evidence", {}).get("response", ""):
        fact = Fact(
            category=FactCategory.EXPLOITATION_ARTIFACT,
            key="custom_artifact",
            value={"extracted_data": "..."}
        )
        fact_store.add_fact(fact)
        facts.append(fact)
    return facts

val_engine.result_processor.register_extraction_rule(
    "custom_validator",
    extract_custom_facts
)


Pattern 3: Iterate with Chains
───────────────────────────────
iteration = 0
while iteration < 3:
    plan = dag_engine.plan_validations(state)
    results = val_engine.run(plan, state)
    state_manager.update(state, results)
    
    # Queue injected nodes
    for result in results:
        for node in result.get("injected_nodes", []):
            queue_exploitation_node(node)
    
    iteration += 1


Pattern 4: Monitor Chain Progress
──────────────────────────────────
stats = chain_manager.get_chain_statistics()
print(f"Active chains: {stats['triggered_chains']}")
print(f"Pending exploits: {stats['pending_exploitation_nodes']}")

summary = fact_store.get_summary()
print(f"Credentials: {summary.get('credential', 0)}")
print(f"Vulnerabilities: {summary.get('confirmed_vulnerability', 0)}")

═══════════════════════════════════════════════════════════════════════════════
CONFIDENCE LEVELS REFERENCE
═══════════════════════════════════════════════════════════════════════════════

0.60 - Pattern Match Only
     Example: Regex found "<script>" in response
     Action: Likely vulnerable, needs deeper testing

0.75 - Error-Based Detection
     Example: SQL error message in response
     Action: Vulnerability probable, may be false positive

0.85 - Time-Based Blind
     Example: Response time difference proves execution
     Action: Vulnerability confirmed, low false positive rate

0.95 - Code Execution Proof
     Example: Command output (uid=0) in response
     Action: Definitely exploited, highest confidence

0.98+ - Multiple Confirmations
     Example: Shell output + file read + network callback all succeeded
     Action: Exploit chain established, safe to use in further attacks

═══════════════════════════════════════════════════════════════════════════════
DEBUGGING & MONITORING
═══════════════════════════════════════════════════════════════════════════════

# Export Engine State
engine_state = dag_engine.get_engine_state()
print(json.dumps(engine_state, indent=2))

# Monitor Specific Category
creds = fact_store.query(
    FactCategory.CREDENTIAL,
    min_confidence=0.9
)
for cred in creds:
    print(f"{cred.key}: confidence={cred.confidence}")

# Track Chain Execution
for chain in chain_manager.chains.values():
    print(f"Chain: {chain.name}")
    print(f"  Trigger sequence: {chain.trigger_sequence}")
    print(f"  Can trigger: {chain.can_trigger(...)}")

# Endpoint Statistics
stats = endpoint_normalizer.get_pattern_stats()
print(f"Deduplication saves: {stats['deduplication_ratio']:.1%}")

═══════════════════════════════════════════════════════════════════════════════
FILE LOCATIONS
═══════════════════════════════════════════════════════════════════════════════

Core Implementation:
  brain/fact_store.py
  brain/endpoint_normalizer.py
  brain/attack_chain_manager.py
  brain/dag_engine_enhanced.py
  engine/validation_engine_enhanced.py
  brain/attack_chain_examples.py

Documentation:
  docs/README_REFACTORING.md .................. Start here
  docs/EXPERT_CHAINING_REFACTORING.md ........ Architecture
  docs/ADVANCED_CHAINING_GUIDE.md ............ Integration guide

Examples:
  examples/complete_chaining_example.py ...... End-to-end example
  brain/attack_chain_examples.py ............. Chain implementations

═══════════════════════════════════════════════════════════════════════════════
TROUBLESHOOTING
═══════════════════════════════════════════════════════════════════════════════

Q: Chains not triggering?
A: Check chain_manager.get_active_chains()
   Verify validators have correct IDs in trigger_sequence

Q: Fact store not populating?
A: Ensure extraction rules registered before val_engine.run()
   Check result["extracted_facts"] in results

Q: Endpoints not deduping?
A: Call mark_pattern_scanned() after testing each pattern
   Verify should_skip_endpoint() returns True on duplicates

Q: Memory growing too large?
A: Call fact_store.clear() between engagements
   Limit evidence_bundle sizes in validators

Q: Chains executing but results wrong?
A: Check injected_nodes in results
   Verify exploitation node payloads are correct
   Enable logging in on_chain_inject callback

═══════════════════════════════════════════════════════════════════════════════
PERFORMANCE TIPS
═══════════════════════════════════════════════════════════════════════════════

• Use EndpointNormalizer to reduce test count by 60-80%
• Register extraction rules for common validator types
• Clear fact_store between unrelated targets
• Archive old endpoint patterns periodically
• Batch chain evaluations (don't evaluate every result)
• Cache pattern matches in EndpointNormalizer
• Limit evidence_bundle sizes (don't store entire HTML responses)

═══════════════════════════════════════════════════════════════════════════════

For detailed documentation, see: docs/README_REFACTORING.md
For integration examples, see: examples/complete_chaining_example.py
For implementation details, see: brain/attack_chain_examples.py

═══════════════════════════════════════════════════════════════════════════════
"""

if __name__ == "__main__":
    print(__doc__)
    print("\n✓ Quick reference card ready!")
    print("  → Copy code snippets from sections above")
    print("  → Refer back to CONFIDENCE LEVELS when scoring results")
    print("  → Use COMMON PATTERNS for your implementation")
