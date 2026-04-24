"""
INTEGRATION GUIDE: Advanced Attack Chaining Engine

This guide explains how to integrate the enhanced DAG engine with your
existing red-teaming pipeline to enable expert-level attack chaining.

========================================================================
COMPONENTS OVERVIEW
========================================================================

1. FactStore (brain/fact_store.py)
   - Centralized state manager for discovered prerequisites
   - Categories: credentials, internal_hosts, active_sessions, 
     confirmed_vulnerabilities, service_info, endpoints, artifacts
   - Thread-safe singleton

2. EndpointNormalizer (brain/endpoint_normalizer.py)
   - Deduplication via parameter pattern grouping
   - Example: /item.php?id=1 and /item.php?id=2 → /item.php?id={int}
   - Reduces redundant vulnerability scanning

3. AttackChainManager (brain/attack_chain_manager.py)
   - Manages 5 built-in attack chains
   - Detects when prerequisites are met
   - Dynamically injects exploitation nodes
   - Chainable callbacks

4. Enhanced Models (engine/models.py)
   - EvidenceBundle: Rich evidence with execution proof
   - ValidationResult: confidence_score, evidence_bundle, chain_source
   - execution_proved: True if actual code executed

5. Enhanced DAGEngine (brain/dag_engine_enhanced.py)
   - Fact store aware planning
   - Chain injection support
   - Endpoint deduplication

6. Enhanced ValidationEngine (engine/validation_engine_enhanced.py)
   - ValidationResultProcessor: Automatic fact extraction
   - Fact store updates on validation success
   - Chain reaction triggering

========================================================================
QUICK START: 3-Step Integration
========================================================================

Step 1: Initialize Enhanced Components
-----------------------------------------

from brain.fact_store import FactStore
from brain.endpoint_normalizer import EndpointNormalizer
from brain.attack_chain_manager import AttackChainManager
from brain.dag_engine_enhanced import DAGBrain
from engine.validation_engine_enhanced import ValidationEngine

# Create shared components
fact_store = FactStore()
endpoint_normalizer = EndpointNormalizer()
attack_chain_manager = AttackChainManager(fact_store)

# Initialize enhanced engines
dag_engine = DAGBrain(
    fact_store=fact_store,
    endpoint_normalizer=endpoint_normalizer,
)

validation_engine = ValidationEngine(
    fact_store=fact_store,
    endpoint_normalizer=endpoint_normalizer,
    attack_chain_manager=attack_chain_manager,
)

# Define chain injection callback
def on_chain_inject(node):
    '''Called when exploitation node should be injected'''
    print(f"[CHAIN] Injecting: {node.exploit_type}")
    # Add to DAG for execution
    # Your DAG update logic here

dag_engine.register_chain_injection_callback(on_chain_inject)


Step 2: Plan and Execute Validations
--------------------------------------

# Plan validations with enhanced engine
state = {
    "target": "altoro.testfire.net",
    "endpoints": ["/login.php", "/search.php"],
    "protocols": ["http", "https"],
}

plan = dag_engine.plan_validations(state)

# Run with fact store integration
results = validation_engine.run(plan, state)

# State now includes:
# - state["fact_store_state"]: All discovered facts
# - results[i]["injected_nodes"]: Exploitation nodes to inject
# - results[i]["extracted_facts"]: Facts discovered from this validation


Step 3: Iterate with Attack Chains
-----------------------------------

confirmed_validations = [r for r in results if r["success"]]

for result in confirmed_validations:
    print(f"✓ {result['vulnerability']} (confidence: {result['validation']['confidence_score']})")
    
    # Check for injected nodes
    injected = result.get("injected_nodes", [])
    if injected:
        print(f"  → Triggering {len(injected)} exploitation node(s)")
        
        for node in injected:
            print(f"    - {node['exploit_type']}: {node['description']}")
            # Queue node for exploitation execution

# Get updated fact store
facts = fact_store.export()
print(f"Discovered credentials: {len(facts.get('credential', []))}")
print(f"Internal hosts: {len(facts.get('internal_host', []))}")

========================================================================
ADVANCED USAGE: Custom Attack Chains
========================================================================

Example: Add Custom Attack Chain
---------------------------------

from brain.attack_chain_manager import AttackChain, ChainedExploitationNode
from brain.fact_store import PrerequisiteQuery, FactCategory

# Define your custom chain
custom_chain = AttackChain(
    chain_id="custom_auth_bypass",
    name="Session Token to Account Takeover",
    description="Use leaked session token to hijack admin account",
    trigger_sequence=["session_token_leak"],  # Prerequisite validators
    exploitation_nodes=[
        ChainedExploitationNode(
            node_id="admin_impersonation",
            parent_validator_id="session_token_leak",
            exploit_type="account_takeover",
            target="admin_panel",
            payload={
                "cookie_name": "admin_session",
                "replacement_action": "delete_security_logs",
            },
            description="Delete audit logs to cover tracks",
            expected_artifact="logs_deleted",
        ),
    ],
)

# Register chain
attack_chain_manager.chains["custom_auth_bypass"] = custom_chain

# Now when "session_token_leak" validator succeeds, the exploitation node
# will be automatically injected


Example: Custom Fact Extraction Rules
--------------------------------------

from brain.fact_store import FactCategory, Fact

def extract_database_credentials(result):
    '''Custom extraction for database-related vulnerabilities'''
    facts = []
    
    # Parse custom response format
    response = result.get("evidence", {}).get("response", "")
    
    # Your parsing logic
    if "connection_string" in response:
        # Extract credentials
        fact = Fact(
            category=FactCategory.CREDENTIAL,
            key="database_creds",
            value={"host": "db.internal", "user": "appuser"},
            confidence=0.95,
            source_validator_id=result.get("validator_id"),
        )
        fact_store.add_fact(fact)
        facts.append(fact)
    
    return facts

# Register custom rule
validation_engine.result_processor.register_extraction_rule(
    "database_error_leak",
    extract_database_credentials,
)


Example: Query Fact Store for Readiness
---------------------------------------

from brain.fact_store import PrerequisiteQuery, FactCategory

# Check if we have discovered credentials
has_creds = len(fact_store.get_facts_by_category(FactCategory.CREDENTIAL)) > 0

# Check specific prerequisites for node readiness
query = PrerequisiteQuery(
    required_facts={
        FactCategory.CONFIRMED_VULNERABILITY: ["ssrf_to_metadata"],
        FactCategory.EXPLOITATION_ARTIFACT: ["iam_token"],
    },
    min_confidence=0.8,
    all_required=True,
)

if fact_store.prerequisites_met(query):
    print("✓ Ready for lateral movement via stolen IAM token")
else:
    print("✗ Prerequisites not met")


========================================================================
ENDPOINT DEDUPLICATION: Reduce Redundant Scanning
========================================================================

# Before running XSS validation
endpoint = "/search.php?q=apple&sort=date"
vuln_type = "xss"

if engine.should_skip_endpoint(endpoint, vuln_type):
    print("Already tested XSS on /search.php?q={str} pattern - skipping")
else:
    # Run XSS validation
    result = xss_validator.run(state)
    
    # Mark pattern as scanned
    engine.mark_endpoint_pattern_scanned(endpoint, vuln_type)

# Get deduplication statistics
stats = endpoint_normalizer.get_pattern_stats()
print(f"Total patterns: {stats['total_patterns']}")
print(f"Deduplication ratio: {stats['deduplication_ratio']:.2%}")


========================================================================
HIGH-CONFIDENCE VALIDATION: Execution Proof vs Pattern Matching
========================================================================

# Low-confidence: Only regex match
low_conf = ValidationResult(
    success=True,
    confidence=0.6,
    confidence_score=0.6,  # Pattern match only
    severity="high",
    vulnerability="sqli",
    evidence=Evidence(
        request="GET /search.php?q=1 OR 1=1",
        response='<h1>Results: 5000</h1>',
        matched="5000",
    ),
    execution_proved=False,  # ← No actual code execution proven
)

# High-confidence: Execution proof (e.g., shell command output)
high_conf = ValidationResult(
    success=True,
    confidence=0.95,
    confidence_score=0.95,
    severity="critical",
    vulnerability="rce",
    evidence=Evidence(
        request="POST /upload.php",
        response="File uploaded",
        matched="uid=0",
    ),
    evidence_bundle=EvidenceBundle(
        raw_request="POST /shell.php\nid",
        raw_response="uid=0(root) gid=0(root)",
        matched_indicator="uid=0",
        execution_proof={"shell_output": "uid=0(root) gid=0(root)"},
        tool_logs=[{"tool": "shell", "output": "Command executed"}],
    ),
    execution_proved=True,  # ← Actual code execution proven!
    chain_source="upload_validator",
)

# Use confidence_score for automated decision-making
if high_conf.confidence_score >= 0.9 and high_conf.execution_proved:
    # Safely inject exploitation nodes
    print("✓ Exploit confirmed with execution proof - injecting chains")
else:
    # Require manual verification
    print("⚠ Low-confidence validation - manual review recommended")


========================================================================
DEBUGGING & MONITORING
========================================================================

# Export engine state for analysis
engine_state = dag_engine.get_engine_state()

print("=== Fact Store ===")
for category, facts in engine_state["fact_store"].items():
    print(f"{category}: {len(facts)} facts")

print("\n=== Active Chains ===")
for chain in attack_chain_manager.get_active_chains():
    print(f"- {chain.name}")

print("\n=== Endpoint Patterns ===")
patterns = engine_state["endpoint_patterns"]
print(f"Total patterns: {len(patterns)}")
for pattern_key, pattern in patterns.items():
    print(f"  {pattern['pattern']}: {len(pattern['original_endpoints'])} endpoints")

print("\n=== Chain Statistics ===")
stats = attack_chain_manager.get_chain_statistics()
for key, value in stats.items():
    print(f"{key}: {value}")


========================================================================
MIGRATION FROM OLD ENGINE
========================================================================

# Old way (still supported):
from brain.dag_engine import DAGBrain as DAGBrainOld

old_engine = DAGBrainOld()
plan = old_engine.plan_validations(state)
results = validation_engine_old.run(plan, state)

# New way (with chaining):
from brain.dag_engine_enhanced import DAGBrain

new_engine = DAGBrain(
    fact_store=FactStore(),
    endpoint_normalizer=EndpointNormalizer(),
)
plan = new_engine.plan_validations(state)
results = validation_engine.run(plan, state)

# Both work, but new engine provides chain injection capability


========================================================================
PRODUCTION CHECKLIST
========================================================================

□ Initialize FactStore as singleton (already done in __new__)
□ Thread-safe fact updates (use add_fact with locks)
□ Register all extraction rules before validation
□ Set up chain injection callbacks before validation
□ Monitor fact store growth (could impact memory)
□ Log all chain injections for audit trail
□ Verify confidence scores before exploitation
□ Store complete evidence bundles (for forensics)
□ Implement rate limiting for chain injections
□ Secure credential storage in fact store
□ Backup fact store state between runs
□ Clean up fact store after engagement (for reuse)

========================================================================
"""

# Quick reference table of classes

QUICK_REFERENCE = """
┌─────────────────────────────────────────────────────────────────────┐
│                    QUICK REFERENCE TABLE                            │
├─────────────────────────────────┬─────────────────────────────────────┤
│ Component                       │ Key Methods/Attributes              │
├─────────────────────────────────┼─────────────────────────────────────┤
│ FactStore                       │ add_fact(), get_fact(),            │
│                                 │ get_facts_by_category(),            │
│                                 │ prerequisites_met()                │
│                                 │                                     │
│ EndpointNormalizer              │ register_endpoint(),               │
│                                 │ should_skip_scan(),                │
│                                 │ get_pattern_stats()                │
│                                 │                                     │
│ AttackChainManager              │ validator_completed(),              │
│                                 │ get_pending_exploitation_nodes(),  │
│                                 │ register_chain_callback()          │
│                                 │                                     │
│ DAGBrain (Enhanced)             │ inject_exploitation_nodes(),       │
│                                 │ should_skip_endpoint(),            │
│                                 │ get_engine_state()                │
│                                 │                                     │
│ ValidationEngine (Enhanced)     │ run(),                             │
│                                 │ fact_store, endpoint_normalizer   │
│                                 │                                     │
│ ValidationResult                │ confidence_score,                  │
│                                 │ evidence_bundle,                   │
│                                 │ chain_source,                      │
│                                 │ execution_proved                   │
└─────────────────────────────────┴─────────────────────────────────────┘

Built-in Attack Chains:
  • Chain A: Port → Service → Creds → Auth Attack
  • Chain B: SSRF → Metadata → Token Theft
  • Chain C: XSS + CSRF → Session Hijacking
  • Chain D: LFI → Source Code → Credentials
  • Chain E: RCE → Shell → Privilege Escalation
"""

print(QUICK_REFERENCE)
