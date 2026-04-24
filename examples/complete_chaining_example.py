"""
Practical Integration Example: Complete Red-Teaming Pipeline with Expert Chaining

This file demonstrates a complete, end-to-end integration of the enhanced
engine components into a working red-teaming pipeline.

Run this to see the chain reactions in action!
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import asdict

# Import enhanced components
from brain.fact_store import FactStore, FactCategory
from brain.endpoint_normalizer import EndpointNormalizer
from brain.attack_chain_manager import AttackChainManager, ChainedExploitationNode
from brain.dag_engine_enhanced import DAGBrain
from engine.validation_engine_enhanced import ValidationEngine, StateManager
from engine.models import ExecutionContext, ValidationResult, Evidence, EvidenceBundle


class RedTeamingOrchestrator:
    """
    Complete red-teaming orchestrator that combines all enhanced components
    to create sophisticated multi-stage attack chains.
    """

    def __init__(self, target: str):
        self.target = target
        
        # Initialize shared components
        self.fact_store = FactStore()
        self.endpoint_normalizer = EndpointNormalizer()
        self.attack_chain_manager = AttackChainManager(self.fact_store)
        
        # Initialize engines
        self.dag_engine = DAGBrain(
            fact_store=self.fact_store,
            endpoint_normalizer=self.endpoint_normalizer,
        )
        self.validation_engine = ValidationEngine(
            fact_store=self.fact_store,
            endpoint_normalizer=self.endpoint_normalizer,
            attack_chain_manager=self.attack_chain_manager,
        )
        self.state_manager = StateManager(fact_store=self.fact_store)
        
        # Track injected nodes for queuing
        self.injected_nodes: List[ChainedExploitationNode] = []
        
        # Register chain injection callback
        self.dag_engine.register_chain_injection_callback(
            self._on_chain_injection
        )

    def _on_chain_injection(self, node: ChainedExploitationNode) -> None:
        """Callback invoked when an exploitation node is injected."""
        print(f"\n[⚡ CHAIN REACTION] Injecting exploitation node:")
        print(f"  Type: {node.exploit_type}")
        print(f"  Target: {node.target}")
        print(f"  Description: {node.description}")
        self.injected_nodes.append(node)

    def stage_1_reconnaissance(self) -> Dict[str, Any]:
        """
        Stage 1: Reconnaissance - Discover services, endpoints, etc.
        """
        print("\n" + "="*70)
        print("STAGE 1: RECONNAISSANCE")
        print("="*70)
        
        state = {
            "target": self.target,
            "endpoints": [
                "/login.php",
                "/admin/index.php?page=users",
                "/upload.php?id=1",
                "/search.php?q=test",
                "/api/export?format=json",
            ],
            "protocols": ["http", "https"],
            "ports": [80, 443, 27017],
        }
        
        print(f"Target: {self.target}")
        print(f"Endpoints: {len(state['endpoints'])}")
        print(f"Ports: {state['ports']}")
        
        return state

    def stage_2_service_discovery(self, state: Dict[str, Any]) -> None:
        """
        Stage 2: Service Discovery - Identify running services and versions.
        """
        print("\n" + "="*70)
        print("STAGE 2: SERVICE DISCOVERY")
        print("="*70)
        
        # Simulate service discovery results
        services = [
            {
                "validator_id": "service_discovery",
                "success": True,
                "vulnerability": "service_detected",
                "target": f"{self.target}:80",
                "evidence": {
                    "response": {
                        "server": "Apache/2.4.41",
                        "version": "2.4.41"
                    }
                }
            },
            {
                "validator_id": "port_discovery",
                "success": True,
                "vulnerability": "open_port_mongodb",
                "target": f"{self.target}:27017",
                "evidence": {
                    "response": {
                        "status": "open",
                        "service": "mongodb"
                    }
                }
            }
        ]
        
        for service_result in services:
            self.validation_engine.result_processor.extract_facts_from_result(
                service_result
            )
            print(f"✓ Detected: {service_result['evidence']['response'].get('server')}")

    def stage_3_vulnerability_scanning(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Stage 3: Vulnerability Scanning - Find exploitable conditions.
        """
        print("\n" + "="*70)
        print("STAGE 3: VULNERABILITY SCANNING")
        print("="*70)
        
        # Plan validations using enhanced DAG engine
        plan = self.dag_engine.plan_validations(state)
        print(f"Planning validations...")
        print(f"  Total validators: {len(plan.validators)}")
        print(f"  Ordered nodes: {len(plan.ordered_nodes)}")
        
        # Simulate validation results with various vulnerabilities
        simulated_results = [
            {
                "validator_id": "lfi_validator",
                "success": True,
                "vulnerability": "path_traversal_lfi",
                "severity": "high",
                "confidence_score": 0.96,
                "execution_proved": True,
                "evidence": {
                    "request": "/page.php?file=../../../etc/passwd",
                    "response": "root:x:0:0:root:/root:/bin/bash",
                    "matched": "root:/bin/bash"
                },
                "evidence_bundle": {
                    "raw_request": "GET /page.php?file=../../../etc/passwd",
                    "raw_response": "root:x:0:0:root:/root:/bin/bash",
                    "matched_indicator": "root:/bin/bash",
                    "execution_proof": {"file_read": True}
                }
            },
            {
                "validator_id": "ssrf_validator",
                "success": True,
                "vulnerability": "ssrf_blind",
                "severity": "high",
                "confidence_score": 0.92,
                "evidence": {
                    "request": "POST /api/export?url=http://localhost",
                    "response": "timeout_detected",
                    "matched": "time_based_delay"
                }
            },
            {
                "validator_id": "xss_validator",
                "success": True,
                "vulnerability": "reflected_xss",
                "severity": "medium",
                "confidence_score": 0.85,
                "evidence": {
                    "request": "/search.php?q=<script>alert('xss')</script>",
                    "response": "<script>alert('xss')</script> in results",
                    "matched": "<script>alert"
                }
            }
        ]
        
        # Process results through enhanced validation engine
        for result in simulated_results:
            # Process through result processor (extract facts, trigger chains)
            processed = self.validation_engine.result_processor.process_result(result)
            
            print(f"✓ {processed['vulnerability']}")
            print(f"  Confidence: {processed['validation'].get('confidence_score', 0):.2f}")
            print(f"  Execution proved: {processed['validation'].get('execution_proved', False)}")
            
            # Check for injected nodes
            injected = processed.get("injected_nodes", [])
            if injected:
                print(f"  → {len(injected)} exploitation node(s) injected!")
        
        self.state_manager.update(state, simulated_results)
        return simulated_results

    def stage_4_chain_exploitation(self) -> None:
        """
        Stage 4: Chain Exploitation - Execute multi-stage attack chains.
        """
        print("\n" + "="*70)
        print("STAGE 4: CHAIN EXPLOITATION")
        print("="*70)
        
        # Get pending exploitation nodes from chains
        pending_nodes = self.attack_chain_manager.get_pending_exploitation_nodes()
        print(f"Pending exploitation nodes: {len(pending_nodes)}")
        
        for node in pending_nodes:
            print(f"\n→ Exploiting: {node.exploit_type}")
            print(f"  Target: {node.target}")
            print(f"  Payload: {node.payload}")

    def stage_5_privilege_escalation(self) -> None:
        """
        Stage 5: Privilege Escalation - Escalate compromised access.
        """
        print("\n" + "="*70)
        print("STAGE 5: PRIVILEGE ESCALATION")
        print("="*70)
        
        facts = self.fact_store.get_facts_by_category(FactCategory.EXPLOITATION_ARTIFACT)
        if facts:
            print(f"Available exploitation artifacts: {len(facts)}")
            for artifact in facts:
                print(f"  - {artifact.value.get('type')}: {artifact.key}")

    def stage_6_lateral_movement(self) -> None:
        """
        Stage 6: Lateral Movement - Move through network.
        """
        print("\n" + "="*70)
        print("STAGE 6: LATERAL MOVEMENT")
        print("="*70)
        
        internal_hosts = self.fact_store.get_facts_by_category(
            FactCategory.INTERNAL_HOST
        )
        if internal_hosts:
            print(f"Discovered internal hosts: {len(internal_hosts)}")
            for host in internal_hosts:
                print(f"  - {host.key}: {host.value}")

    def print_summary(self) -> None:
        """
        Print comprehensive summary of all discoveries and chains.
        """
        print("\n" + "="*70)
        print("ENGAGEMENT SUMMARY")
        print("="*70)
        
        # Fact store summary
        print("\n[FACT STORE]")
        summary = self.fact_store.get_summary()
        for category, count in summary.items():
            print(f"  {category}: {count}")
        
        # Endpoint deduplication
        print("\n[ENDPOINT DEDUPLICATION]")
        stats = self.endpoint_normalizer.get_pattern_stats()
        print(f"  Total patterns: {stats['total_patterns']}")
        print(f"  Scanned patterns: {stats['scanned_patterns']}")
        print(f"  Total endpoints: {stats['total_endpoints']}")
        print(f"  Deduplication ratio: {stats['deduplication_ratio']:.1%}")
        
        # Chain management
        print("\n[ATTACK CHAINS]")
        chain_stats = self.attack_chain_manager.get_chain_statistics()
        for key, value in chain_stats.items():
            print(f"  {key}: {value}")
        
        # Detailed facts
        print("\n[DISCOVERED CREDENTIALS]")
        creds = self.fact_store.get_facts_by_category(FactCategory.CREDENTIAL)
        for cred in creds:
            print(f"  - {cred.key} (confidence: {cred.confidence})")
        
        print("\n[CONFIRMED VULNERABILITIES]")
        vulns = self.fact_store.get_facts_by_category(
            FactCategory.CONFIRMED_VULNERABILITY
        )
        for vuln in vulns:
            print(f"  - {vuln.value['type']} on {vuln.value['target']}")
        
        print("\n[EXPLOITATION ARTIFACTS]")
        artifacts = self.fact_store.get_facts_by_category(
            FactCategory.EXPLOITATION_ARTIFACT
        )
        for artifact in artifacts:
            print(f"  - {artifact.value['type']}: {artifact.key}")

    def export_results(self, filename: str = "engagement_results.json") -> None:
        """
        Export complete engagement results to JSON.
        """
        results = {
            "target": self.target,
            "fact_store": self.fact_store.export(),
            "endpoint_patterns": self.endpoint_normalizer.export(),
            "chain_statistics": self.attack_chain_manager.get_chain_statistics(),
            "injected_nodes": [node.to_dict() for node in self.injected_nodes],
        }
        
        with open(filename, "w") as f:
            json.dump(results, f, indent=2)
        
        print(f"\n✓ Results exported to {filename}")

    def run_complete_engagement(self) -> None:
        """
        Execute complete red-teaming engagement with all stages.
        """
        print("\n" + "#"*70)
        print("# EXPERT-LEVEL RED-TEAMING PIPELINE - COMPLETE ENGAGEMENT")
        print("#"*70)
        
        # Stage 1: Reconnaissance
        state = self.stage_1_reconnaissance()
        
        # Stage 2: Service Discovery
        self.stage_2_service_discovery(state)
        
        # Stage 3: Vulnerability Scanning
        self.stage_3_vulnerability_scanning(state)
        
        # Stage 4: Chain Exploitation
        self.stage_4_chain_exploitation()
        
        # Stage 5: Privilege Escalation
        self.stage_5_privilege_escalation()
        
        # Stage 6: Lateral Movement
        self.stage_6_lateral_movement()
        
        # Summary
        self.print_summary()
        
        # Export results
        self.export_results()


def main():
    """Run complete integration example."""
    
    # Create orchestrator
    orchestrator = RedTeamingOrchestrator("altoro.testfire.net")
    
    # Run engagement
    orchestrator.run_complete_engagement()


if __name__ == "__main__":
    main()
