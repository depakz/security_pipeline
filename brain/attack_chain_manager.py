"""
Attack Chain Manager: Intelligent exploitation scenarios based on discovered vulnerabilities.

This module implements sophisticated attack chains that automatically trigger
when prerequisites are met. It enables expert-level attack sequencing like:

Chain A: Open Port → Unauth Service → Credential Leak → Authenticated Attack
Chain B: SSRF → Internal Metadata Service → IAM Token Theft
Chain C: XSS + CSRF → Session Hijacking
Chain D: LFI → Source Code Disclosure → Hardcoded Credentials
Chain E: RCE → Reverse Shell → Internal Network Pivoting
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from enum import Enum

from brain.fact_store import FactStore, FactCategory, Fact, PrerequisiteQuery


class ChainTriggerCondition(Enum):
    """When to trigger a chain exploitation node."""
    IMMEDIATE = "immediate"  # Trigger as soon as parent succeeds
    ON_CREDENTIALS = "on_credentials"  # Only if credentials discovered
    ON_INTERNAL_HOST = "on_internal_host"  # Only if internal host discovered
    ON_SESSION = "on_session"  # Only if active session established
    ON_ARTIFACT = "on_artifact"  # Only if exploitation artifact found


@dataclass
class ChainedExploitationNode:
    """
    Represents an exploitation node dynamically injected into DAG after
    a successful validation reveals new attack opportunities.
    """
    node_id: str  # Unique identifier for this exploitation node
    parent_validator_id: str  # Which validator success triggered this
    exploit_type: str  # e.g., "auth_bypass", "rce", "data_exfiltration"
    target: str  # What to attack (hostname, URL, session ID, etc.)
    payload: Dict[str, Any]  # Parameters for the exploitation attempt
    trigger_condition: ChainTriggerCondition = ChainTriggerCondition.IMMEDIATE
    prerequisites: Optional[PrerequisiteQuery] = None
    description: str = ""
    expected_artifact: Optional[str] = None  # If successful, what fact to expect

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "parent_validator_id": self.parent_validator_id,
            "exploit_type": self.exploit_type,
            "target": self.target,
            "payload": self.payload,
            "trigger_condition": self.trigger_condition.value,
            "description": self.description,
            "expected_artifact": self.expected_artifact,
        }


@dataclass
class AttackChain:
    """
    Definition of a complete attack chain with trigger logic.
    """
    chain_id: str
    name: str  # e.g., "Credential Leak to Auth Bypass"
    description: str
    trigger_sequence: List[str]  # Ordered list of validator IDs that must succeed
    exploitation_nodes: List[ChainedExploitationNode] = field(default_factory=list)
    enabled: bool = True

    def can_trigger(
        self,
        completed_validators: List[str],
        fact_store: FactStore,
    ) -> bool:
        """Check if prerequisites for this chain are met."""
        if not self.enabled:
            return False

        for required_validator in self.trigger_sequence:
            if required_validator not in completed_validators:
                return False

        # All validators in sequence have completed
        return True

    def get_exploitation_nodes(self, fact_store: FactStore) -> List[ChainedExploitationNode]:
        """Get exploitation nodes that should be added, filtered by prerequisites."""
        nodes = []
        for node in self.exploitation_nodes:
            if node.prerequisites is None:
                nodes.append(node)
            elif fact_store.prerequisites_met(node.prerequisites):
                nodes.append(node)
        return nodes


class AttackChainManager:
    """
    Manages attack chain definitions and determines when to inject
    exploitation nodes into the DAG.
    """

    def __init__(self, fact_store: FactStore):
        self.fact_store = fact_store
        self.chains: Dict[str, AttackChain] = {}
        self.completed_validators: List[str] = []
        self.injection_callbacks: List[Callable[[ChainedExploitationNode], None]] = []
        self._initialize_default_chains()

    def _initialize_default_chains(self) -> None:
        """Initialize built-in attack chains."""
        # Chain A: Open Port → Unauth Service → Credential Leak → Auth Attack
        chain_a = AttackChain(
            chain_id="chain_a_credential_escalation",
            name="Port Discovery to Credential-Based Attack",
            description=(
                "Exploit open ports → unauth service access → credential discovery → "
                "authenticated attack execution"
            ),
            trigger_sequence=[
                "port_discovery",
                "unauth_service_validator",
                "cred_leak_validator",
            ],
            exploitation_nodes=[
                ChainedExploitationNode(
                    node_id="auth_bypass_rce",
                    parent_validator_id="cred_leak_validator",
                    exploit_type="authenticated_rce",
                    target="{discovered_service}",
                    payload={
                        "use_discovered_creds": True,
                        "payload_type": "reverse_shell",
                    },
                    description="Execute RCE using discovered credentials",
                    expected_artifact="shell_access",
                )
            ],
        )
        self.chains["chain_a"] = chain_a

        # Chain B: SSRF → Internal Metadata → Token Theft
        chain_b = AttackChain(
            chain_id="chain_b_ssrf_to_metadata",
            name="SSRF to Internal Metadata Access",
            description="Exploit SSRF → access internal metadata service → steal IAM tokens",
            trigger_sequence=["ssrf_validator"],
            exploitation_nodes=[
                ChainedExploitationNode(
                    node_id="metadata_access",
                    parent_validator_id="ssrf_validator",
                    exploit_type="metadata_exfiltration",
                    target="http://169.254.169.254/latest/meta-data/",
                    payload={
                        "use_ssrf_gadget": True,
                        "target_endpoint": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    },
                    description="Access internal metadata service via SSRF",
                    expected_artifact="iam_token",
                ),
                ChainedExploitationNode(
                    node_id="token_exfiltration",
                    parent_validator_id="ssrf_validator",
                    exploit_type="credential_theft",
                    target="metadata_service",
                    payload={
                        "credential_type": "iam_token",
                        "exfiltration_method": "dns_exfil",
                    },
                    prerequisites=PrerequisiteQuery(
                        required_facts={
                            FactCategory.EXPLOITATION_ARTIFACT: ["iam_token"]
                        },
                        min_confidence=0.8,
                    ),
                    description="Exfiltrate IAM token from metadata service",
                    expected_artifact="exfiltrated_credentials",
                ),
            ],
        )
        self.chains["chain_b"] = chain_b

        # Chain C: XSS + CSRF → Session Hijacking
        chain_c = AttackChain(
            chain_id="chain_c_xss_csrf_session",
            name="XSS+CSRF to Session Hijacking",
            description="Combine XSS and CSRF to hijack user sessions",
            trigger_sequence=["xss_validator", "csrf_validator"],
            exploitation_nodes=[
                ChainedExploitationNode(
                    node_id="session_cookie_extraction",
                    parent_validator_id="xss_validator",
                    exploit_type="cookie_theft",
                    target="victim_browser",
                    payload={
                        "payload_injection": "js_cookie_stealer",
                        "exfiltration_endpoint": "{attacker_callback}",
                    },
                    description="Inject XSS payload to steal session cookies",
                    expected_artifact="stolen_session_cookie",
                ),
            ],
        )
        self.chains["chain_c"] = chain_c

        # Chain D: LFI → Source Code → Hardcoded Credentials
        chain_d = AttackChain(
            chain_id="chain_d_lfi_source_creds",
            name="LFI to Source Code to Credentials",
            description="Exploit LFI to read source code, extract hardcoded credentials",
            trigger_sequence=["lfi_validator"],
            exploitation_nodes=[
                ChainedExploitationNode(
                    node_id="source_code_extraction",
                    parent_validator_id="lfi_validator",
                    exploit_type="information_disclosure",
                    target="application_source",
                    payload={
                        "lfi_gadget": "../../../",
                        "target_files": [
                            "config.php",
                            ".env",
                            "database.yml",
                            "secrets.json",
                        ],
                    },
                    description="Extract configuration files containing credentials",
                    expected_artifact="hardcoded_credentials",
                ),
            ],
        )
        self.chains["chain_d"] = chain_d

        # Chain E: RCE → Reverse Shell → Privilege Escalation
        chain_e = AttackChain(
            chain_id="chain_e_rce_to_privesc",
            name="RCE to Reverse Shell to Privilege Escalation",
            description="Establish RCE → spawn reverse shell → escalate privileges",
            trigger_sequence=["rce_validator"],
            exploitation_nodes=[
                ChainedExploitationNode(
                    node_id="reverse_shell",
                    parent_validator_id="rce_validator",
                    exploit_type="shell_access",
                    target="vulnerable_service",
                    payload={
                        "payload_type": "reverse_bash",
                        "attacker_host": "{attacker_ip}",
                        "attacker_port": "{attacker_port}",
                    },
                    description="Establish reverse shell from compromised service",
                    expected_artifact="shell_session",
                ),
                ChainedExploitationNode(
                    node_id="privilege_escalation",
                    parent_validator_id="rce_validator",
                    exploit_type="privesc",
                    target="compromised_system",
                    payload={
                        "escalation_vector": "sudo_misconfiguration",
                        "target_binary": "/bin/bash",
                    },
                    prerequisites=PrerequisiteQuery(
                        required_facts={
                            FactCategory.EXPLOITATION_ARTIFACT: ["shell_session"]
                        }
                    ),
                    description="Escalate privileges via sudo misconfiguration",
                    expected_artifact="root_access",
                ),
            ],
        )
        self.chains["chain_e"] = chain_e

    def register_chain_callback(self, callback: Callable[[ChainedExploitationNode], None]) -> None:
        """
        Register a callback to be invoked when exploitation nodes should be injected.

        Callback signature: callback(node: ChainedExploitationNode) -> None

        Args:
            callback: Function to invoke with ChainedExploitationNode
        """
        self.injection_callbacks.append(callback)

    def validator_completed(self, validator_id: str) -> None:
        """
        Notify manager that a validator has completed successfully.

        Triggers evaluation of attack chains.

        Args:
            validator_id: ID of the validator that succeeded
        """
        if validator_id not in self.completed_validators:
            self.completed_validators.append(validator_id)

        # Check which chains are now triggered
        self._evaluate_chains()

    def _evaluate_chains(self) -> None:
        """Evaluate all chains to see if exploitation nodes should be injected."""
        for chain in self.chains.values():
            if chain.can_trigger(self.completed_validators, self.fact_store):
                # Get exploitation nodes for this chain
                exploitation_nodes = chain.get_exploitation_nodes(self.fact_store)

                # Inject each node via callbacks
                for node in exploitation_nodes:
                    for callback in self.injection_callbacks:
                        try:
                            callback(node)
                        except Exception as e:
                            print(f"Error invoking injection callback: {e}")

    def enable_chain(self, chain_id: str) -> None:
        """Enable a specific attack chain."""
        if chain_id in self.chains:
            self.chains[chain_id].enabled = True

    def disable_chain(self, chain_id: str) -> None:
        """Disable a specific attack chain."""
        if chain_id in self.chains:
            self.chains[chain_id].enabled = False

    def get_active_chains(self) -> List[AttackChain]:
        """Get currently active chains (can be triggered)."""
        active = []
        for chain in self.chains.values():
            if chain.can_trigger(self.completed_validators, self.fact_store):
                active.append(chain)
        return active

    def get_pending_exploitation_nodes(self) -> List[ChainedExploitationNode]:
        """Get all exploitation nodes that should be injected."""
        nodes = []
        for chain in self.chains.values():
            if chain.can_trigger(self.completed_validators, self.fact_store):
                nodes.extend(chain.get_exploitation_nodes(self.fact_store))
        return nodes

    def get_chain_statistics(self) -> Dict[str, Any]:
        """Get statistics about registered chains."""
        return {
            "total_chains": len(self.chains),
            "enabled_chains": sum(1 for c in self.chains.values() if c.enabled),
            "triggered_chains": len(self.get_active_chains()),
            "completed_validators": len(self.completed_validators),
            "pending_exploitation_nodes": len(self.get_pending_exploitation_nodes()),
        }

    def export_chains(self) -> Dict[str, Dict[str, Any]]:
        """Export all chains as serializable structure."""
        return {
            chain_id: {
                "name": chain.name,
                "description": chain.description,
                "trigger_sequence": chain.trigger_sequence,
                "enabled": chain.enabled,
                "exploitation_nodes": [
                    node.to_dict() for node in chain.exploitation_nodes
                ],
            }
            for chain_id, chain in self.chains.items()
        }
