# OWASP Top 10 Coverage Matrix

This document defines how the validator layer maps to the OWASP Top 10 2021 categories.

The goal of this project is not just discovery, but **validation with proof**:
- discovery identifies candidates
- validators confirm the weakness
- proof collection records evidence, confidence, and execution artifacts
- attack chaining triggers the next step when prerequisites are met

## Status Legend

- **Full**: dedicated validator exists and can produce strong confirmation evidence
- **Partial**: validator exists, but proof is heuristic, limited, or environment-dependent
- **Proof-limited**: validator exists, but high-confidence confirmation usually needs internal access or OOB support
- **Missing**: no dedicated validator yet in the current codebase

## Coverage Matrix

| OWASP Category | Status | Current Modules | Proof Standard | Notes |
| --- | --- | --- | --- | --- |
| A01: Broken Access Control | Partial | `validators/idor.py` | Role/ownership mismatch, object access difference, authenticated response delta | Currently represented mainly by IDOR-style validation. This is narrower than the full A01 surface. |
| A02: Cryptographic Failures | Partial | `validators/crypto.py` | Weak TLS version acceptance, plaintext secret transport, cookie exposure over HTTP | Good for transport checks; does not prove data-at-rest encryption or server-side key management. |
| A03: Injection | Partial | `validators/injection.py`, `engine/executor.py`, `engine/decision.py` | Reflected payload execution, error-based evidence, timing delta, command output where safe | Dedicated A03 validation now exists for reflected XSS and SQL error signals; command injection remains a future expansion point. |
| A04: Insecure Design | Partial | `validators/insecure_design.py` | Workflow abuse, state transition bypass, business-rule violation | Dedicated A04 validation now exists for externally observable workflow/state-transition bypass checks. |
| A05: Security Misconfiguration | Partial | `validators/http.py`, `validators/logging.py` | Missing security headers, debug exposure, unsafe defaults, permissive responses | External evidence is good for hardening signals, but not all misconfigurations are externally provable. |
| A06: Vulnerable and Outdated Components | Partial | `brain/cve_mapper.py`, CVE-aware planning in `brain/dag_engine_enhanced.py` | Version match plus safe validator confirmation or exploitability proof | Strong for fingerprinting and routing; proof depends on target-specific validation. |
| A07: Identification and Authentication Failures | Partial | `validators/auth.py`, `validators/redis.py`, `validators/ftp.py` | Rate-limit absence, weak session/cookie flags, default credential acceptance | Good practical coverage, but brute-force/credential-stuffing remains intentionally constrained. |
| A08: Software and Data Integrity Failures | Partial | `validators/deserialization.py`, `validators/integrity.py` | Signature hit, timing probe, unsigned artifact evidence, OOB callback when available | One of the stronger areas, but some cases still need stronger execution proof. |
| A09: Security Logging and Monitoring Failures | Proof-limited | `validators/logging.py` | Passive hardening indicators only | External tooling cannot directly prove internal alerting or SOC visibility without telemetry access. |
| A10: Server-Side Request Forgery | Partial | `validators/ssrf.py`, chain engine | Loopback/internal fetch behavior, response error patterns, OOB callback for high confidence | Strong candidate validation exists, but proof is highest quality only with an OOB channel. |

## What “Proof” Means Here

Each validator should attach one or more of these proof signals:

- raw request or payload used for the probe
- raw response or response snippet
- timing delta for blind validation
- matched indicator or error signature
- execution evidence such as shell output, file content, or callback proof
- chain source showing which prior finding enabled the follow-up

## Practical Interpretation

This repository is best described as an **automated OWASP validator with proof collection**, not a scanner-only project.

The current design already supports:
- candidate discovery from scanners
- category-specific validation modules
- proof normalization through `brain/proof_collector.py`
- chained follow-up actions through `brain/attack_chain_manager.py`

The main remaining gaps are:
- stronger OOB-backed confirmation for A09 and A10
- deeper A02 verification for encryption-at-rest and server-side key handling

## Recommended Next Implementation Order

1. Add a unified A03 Injection validator that can route SQLi/XSS/command-injection proofs into the proof collector.
2. Add an A04 validator that models business workflows and state transitions.
3. Extend A10 with optional OOB proof hooks.
4. Expand A09 into a telemetry-aware mode when internal logs are available.
5. Add A02 checks for configuration artifacts and secret-handling hints where the environment permits.
