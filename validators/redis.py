import socket
from typing import Optional

from engine.models import Evidence, ExecutionContext, ValidationResult


class RedisNoAuthValidator:
    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context

    def can_run(self, state):
        ports = state.get("ports", []) or []
        return 6379 in ports

    def run(self, state):
        target = state.get("target")
        if not target:
            return None

        s = socket.socket()
        s.settimeout(3)

        try:
            s.connect((target, 6379))
            s.send(b"PING\r\n")
            response = s.recv(1024).decode(errors="ignore")

            success = "PONG" in response

            evidence = Evidence(
                request="PING",
                response=response,
                matched="PONG" if success else "",
                extra={"port": 6379},
            )

            return ValidationResult(
                success=success,
                confidence=0.95 if success else 0.0,
                severity="high",
                vulnerability="redis-no-auth",
                evidence=evidence,
                impact="Unauthenticated Redis access allows data exposure.",
                remediation="Enable authentication (ACLs/requirepass) and restrict Redis to an internal network (firewall/VPC rules).",
            )

        except Exception as e:
            return ValidationResult(
                success=False,
                confidence=0.0,
                severity="info",
                vulnerability="redis-connection-failed",
                evidence=Evidence(
                    request="PING",
                    response=str(e),
                    extra={"port": 6379},
                ),
            )

        finally:
            try:
                s.close()
            except Exception:
                pass
