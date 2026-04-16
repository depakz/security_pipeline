from __future__ import annotations

from ftplib import FTP, error_perm
from typing import Optional

from engine.models import Evidence, ExecutionContext, ValidationResult


class FTPAnonymousLoginValidator:
    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context

    def can_run(self, state):
        ports = state.get("ports", []) or []
        return 21 in ports

    def run(self, state):
        target = state.get("target")
        if not isinstance(target, str) or not target.strip():
            return None

        ftp = FTP()
        request = {"host": target, "port": 21, "user": "anonymous"}

        try:
            banner = ftp.connect(target, 21, timeout=5)
            login_response = ftp.login(user="anonymous", passwd="anonymous@")

            try:
                ftp.quit()
            except Exception:
                pass

            return ValidationResult(
                success=True,
                confidence=0.95,
                severity="high",
                vulnerability="ftp-anonymous-login",
                evidence=Evidence(
                    request=request,
                    response={
                        "banner": banner,
                        "login_response": login_response,
                    },
                    matched="anonymous",
                    extra={"port": 21},
                ),
                impact="Anonymous FTP login can allow unauthenticated access to files and may enable further compromise depending on permissions.",
                remediation="Disable anonymous FTP access or restrict it to a non-sensitive, read-only directory. Prefer SFTP/SSH with authenticated access.",
            )

        except error_perm as e:
            # Anonymous login rejected (expected secure behavior)
            return ValidationResult(
                success=False,
                confidence=0.9,
                severity="info",
                vulnerability="ftp-anonymous-login",
                evidence=Evidence(
                    request=request,
                    response=str(e),
                    extra={"port": 21},
                ),
            )

        except Exception as e:
            return ValidationResult(
                success=False,
                confidence=0.0,
                severity="info",
                vulnerability="ftp-connection-failed",
                evidence=Evidence(
                    request=request,
                    response=str(e),
                    extra={"port": 21},
                ),
            )

        finally:
            try:
                ftp.close()
            except Exception:
                pass
