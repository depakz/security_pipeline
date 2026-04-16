from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from typing import Optional

from engine.models import Evidence, ExecutionContext, ValidationResult


class MissingSecurityHeadersValidator:
    def __init__(self, context: Optional[ExecutionContext] = None):
        self.context = context

    def can_run(self, state):
        protocols = state.get("protocols", []) or []
        return "http" in protocols

    def run(self, state):
        url = state.get("url")
        if not url:
            target = state.get("target", "")
            if target:
                url = "https://" + target
            else:
                return None

        try:
            req = Request(url, headers={"User-Agent": "security-pipeline-validator/1.0"})
            with urlopen(req, timeout=5) as r:
                headers = dict(r.headers.items())

            missing = []

            if "Content-Security-Policy" not in headers:
                missing.append("CSP")
            if "X-Frame-Options" not in headers:
                missing.append("X-Frame-Options")

            success = len(missing) > 0

            return ValidationResult(
                success=success,
                confidence=0.8 if success else 0.0,
                severity="info",
                vulnerability="missing-security-headers",
                evidence=Evidence(
                    request=url,
                    response=headers,
                    matched=",".join(missing),
                ),
                impact="Missing headers can increase exposure to clickjacking and some XSS scenarios.",
                remediation="Add standard security headers (at minimum CSP and X-Frame-Options) at the web server or application layer.",
            )

        except HTTPError as e:
            return ValidationResult(
                success=False,
                confidence=0.0,
                severity="info",
                vulnerability="http-request-failed",
                evidence=Evidence(
                    request=url,
                    response=str(e),
                ),
            )

        except URLError as e:
            return ValidationResult(
                success=False,
                confidence=0.0,
                severity="info",
                vulnerability="http-request-failed",
                evidence=Evidence(
                    request=url,
                    response=str(e),
                ),
            )

        except Exception as e:
            return ValidationResult(
                success=False,
                confidence=0.0,
                severity="info",
                vulnerability="http-request-failed",
                evidence=Evidence(
                    request=url,
                    response=str(e),
                ),
            )
