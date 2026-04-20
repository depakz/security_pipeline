import json
import re
import socket
from datetime import datetime, timezone
from hashlib import sha1
from urllib.parse import urlparse

from utils.normalizer import is_noise_url


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_TO_DEFAULT_CVSS = {
    "critical": 9.8,
    "high": 8.1,
    "medium": 6.5,
    "low": 3.1,
    "info": 0.0,
}

_DEFAULT_PORT_TO_SERVICE = {
    21: "ftp",
    80: "http",
    443: "https",
    6379: "redis",
}


def _now_utc_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[AGG ERROR] Failed reading {path}: {e}")
        return None


def _extract_target_host(target):
    if not target:
        return ""
    t = str(target).strip()
    if "://" in t:
        try:
            parsed = urlparse(t)
            return parsed.hostname or ""
        except Exception:
            return t.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    return t.split("/", 1)[0].split(":", 1)[0]


def _in_scope_hostname(hostname, target_host):
    if not hostname or not target_host:
        return False
    hostname = hostname.lower().strip(".")
    target_host = target_host.lower().strip(".")
    return hostname == target_host or hostname.endswith("." + target_host)


def _parse_port_from_match(matched_url):
    if not matched_url:
        return None, None

    s = str(matched_url).strip()
    if not s:
        return None, None

    # URL form
    if "://" in s:
        try:
            p = urlparse(s)
            hostname = p.hostname
            if p.port is not None:
                return hostname, int(p.port)
            if p.scheme == "https":
                return hostname, 443
            if p.scheme == "http":
                return hostname, 80
            return hostname, None
        except Exception:
            return None, None

    # host:port form
    m = re.match(r"^(?P<host>[^:]+):(?P<port>\d{1,5})$", s)
    if m:
        host = m.group("host")
        try:
            port = int(m.group("port"))
            return host, port
        except Exception:
            return host, None

    return s, None


def _normalize_severity(severity):
    s = (severity or "").strip().lower()
    if s in _SEVERITY_ORDER:
        return s
    return "info"


def _extract_cves(template, name, classification):
    cves = []

    if isinstance(classification, dict):
        raw = classification.get("cve-id")
        if isinstance(raw, str) and raw:
            raw = [raw]
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str) and item.upper().startswith("CVE-"):
                    cves.append(item.upper())

    # fallback: template-id/name often contains CVE-XXXX-YYYY
    haystack = " ".join([str(template or ""), str(name or "")])
    for m in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", haystack, flags=re.IGNORECASE):
        cves.append(m.upper())

    # unique, stable order
    deduped = []
    seen = set()
    for c in cves:
        if c not in seen:
            seen.add(c)
            deduped.append(c)
    return deduped


def _extract_cwe(classification):
    if not isinstance(classification, dict):
        return ""
    cwe_ids = classification.get("cwe-id")
    if isinstance(cwe_ids, list) and cwe_ids:
        return str(cwe_ids[0])
    if isinstance(cwe_ids, str) and cwe_ids:
        return cwe_ids
    return ""


def _extract_cvss_score(severity, classification, fallback_default=True):
    if isinstance(classification, dict):
        for key in ("cvss-score", "cvss_score", "cvssScore"):
            v = classification.get(key)
            try:
                if v is not None and v != "":
                    return float(v)
            except Exception:
                pass
    if not fallback_default:
        return None
    return float(_SEVERITY_TO_DEFAULT_CVSS.get(_normalize_severity(severity), 0.0))


def _infer_service(port, preferred=None):
    if preferred:
        return preferred
    if port is None:
        return ""
    return _DEFAULT_PORT_TO_SERVICE.get(int(port), "")


def _truncate(value, limit):
    if value is None:
        return ""
    s = str(value)
    if len(s) <= limit:
        return s
    return s[:limit] + "...(truncated)"


def _finding_defaults():
    return {
        "id": "",
        "title": "",
        "description": "",
        "severity": "info",
        "cvss_score": 0.0,
        "cwe": "",
        "cve": [],
        "asset": "",
        "port": None,
        "protocol": "",
        "evidence": {},
        "impact": "",
        "remediation": "",
        "references": [],
        "tags": [],
    }


def _lookup_remediation(template, cves, port, service):
    t = (template or "").lower()
    if "wordpress-eol" in t or "eol-" in t or t.startswith("eol"):
        return "Upgrade the affected platform to a supported (non-EOL) version and apply the latest security patches."
    if "nginx-version" in t:
        return "Avoid exposing precise server versions (e.g., disable server tokens) and keep Nginx updated with security patches."
    if "exposed-redis" in t or (service == "redis" and port == 6379):
        return (
            "Restrict Redis to trusted networks (firewall/VPC rules), bind to localhost or a private interface, "
            "and require authentication (ACLs). Disable dangerous commands if not needed."
        )
    if "redis-default-logins" in t:
        return "Remove default credentials, enforce strong passwords/ACLs, and restrict network exposure."
    if cves:
        return "Update the affected software to a patched version and verify the service is not exposed to untrusted networks."
    if "http-missing-security-headers" in t:
        return "Add recommended security headers (e.g., CSP, HSTS, X-Frame-Options/Frame-Options, X-Content-Type-Options) at the web server or application layer."
    if "missing-sri" in t:
        return "Add Subresource Integrity (SRI) hashes to externally loaded scripts/styles, or self-host critical third-party assets."
    return ""


def _lookup_impact(template, cves, port, service):
    t = (template or "").lower()
    if "wordpress-eol" in t or "eol-" in t or t.startswith("eol"):
        return "End-of-life software may contain unpatched vulnerabilities, increasing the likelihood and impact of exploitation."
    if "nginx-version" in t:
        return "Version disclosure can help attackers tailor exploits and reduce the cost of reconnaissance."
    if "exposed-redis" in t or (service == "redis" and port == 6379):
        return "Attackers may read/write database contents and potentially achieve remote code execution depending on configuration."
    if "redis-default-logins" in t:
        return "Attackers may authenticate using default credentials and gain full control of the service."
    if cves:
        return "A vulnerable service may be exploitable by remote attackers, depending on configuration and exposure."
    if "http-missing-security-headers" in t:
        return "Missing browser-side mitigations can increase the impact of XSS, clickjacking, and related attacks."
    if "missing-sri" in t:
        return "If a third-party asset is compromised, attackers can inject malicious code into users' browsers."
    return ""


def _normalize_nuclei_findings(target_host, nuclei_data):
    findings = []

    if not isinstance(nuclei_data, dict):
        return findings

    if nuclei_data.get("error"):
        print(f"[AGG ERROR] Nuclei error: {nuclei_data.get('error')}")
        return findings

    for v in nuclei_data.get("findings", []) or []:
        if not isinstance(v, dict):
            continue

        template = v.get("template", "")
        name = v.get("name", "") or template
        severity = _normalize_severity(v.get("severity"))
        matched_url = v.get("matched_url", "") or v.get("matched-at", "") or v.get("matched_at", "")

        classification = v.get("classification") or {}
        cves = _extract_cves(template, name, classification)
        cwe = v.get("cwe") or _extract_cwe(classification)
        cvss_score = _extract_cvss_score(severity, classification)

        matched_host, matched_port = _parse_port_from_match(matched_url)
        port = int(matched_port) if (matched_port is not None and _in_scope_hostname(matched_host, target_host)) else None
        protocol = "tcp" if port is not None else ""
        service = _infer_service(port)

        references = []
        refs = v.get("references") or v.get("reference") or v.get("references_url")
        if isinstance(refs, list):
            references.extend([r for r in refs if isinstance(r, str) and r.strip()])
        elif isinstance(refs, str) and refs.strip():
            references.append(refs.strip())

        # Always add authoritative CVE references when applicable
        for cve in cves:
            references.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}")

        evidence = {
            "source": "nuclei",
            "template": template,
            "name": name,
            "matched_url": matched_url,
            "type": v.get("type", ""),
        }

        for key, out_key, limit in [
            ("matcher-name", "matcher", 200),
            ("matcher_name", "matcher", 200),
            ("curl-command", "curl_command", 800),
            ("curl_command", "curl_command", 800),
            ("request", "request", 4000),
            ("response", "response", 4000),
        ]:
            if key in v and v.get(key):
                evidence[out_key] = _truncate(v.get(key), limit)

        extracted = v.get("extracted-results") or v.get("extracted_results")
        if extracted:
            evidence["extracted_results"] = extracted

        tags = []
        raw_tags = v.get("tags")
        if isinstance(raw_tags, list):
            tags.extend([t for t in raw_tags if isinstance(t, str)])
        elif isinstance(raw_tags, str) and raw_tags:
            tags.extend([t.strip() for t in raw_tags.split(",") if t.strip()])

        if service:
            tags.append(service)
        if template:
            tags.append(template)

        deduped_tags = []
        seen = set()
        for t in tags:
            key = t.strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            deduped_tags.append(t)

        finding = _finding_defaults()
        finding.update(
            {
                "title": name,
                "description": v.get("description", "") or "",
                "severity": severity,
                "cvss_score": cvss_score,
                "cwe": str(cwe) if cwe else "",
                "cve": cves,
                "asset": target_host,
                "port": port,
                "protocol": protocol,
                "evidence": evidence,
                "impact": v.get("impact", "") or _lookup_impact(template, cves, port, service),
                "remediation": v.get("remediation", "") or _lookup_remediation(template, cves, port, service),
                "references": references,
                "tags": deduped_tags,
            }
        )

        if not finding["description"]:
            finding["description"] = f"Nuclei finding '{template}' matched at '{matched_url}'."

        findings.append(finding)

    return findings


def _dedupe_findings(findings):
    deduped = {}
    for f in findings:
        template = (f.get("evidence") or {}).get("template", "")
        matched_url = (f.get("evidence") or {}).get("matched_url", "")
        asset = f.get("asset", "")
        port = f.get("port")

        key_str = "|".join(
            [
                str(template or "").lower(),
                str(matched_url or "").lower(),
                str(asset or "").lower(),
                str(port or ""),
                str(f.get("severity") or "").lower(),
            ]
        )
        fp = sha1(key_str.encode("utf-8", errors="ignore")).hexdigest()
        if fp not in deduped:
            deduped[fp] = f
        else:
            existing = deduped[fp]
            existing["references"] = list({*existing.get("references", []), *f.get("references", [])})
            existing["tags"] = list({*existing.get("tags", []), *f.get("tags", [])})
    return list(deduped.values())


def _collect_asset_ports(target_host, naabu_data, httpx_data, gospider_data, katana_data, gau_data, nuclei_data):
    ports = {}

    def add_port(port, service="", version="", protocol="tcp"):
        if port is None:
            return
        try:
            p = int(port)
        except Exception:
            return
        entry = ports.get(p) or {"port": p, "protocol": protocol, "service": "", "version": ""}
        if service and not entry.get("service"):
            entry["service"] = service
        if version and not entry.get("version"):
            entry["version"] = version
        ports[p] = entry

    if isinstance(naabu_data, dict):
        for p in naabu_data.get("open_ports", []) or []:
            if not isinstance(p, dict):
                continue
            add_port(p.get("port"), service=p.get("service") or "", version=p.get("version") or "")

    if isinstance(httpx_data, list):
        for item in httpx_data:
            if not isinstance(item, dict):
                continue
            url = item.get("url") or ""
            if not url:
                continue
            try:
                parsed = urlparse(url)
                if not _in_scope_hostname(parsed.hostname, target_host):
                    continue
                port = parsed.port
                if port is None:
                    port = 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
                service = "https" if parsed.scheme == "https" else "http" if parsed.scheme == "http" else ""
                add_port(port, service=service)
            except Exception:
                continue

    for crawler_data in (gospider_data, katana_data, gau_data):
        if not isinstance(crawler_data, dict):
            continue
        for url in crawler_data.get("endpoints", []) or []:
            if not isinstance(url, str) or not url:
                continue
            try:
                parsed = urlparse(url)
                if not _in_scope_hostname(parsed.hostname, target_host):
                    continue
                port = parsed.port
                if port is None:
                    port = 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
                service = "https" if parsed.scheme == "https" else "http" if parsed.scheme == "http" else ""
                add_port(port, service=service)
            except Exception:
                continue

    if isinstance(nuclei_data, dict):
        for v in nuclei_data.get("findings", []) or []:
            if not isinstance(v, dict):
                continue
            matched_url = v.get("matched_url", "") or v.get("matched-at", "") or v.get("matched_at", "")
            host, port = _parse_port_from_match(matched_url)
            if port is None:
                continue
            if not _in_scope_hostname(host, target_host):
                continue
            add_port(port, service=_infer_service(port))

    for p, entry in list(ports.items()):
        if not entry.get("service"):
            entry["service"] = _infer_service(p)
            ports[p] = entry

    return [ports[p] for p in sorted(ports.keys())]


def _collect_asset_technologies(httpx_data):
    tech = {}

    def add(value):
        if not value:
            return
        s = str(value).strip()
        if not s:
            return
        key = s.lower()
        tech.setdefault(key, s)

    if isinstance(httpx_data, list):
        for item in httpx_data:
            if not isinstance(item, dict):
                continue
            add(item.get("webserver"))
            for t in item.get("tech", []) or []:
                add(t)

    return [tech[k] for k in sorted(tech.keys())]


def _collect_asset_endpoints(target_host, gospider_data, katana_data, gau_data):
    endpoints = []
    seen = set()

    for crawler_data in (gospider_data, katana_data, gau_data):
        if not isinstance(crawler_data, dict):
            continue

        for url in crawler_data.get("endpoints", []) or []:
            if not isinstance(url, str) or not url:
                continue

            if is_noise_url(url):
                continue

            try:
                parsed = urlparse(url)
                if not _in_scope_hostname(parsed.hostname, target_host):
                    continue
            except Exception:
                continue

            if url not in seen:
                seen.add(url)
                endpoints.append(url)
    return sorted(endpoints)


def _extract_ip_from_httpx(httpx_data, target_host):
    if not isinstance(httpx_data, list) or not target_host:
        return ""
    for item in httpx_data:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str) or not url:
            continue
        try:
            parsed = urlparse(url)
            if not _in_scope_hostname(parsed.hostname, target_host):
                continue
        except Exception:
            continue
        ip = item.get("ip")
        if isinstance(ip, str) and ip.strip():
            return ip.strip()
    return ""


def _resolve_ip(host, httpx_data=None):
    if not host:
        return ""
    try:
        ip = socket.gethostbyname(host)
        if ip:
            return ip
    except Exception:
        pass
    return _extract_ip_from_httpx(httpx_data, host)


def _compute_summary(findings):
    counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        sev = _normalize_severity(f.get("severity"))
        counts[sev] = counts.get(sev, 0) + 1

    scores = []
    for f in findings:
        try:
            scores.append(float(f.get("cvss_score", 0.0)))
        except Exception:
            continue

    scores = sorted([s for s in scores if s > 0.0], reverse=True)
    if not scores:
        risk_score = 0.0
    else:
        top = scores[:5]
        risk_score = round(sum(top) / len(top), 1)

    return {
        "total_findings": len(findings),
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "risk_score": risk_score,
    }


def parse_all(target, scan_time=None, scanner="ReconX", profile="full_scan", duration_seconds=0):
    target_host = _extract_target_host(target)

    naabu_data = _safe_load_json("output/naabu.json")
    httpx_data = _safe_load_json("output/httpx.json")
    gospider_data = _safe_load_json("output/gospider.json")
    katana_data = _safe_load_json("output/katana.json")
    gau_data = _safe_load_json("output/gau.json")
    nuclei_data = _safe_load_json("output/nuclei.json")

    scan_info = {
        "target": target_host or str(target),
        "scan_time": scan_time or _now_utc_iso(),
        "scanner": scanner,
        "profile": profile,
        "duration_seconds": int(duration_seconds or 0),
    }

    asset = {
        "host": target_host,
        "ip": _resolve_ip(target_host, httpx_data=httpx_data),
        "ports": _collect_asset_ports(target_host, naabu_data, httpx_data, gospider_data, katana_data, gau_data, nuclei_data),
        "technologies": _collect_asset_technologies(httpx_data),
        "endpoints": _collect_asset_endpoints(target_host, gospider_data, katana_data, gau_data),
    }

    findings = []
    findings.extend(_normalize_nuclei_findings(target_host, nuclei_data))
    findings = _dedupe_findings(findings)

    severity_rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    findings.sort(
        key=lambda f: (
            severity_rank.get(_normalize_severity(f.get("severity")), len(_SEVERITY_ORDER)),
            (f.get("title") or "").lower(),
        )
    )

    for idx, f in enumerate(findings, start=1):
        f["id"] = f"VULN-{idx:03d}"

    summary = _compute_summary(findings)

    return {
        "scan_info": scan_info,
        "assets": [asset] if target_host else [],
        "findings": findings,
        "summary": summary,
    }
