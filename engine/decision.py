def decide_actions(data):
    actions = []

    def add_action(action, endpoint):
        if not endpoint:
            return
        if not isinstance(endpoint, str):
            return
        if not endpoint.startswith("http://") and not endpoint.startswith("https://"):
            return
        if any(a.get("endpoint") == endpoint and a.get("action") == action for a in actions):
            return
        actions.append({"action": action, "endpoint": endpoint})

    # 1) Actions derived from normalized findings
    for finding in data.get("findings", []) or []:
        if not isinstance(finding, dict):
            continue

        title = (finding.get("title") or "").lower()
        tags = finding.get("tags") or []
        tags_l = [t.lower() for t in tags if isinstance(t, str)]

        evidence = finding.get("evidence") or {}
        endpoint = ""
        if isinstance(evidence, dict):
            endpoint = evidence.get("matched_url") or ""

        # Some findings may point to non-HTTP services (e.g., host:6379)
        if "xss" in title or "xss" in tags_l:
            add_action("test_xss", endpoint)
        if "sql" in title or "sqli" in title or "sql" in tags_l or "sqli" in tags_l:
            add_action("test_sqli", endpoint)

    # 2) Actions derived from discovered endpoints (gospider)
    for asset in data.get("assets", []) or []:
        if not isinstance(asset, dict):
            continue
        for endpoint in asset.get("endpoints", []) or []:
            if not isinstance(endpoint, str) or "?" not in endpoint:
                continue
            add_action("test_sqli", endpoint)
            add_action("test_xss", endpoint)

    return actions
