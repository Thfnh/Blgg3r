import re
from urllib.parse import urlparse


SECURITY_HEADERS = {
    "content-security-policy": ("Medium", "Consider a Content-Security-Policy suited to the application."),
    "strict-transport-security": ("Medium", "For HTTPS sites, configure HSTS with an appropriate max-age."),
    "x-content-type-options": ("Low", "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": ("Low", "Set a Referrer-Policy appropriate to the application's privacy needs."),
    "permissions-policy": ("Info", "Consider restricting browser features with Permissions-Policy."),
}


def analyze(results):
    findings = []
    seen = set()

    def add(finding):
        key = (finding["type"], finding["url"], finding.get("evidence", ""))
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    for page in results["pages"]:
        url = page["url"]
        headers = {k.lower(): v for k, v in page["headers"].items()}
        host = urlparse(url).hostname or ""

        if urlparse(url).scheme == "https" and "strict-transport-security" not in headers:
            add({
                "type": "Missing Security Header",
                "severity": "Medium",
                "url": url,
                "evidence": "Strict-Transport-Security header is absent on an HTTPS response.",
                "recommendation": SECURITY_HEADERS["strict-transport-security"][1],
                "confidence": "High",
            })

        for header, (severity, recommendation) in SECURITY_HEADERS.items():
            if header in headers:
                continue
            if header == "strict-transport-security" and urlparse(url).scheme != "https":
                continue
            add({
                "type": "Missing Security Header",
                "severity": severity,
                "url": url,
                "evidence": f"{header} header is absent.",
                "recommendation": recommendation,
                "confidence": "High",
            })

        set_cookie = page["headers"].get("Set-Cookie", "")
        # requests combines some repeated header values; this is a best-effort passive check.
        if set_cookie:
            cookie_lower = set_cookie.lower()
            for flag, severity in (("httponly", "Low"), ("secure", "Low"), ("samesite", "Info")):
                if flag not in cookie_lower:
                    add({
                        "type": "Cookie Attribute Review",
                        "severity": severity,
                        "url": url,
                        "evidence": f"Set-Cookie response value may be missing {flag.capitalize()}.",
                        "recommendation": f"Review whether the cookie should include the {flag.capitalize()} attribute.",
                        "confidence": "Low",
                    })

        body = page.get("body", "")
        # Heuristic only: report possible disclosure indicators, not confirmed vulnerabilities.
        patterns = [
            (r"(?i)\b(?:traceback \(most recent call last\)|stack trace)\b", "Possible Debug Information", "Review whether detailed stack traces are exposed to unauthenticated users."),
            (r"(?i)\b(?:SQL syntax.*error|mysql_fetch|ORA-\d{5}|SQLSTATE\[)", "Possible Database Error Disclosure", "Avoid returning database errors to clients; log details server-side."),
            (r"(?i)\b(?:api[_ -]?key|secret[_ -]?key)\s*[:=]\s*['\"][^'\"]{8,}", "Possible Secret in HTML", "Verify the match manually; never embed private secrets in client-side code."),
        ]
        for pattern, title, recommendation in patterns:
            match = re.search(pattern, body)
            if match:
                add({
                    "type": title,
                    "severity": "Low",
                    "url": url,
                    "evidence": f"Heuristic matched text: {match.group(0)[:120]}",
                    "recommendation": recommendation,
                    "confidence": "Low",
                })

    return findings
