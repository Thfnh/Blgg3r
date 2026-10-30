import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path


def save_report(target, crawl_results, findings, output_dir="reports"):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_host = "".join(c if c.isalnum() or c in ".-_" else "_" for c in target)[:80]
    data = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "scan_mode": "passive",
        "summary": {
            "pages_visited": len(crawl_results["visited_urls"]),
            "urls_discovered": len(crawl_results["urls"]),
            "parameters": len(crawl_results["parameters"]),
            "forms": len(crawl_results["forms"]),
            "findings": len(findings),
        },
        "crawl": {
            "urls": crawl_results["urls"],
            "visited_urls": crawl_results["visited_urls"],
            "parameters": crawl_results["parameters"],
            "forms": crawl_results["forms"],
        },
        "findings": findings,
    }
    json_path = out / f"{safe_host}_{stamp}.json"
    html_path = out / f"{safe_host}_{stamp}.html"
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    rows = []
    for item in findings:
        rows.append(
            "<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>".format(
                escape(item["severity"]), escape(item["type"]), escape(item["url"]),
                escape(item["evidence"]), escape(item["recommendation"])
            )
        )
    html = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>WebVulnScanner Report</title>
<style>body{font:15px system-ui;max-width:1200px;margin:2rem auto;padding:0 1rem}
table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:.6rem;text-align:left;vertical-align:top}
th{background:#f4f4f4}code{overflow-wrap:anywhere} .note{padding:1rem;background:#fff8df}</style></head><body>
<h1>WebVulnScanner — Passive Report</h1>
<p><b>Target:</b> {target}</p>
<p><b>Pages visited:</b> {pages} · <b>URLs discovered:</b> {urls} · <b>Parameters:</b> {params} · <b>Forms:</b> {forms}</p>
<div class="note">Passive heuristic results are not proof of exploitability. Manually verify findings within the authorized scope.</div>
<h2>Findings ({count})</h2><table><thead><tr><th>Severity</th><th>Type</th><th>URL</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>""".format(
        target=escape(target), pages=len(crawl_results["visited_urls"]),
        urls=len(crawl_results["urls"]), params=len(crawl_results["parameters"]),
        forms=len(crawl_results["forms"]), count=len(findings), rows="".join(rows)
    )
    html_path.write_text(html, encoding="utf-8")
    return json_path, html_path
