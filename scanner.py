import argparse
import sys
from urllib.parse import urlparse

from config import MAX_PAGES
from crawler import Crawler
from http_client import HTTPClient, ScopeError, normalize_host
from passive_scan import analyze
from report import save_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="Authorized, passive web inventory and security-header scanner."
    )
    parser.add_argument("url", help="Target URL, e.g. https://staging.example.com")
    parser.add_argument("--scope-host", action="append", default=[],
                        help="Additional authorized hostname/domain. Repeat as needed.")
    parser.add_argument("--max-pages", type=int, default=MAX_PAGES,
                        help=f"Maximum pages to visit (default: {MAX_PAGES}).")
    parser.add_argument("--cookie-file", help="JSON cookie file for an authorized test session.")
    parser.add_argument("--allow-private", action="store_true",
                        help="Allow private/loopback IPs for local labs only.")
    parser.add_argument("--output-dir", default="reports", help="Report directory.")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.max_pages < 1 or args.max_pages > 500:
        print("[!] --max-pages must be between 1 and 500.")
        return 2

    target = args.url.strip()
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print("[!] Please provide a valid http:// or https:// URL.")
        return 2

    root_host = normalize_host(parsed.hostname)
    allowed_hosts = {root_host}
    for host in args.scope_host:
        host = normalize_host(host)
        if not host or "/" in host or ":" in host:
            print(f"[!] Invalid --scope-host: {host}")
            return 2
        allowed_hosts.add(host)

    print(r"""
 __      __   _     __     __    ____
 \ \    / /__| |__  \ \   / /   / ___|  ___ __ _ _ __  _ __   ___ _ __
  \ \/\/ / _ \ '_ \  \ \ / /____\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
   \_/\_/\___/_.__/   \_/ /_____|___) | (_| (_| | | | | | | |  __/ |
                                  |____/ \___\__,_|_| |_|_| |_|\___|_|
    """)
    print("[*] Mode: PASSIVE")
    print(f"[*] Target: {target}")
    print(f"[*] Allowed hosts: {', '.join(sorted(allowed_hosts))}")
    print(f"[*] Max pages: {args.max_pages}")
    print("[!] Use only against assets you own or are explicitly authorized to assess.\n")

    try:
        client = HTTPClient(
            allowed_hosts=allowed_hosts,
            cookie_file=args.cookie_file,
            allow_private=args.allow_private,
        )
        crawler = Crawler(target, client, allowed_hosts, max_pages=args.max_pages)
        crawl_results = crawler.crawl()
        findings = analyze(crawl_results)
        json_path, html_path = save_report(target, crawl_results, findings, args.output_dir)
    except (ValueError, OSError, ScopeError) as exc:
        print(f"[!] Scan stopped: {exc}")
        return 1

    print("\n" + "=" * 56)
    print("[+] Passive scan completed")
    print(f"    Pages visited : {len(crawl_results['visited_urls'])}")
    print(f"    URLs found    : {len(crawl_results['urls'])}")
    print(f"    Parameters    : {len(crawl_results['parameters'])}")
    print(f"    Forms         : {len(crawl_results['forms'])}")
    print(f"    Findings      : {len(findings)}")
    print(f"    JSON report   : {json_path}")
    print(f"    HTML report   : {html_path}")
    print("=" * 56)
    print("[!] Missing headers and heuristic matches are review items, not confirmed exploitable vulnerabilities.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
