from collections import deque
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from http_client import host_in_scope


def normalize_url(url):
    url, _fragment = urldefrag(url)
    parsed = urlparse(url)
    # Drop common tracking parameters; preserve functional parameters.
    tracking = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid"}
    query = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k.lower() not in tracking]
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.params, __import__("urllib.parse").urlencode(query, doseq=True), ""))


class Crawler:
    def __init__(self, start_url, http_client, allowed_hosts, max_pages=50):
        self.start_url = normalize_url(start_url)
        self.http_client = http_client
        self.allowed_hosts = set(allowed_hosts)
        self.max_pages = max_pages
        self.visited = set()
        self.discovered = {self.start_url}
        self.parameters = set()
        self.forms = []
        self.issues = []
        self.pages = []

    def _in_scope(self, url):
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and host_in_scope(parsed.hostname, self.allowed_hosts)

    def crawl(self):
        queue = deque([self.start_url])
        while queue and len(self.visited) < self.max_pages:
            url = queue.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)
            print(f"[+] GET {url}")
            response = self.http_client.get(url)
            if response is None:
                continue

            parsed = urlparse(url)
            for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
                self.parameters.add(key)

            page_info = {
                "url": url,
                "status_code": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "headers": dict(response.headers),
                "body": "",
            }
            content_type = page_info["content_type"].lower()
            if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                self.pages.append(page_info)
                continue

            text = response.text
            page_info["body"] = text
            soup = BeautifulSoup(text, "html.parser")
            self.pages.append(page_info)

            for anchor in soup.find_all("a", href=True):
                candidate = normalize_url(urljoin(url, anchor["href"].strip()))
                if self._in_scope(candidate):
                    self.discovered.add(candidate)
                    if candidate not in self.visited and candidate not in queue:
                        queue.append(candidate)

            for form in soup.find_all("form"):
                action = normalize_url(urljoin(url, form.get("action") or url))
                if not self._in_scope(action):
                    continue
                fields = []
                for field in form.find_all(["input", "select", "textarea", "button"]):
                    name = field.get("name")
                    if name:
                        fields.append({
                            "name": name,
                            "type": field.get("type", field.name),
                        })
                        self.parameters.add(name)
                self.forms.append({
                    "page_url": url,
                    "action": action,
                    "method": (form.get("method") or "GET").upper(),
                    "fields": fields,
                })

        return {
            "start_url": self.start_url,
            "pages": self.pages,
            "urls": sorted(self.discovered),
            "visited_urls": sorted(self.visited),
            "parameters": sorted(self.parameters),
            "forms": self.forms,
        }
