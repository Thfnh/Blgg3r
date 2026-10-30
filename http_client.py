import ipaddress
import json
import socket
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import MAX_REDIRECTS, MAX_RESPONSE_BYTES, REQUEST_DELAY, REQUEST_TIMEOUT, USER_AGENT


class ScopeError(RuntimeError):
    pass


def normalize_host(host):
    return (host or "").rstrip(".").lower()


def host_in_scope(host, allowed_hosts):
    host = normalize_host(host)
    for allowed in allowed_hosts:
        allowed = normalize_host(allowed)
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def resolve_and_check_public(host, allow_private=False):
    """Reject private/reserved destinations unless explicitly enabled for a lab."""
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError(f"DNS lookup failed for {host}: {exc}") from exc

    addresses = {record[4][0] for record in records}
    if not addresses:
        raise ScopeError(f"No IP addresses resolved for {host}")

    if not allow_private:
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                raise ScopeError(
                    f"Blocked non-public destination {host} -> {address}. "
                    "For a local lab only, rerun with --allow-private."
                )


class HTTPClient:
    def __init__(self, allowed_hosts, cookie_file=None, allow_private=False):
        self.allowed_hosts = set(allowed_hosts)
        self.allow_private = allow_private
        self.last_request_at = 0.0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.max_redirects = MAX_REDIRECTS

        retry = Retry(
            total=1,
            connect=1,
            read=0,
            status=0,
            backoff_factor=0.2,
            allowed_methods=frozenset(["GET", "HEAD"]),
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        if cookie_file:
            self._load_cookies(cookie_file)

    def _load_cookies(self, cookie_file):
        path = Path(cookie_file)
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            for name, value in data.items():
                self.session.cookies.set(str(name), str(value))
        elif isinstance(data, list):
            for item in data:
                if not isinstance(item, dict) or "name" not in item or "value" not in item:
                    raise ValueError("Cookie JSON list items need 'name' and 'value'.")
                self.session.cookies.set(
                    str(item["name"]),
                    str(item["value"]),
                    domain=item.get("domain"),
                    path=item.get("path", "/"),
                )
        else:
            raise ValueError("Cookie file must be a JSON object or list.")

    def _validate_url(self, url):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ScopeError(f"Unsupported URL scheme: {parsed.scheme}")
        if not parsed.hostname:
            raise ScopeError(f"Invalid URL: {url}")
        if not host_in_scope(parsed.hostname, self.allowed_hosts):
            raise ScopeError(f"Out-of-scope host blocked: {parsed.hostname}")
        resolve_and_check_public(parsed.hostname, self.allow_private)

    def get(self, url):
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            try:
                self._validate_url(current)
                elapsed = time.monotonic() - self.last_request_at
                if elapsed < REQUEST_DELAY:
                    time.sleep(REQUEST_DELAY - elapsed)
                response = self.session.get(
                    current,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=False,
                    stream=True,
                )
                self.last_request_at = time.monotonic()

                # Manually validate every redirect before following it.
                if response.is_redirect or response.is_permanent_redirect:
                    location = response.headers.get("Location")
                    status = response.status_code
                    response.close()
                    if not location:
                        return None
                    current = requests.compat.urljoin(current, location)
                    if not host_in_scope(urlparse(current).hostname, self.allowed_hosts):
                        raise ScopeError(f"Redirect leaves authorized scope: {current}")
                    continue

                # Limit body size to avoid downloading very large responses.
                chunks = []
                size = 0
                for chunk in response.iter_content(chunk_size=16384):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        response.close()
                        raise ValueError(f"Response exceeds {MAX_RESPONSE_BYTES} bytes: {current}")
                    chunks.append(chunk)
                response._content = b"".join(chunks)
                response._content_consumed = True
                return response

            except (requests.RequestException, ScopeError, ValueError) as exc:
                print(f"[!] Skipped {current}: {exc}")
                return None

        print(f"[!] Redirect limit reached: {url}")
        return None
