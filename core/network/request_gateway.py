"""
Baseera Sec - Centralized Scope Enforcement & Secure Request Gateway
Provides strict target authorization, RFC 1918 / RFC 3927 private IP blocking,
DNS rebinding prevention, redirect hop validation, request budgeting, and cancellation.
"""
import ipaddress
import socket
import logging
import asyncio
import time
from urllib.parse import urlparse, urljoin
from typing import Optional, Dict, Any, List, Set, Tuple
import httpx

logger = logging.getLogger("baseera.network.gateway")

# Prohibited IP networks by default (Loopback, Private RFC1918, Link-local, Multicast, Reserved)
DEFAULT_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "instance-data",
    "169.254.169.254",
}


class ScopeViolationError(Exception):
    """Raised when a request violates configured scope or security policy."""
    pass


class BudgetExceededError(Exception):
    """Raised when a scan exceeds request or byte count budget."""
    pass


class ScanBudget:
    def __init__(self, max_requests: int = 1500, max_bytes: int = 50 * 1024 * 1024, max_time_seconds: float = 600.0):
        self.max_requests = max_requests
        self.max_bytes = max_bytes
        self.max_time_seconds = max_time_seconds
        self.requests_sent = 0
        self.bytes_received = 0
        self.start_time = time.time()
        self._lock = asyncio.Lock()

    async def record_request(self):
        async with self._lock:
            if time.time() - self.start_time > self.max_time_seconds:
                raise BudgetExceededError(f"Scan time budget exceeded ({self.max_time_seconds}s)")
            if self.requests_sent >= self.max_requests:
                raise BudgetExceededError(f"Request count budget exceeded ({self.max_requests} requests)")
            self.requests_sent += 1

    async def record_bytes(self, count: int):
        async with self._lock:
            self.bytes_received += count
            if self.bytes_received > self.max_bytes:
                raise BudgetExceededError(f"Byte transfer budget exceeded ({self.max_bytes} bytes)")


class RequestGateway:
    """
    Centralized HTTP/HTTPS Gateway for all scanning modules.
    Enforces scope, validates DNS/IPs, tracks budgets, and prevents SSRF.
    """

    def __init__(
        self,
        target_url: str,
        allowed_domains: Optional[List[str]] = None,
        allow_internal_targets: bool = False,
        allow_insecure_tls: bool = False,
        max_redirects: int = 5,
        default_timeout: float = 6.0,
        max_concurrency: int = 15,
        budget: Optional[ScanBudget] = None,
        dry_run: bool = False,
        user_agent: str = "BaseeraSec-EthicalAuditor/2.0 (+https://baseerasec.local)",
        dns_mapping: Optional[Dict[str, str]] = None
    ):
        self.target_url = target_url
        self.parsed_target = urlparse(target_url)
        self.primary_domain = (self.parsed_target.hostname or "").lower()
        self.allowed_domains: Set[str] = {self.primary_domain}
        if allowed_domains:
            for d in allowed_domains:
                clean = d.strip().lower()
                if clean:
                    self.allowed_domains.add(clean)

        self.allow_internal_targets = allow_internal_targets
        self.allow_insecure_tls = allow_insecure_tls
        self.max_redirects = max_redirects
        self.default_timeout = default_timeout
        self.dry_run = dry_run
        self.user_agent = user_agent
        self.dns_mapping = dns_mapping or {}
        self.budget = budget or ScanBudget()
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.cancellation_token = asyncio.Event()
        self.audit_log: List[Dict[str, Any]] = []

    def cancel_scan(self):
        """Signals active and future requests to terminate."""
        self.cancellation_token.set()

    def is_cancelled(self) -> bool:
        return self.cancellation_token.is_set()

    def validate_destination(self, url: str) -> Tuple[str, str, int]:
        """
        Validates scheme, hostname, resolved IP, and allowed domain.
        Returns (hostname, ip_address, port).
        """
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise ScopeViolationError(f"Prohibited URL scheme '{scheme}'. Only http and https allowed.")

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise ScopeViolationError("Missing hostname in target URL.")

        if hostname in BLOCKED_HOSTNAMES and not self.allow_internal_targets:
            raise ScopeViolationError(f"Access to sensitive host '{hostname}' is blocked.")

        # Domain scope check
        is_in_domain_scope = False
        for allowed in self.allowed_domains:
            if hostname == allowed or hostname.endswith("." + allowed):
                is_in_domain_scope = True
                break

        if not is_in_domain_scope:
            raise ScopeViolationError(f"Host '{hostname}' is out of authorized scope: {self.allowed_domains}")

        port = parsed.port or (443 if scheme == "https" else 80)

        # DNS resolution and IP destination validation (SSRF / DNS Rebinding Guard)
        if hostname in self.dns_mapping:
            resolved_ip_str = self.dns_mapping[hostname]
        else:
            try:
                addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
            except socket.gaierror as e:
                raise ScopeViolationError(f"DNS resolution failed for '{hostname}': {e}")

            if not addr_info:
                raise ScopeViolationError(f"Could not resolve any IP address for '{hostname}'.")

            resolved_ip_str = addr_info[0][4][0]
        try:
            ip_obj = ipaddress.ip_address(resolved_ip_str)
        except ValueError:
            raise ScopeViolationError(f"Invalid resolved IP address: {resolved_ip_str}")

        if not self.allow_internal_targets:
            for blocked_net in DEFAULT_BLOCKED_NETWORKS:
                if ip_obj in blocked_net:
                    raise ScopeViolationError(
                        f"Resolved IP {resolved_ip_str} belongs to protected/private network {blocked_net}."
                    )

        return hostname, resolved_ip_str, port

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Any = None,
        json: Any = None,
        params: Any = None,
        timeout: Optional[float] = None,
        follow_redirects: bool = True
    ) -> httpx.Response:
        """
        Executes an audited, scope-validated HTTP request with hop-by-hop redirect validation.
        """
        if self.is_cancelled():
            raise asyncio.CancelledError("Scan was cancelled by user.")

        req_timeout = timeout or self.default_timeout

        # Initial URL scope check
        self.validate_destination(url)
        await self.budget.record_request()

        merged_headers = {"User-Agent": self.user_agent}
        if headers:
            merged_headers.update(headers)

        if self.dry_run:
            # Emulate dry-run response without opening socket
            mock_res = httpx.Response(
                status_code=200,
                request=httpx.Request(method, url, headers=merged_headers),
                content=b"[DRY-RUN-SIMULATED-BODY]"
            )
            self._log_transaction(method, url, 200, 0.0, True, "Dry-run simulated")
            return mock_res

        async with self.semaphore:
            current_url = url
            current_method = method.upper()
            redirect_count = 0
            t0 = time.perf_counter()

            # Client configuration: TLS verification enabled by default
            verify_ssl = not self.allow_insecure_tls

            # Manual redirect following to validate EVERY redirect hop against scope & IP rules
            async with httpx.AsyncClient(verify=verify_ssl, follow_redirects=False) as client:
                while True:
                    if self.is_cancelled():
                        raise asyncio.CancelledError("Scan cancelled during request execution.")

                    self.validate_destination(current_url)

                    try:
                        res = await client.request(
                            method=current_method,
                            url=current_url,
                            headers=merged_headers,
                            data=data if current_method in ("POST", "PUT", "PATCH") else None,
                            json=json if current_method in ("POST", "PUT", "PATCH") else None,
                            params=params,
                            timeout=req_timeout
                        )
                    except (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout) as e:
                        elapsed = (time.perf_counter() - t0) * 1000
                        self._log_transaction(current_method, current_url, 0, elapsed, False, str(e))
                        raise

                    await self.budget.record_bytes(len(res.content))

                    if follow_redirects and res.is_redirect and "location" in res.headers:
                        redirect_count += 1
                        if redirect_count > self.max_redirects:
                            raise ScopeViolationError(f"Exceeded max redirects ({self.max_redirects})")
                        location = res.headers["location"]
                        next_url = urljoin(current_url, location)
                        # Validate the new location before following!
                        self.validate_destination(next_url)
                        current_url = next_url
                        # Standard HTTP redirect semantics: 301/302/303 to GET
                        if res.status_code in (301, 302, 303):
                            current_method = "GET"
                            data = None
                            json = None
                        continue
                    else:
                        elapsed = (time.perf_counter() - t0) * 1000
                        self._log_transaction(current_method, current_url, res.status_code, elapsed, True)
                        return res

    def _log_transaction(self, method: str, url: str, status_code: int, latency_ms: float, success: bool, error: str = ""):
        entry = {
            "timestamp": time.time(),
            "method": method,
            "url": url,
            "status_code": status_code,
            "latency_ms": round(latency_ms, 2),
            "success": success,
            "error": error
        }
        self.audit_log.append(entry)
        if len(self.audit_log) > 2000:
            self.audit_log.pop(0)


class GatewayAsyncClient:
    """HTTPX-compatible subset that routes scanner requests through a gateway."""

    def __init__(self, gateway: RequestGateway, headers: Optional[Dict[str, str]] = None):
        self.gateway = gateway
        self.headers = httpx.Headers(headers or {})

    async def __aenter__(self):
        return self

    async def __aexit__(self, _exc_type, _exc_value, _traceback):
        return False

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        data: Any = None,
        json: Any = None,
        params: Any = None,
        timeout: Optional[float] = None,
        follow_redirects: bool = True,
    ) -> httpx.Response:
        merged_headers = httpx.Headers(self.headers)
        if headers:
            merged_headers.update(headers)
        response = await self.gateway.request(
            method,
            url,
            headers=dict(merged_headers),
            data=data,
            json=json,
            params=params,
            timeout=timeout,
            follow_redirects=follow_redirects,
        )
        return response

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def options(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("OPTIONS", url, **kwargs)
