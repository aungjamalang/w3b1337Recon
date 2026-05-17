"""Async HTTP client with proxy support, rate limiting, and retry logic."""

import asyncio
import random
import time
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector

from .config import Config, ProxyConfig, RateLimitConfig


@dataclass
class HTTPResponse:
    """Standardized HTTP response."""
    status: int
    headers: Dict[str, str]
    text: str
    json_data: Optional[Any] = None
    url: str = ""
    elapsed: float = 0.0


class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_refill = now

            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class AsyncHTTPClient:
    """Async HTTP client with proxy rotation, rate limiting, and retries."""

    def __init__(self, config: Config):
        self.config = config
        self._session: Optional[ClientSession] = None
        self._proxy_config: ProxyConfig = config.proxy
        self._rate_config: RateLimitConfig = config.rate_limit
        self._rate_limiter = TokenBucket(
            rate=self._rate_config.requests_per_second,
            burst=self._rate_config.burst_size,
        )
        self._user_agents: List[str] = config.user_agents
        self._proxy_index = 0

    async def __aenter__(self):
        await self._create_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def _create_session(self):
        """Create aiohttp session with configured settings."""
        connector = TCPConnector(
            limit=self.config.get("general", "max_concurrent_requests", default=50),
            ssl=False,
        )
        timeout = ClientTimeout(total=30)
        self._session = ClientSession(connector=connector, timeout=timeout)

    async def close(self):
        """Close the HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None

    def _get_proxy(self) -> Optional[str]:
        """Get proxy URL based on configuration."""
        if not self._proxy_config.enabled:
            return None

        if self._proxy_config.rotate and self._proxy_config.proxy_list:
            proxy = self._proxy_config.proxy_list[self._proxy_index]
            self._proxy_index = (self._proxy_index + 1) % len(self._proxy_config.proxy_list)
            return proxy

        return self._proxy_config.http_proxy or self._proxy_config.socks_proxy

    def _get_user_agent(self) -> str:
        """Get a random user agent string."""
        if self._user_agents:
            return random.choice(self._user_agents)
        return "BugRecon/1.0"

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        allow_redirects: bool = True,
        timeout: Optional[int] = None,
    ) -> HTTPResponse:
        """Make an HTTP request with rate limiting and retries."""
        if not self._session:
            await self._create_session()

        # Apply rate limiting
        await self._rate_limiter.acquire()

        # Build headers
        request_headers = {
            "User-Agent": self._get_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        if headers:
            request_headers.update(headers)

        # Get proxy
        proxy = self._get_proxy()

        # Retry logic with exponential backoff
        last_exception = None
        for attempt in range(self._rate_config.retry_attempts):
            try:
                start_time = time.monotonic()

                request_timeout = ClientTimeout(total=timeout) if timeout else None

                async with self._session.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    params=params,
                    data=data,
                    json=json,
                    proxy=proxy,
                    allow_redirects=allow_redirects,
                    timeout=request_timeout,
                ) as resp:
                    elapsed = time.monotonic() - start_time
                    text = await resp.text()

                    json_data = None
                    if "application/json" in resp.headers.get("Content-Type", ""):
                        try:
                            json_data = await resp.json()
                        except Exception:
                            pass

                    return HTTPResponse(
                        status=resp.status,
                        headers=dict(resp.headers),
                        text=text,
                        json_data=json_data,
                        url=str(resp.url),
                        elapsed=elapsed,
                    )

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_exception = e
                if attempt < self._rate_config.retry_attempts - 1:
                    backoff = self._rate_config.retry_backoff ** attempt
                    await asyncio.sleep(backoff)

        raise ConnectionError(
            f"Request failed after {self._rate_config.retry_attempts} attempts: {last_exception}"
        )

    async def get(self, url: str, **kwargs) -> HTTPResponse:
        """HTTP GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HTTPResponse:
        """HTTP POST request."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> HTTPResponse:
        """HTTP PUT request."""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> HTTPResponse:
        """HTTP DELETE request."""
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> HTTPResponse:
        """HTTP HEAD request."""
        return await self.request("HEAD", url, **kwargs)

    async def fetch_all(self, urls: List[str], **kwargs) -> List[HTTPResponse]:
        """Fetch multiple URLs concurrently."""
        tasks = [self.get(url, **kwargs) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, HTTPResponse)]
