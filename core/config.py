"""Configuration management for Bug Bounty Recon Framework."""

import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


DEFAULT_CONFIG = {
    "general": {
        "output_dir": "data",
        "log_level": "INFO",
        "max_concurrent_requests": 50,
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ],
    },
    "proxy": {
        "enabled": False,
        "http_proxy": None,
        "socks_proxy": None,
        "rotate": False,
        "proxy_list": [],
    },
    "rate_limit": {
        "requests_per_second": 5,
        "burst_size": 10,
        "retry_attempts": 3,
        "retry_backoff": 2.0,
    },
    "platforms": {
        "hackerone": {
            "enabled": True,
            "api_token": None,
            "api_username": None,
            "base_url": "https://hackerone.com",
        },
        "bugcrowd": {
            "enabled": True,
            "api_token": None,
            "base_url": "https://bugcrowd.com",
        },
        "intigriti": {
            "enabled": True,
            "api_token": None,
            "base_url": "https://app.intigriti.com",
        },
        "yeswehack": {
            "enabled": True,
            "api_token": None,
            "base_url": "https://yeswehack.com",
        },
        "github": {
            "enabled": True,
            "api_token": None,
            "base_url": "https://api.github.com",
            "search_repos": [
                "projectdiscovery/nuclei-templates",
                "swisskyrepo/PayloadsAllTheThings",
            ],
        },
    },
    "categories": [
        "ssrf",
        "xss",
        "sqli",
        "idor",
        "business_logic",
        "rce",
        "lfi",
        "open_redirect",
        "xxe",
        "csrf",
    ],
    "database": {
        "path": "data/recon.db",
        "backup_interval": 3600,
    },
    "dashboard": {
        "host": "0.0.0.0",
        "port": 5000,
        "debug": False,
    },
}


@dataclass
class ProxyConfig:
    enabled: bool = False
    http_proxy: Optional[str] = None
    socks_proxy: Optional[str] = None
    rotate: bool = False
    proxy_list: List[str] = field(default_factory=list)


@dataclass
class RateLimitConfig:
    requests_per_second: int = 5
    burst_size: int = 10
    retry_attempts: int = 3
    retry_backoff: float = 2.0


@dataclass
class PlatformConfig:
    enabled: bool = True
    api_token: Optional[str] = None
    api_username: Optional[str] = None
    base_url: str = ""
    search_repos: List[str] = field(default_factory=list)


class Config:
    """Central configuration management."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config()
        self._data: Dict[str, Any] = {}
        self._load()

    def _find_config(self) -> str:
        """Find config file in standard locations."""
        search_paths = [
            Path("config.yaml"),
            Path("config.yml"),
            Path(os.path.expanduser("~/.bugrecon/config.yaml")),
        ]
        for path in search_paths:
            if path.exists():
                return str(path)
        return "config.yaml"

    def _load(self):
        """Load configuration from file, falling back to defaults."""
        self._data = DEFAULT_CONFIG.copy()

        if Path(self.config_path).exists():
            with open(self.config_path, "r") as f:
                user_config = yaml.safe_load(f) or {}
            self._deep_merge(self._data, user_config)

        # Override with environment variables
        self._load_env_overrides()

    def _deep_merge(self, base: dict, override: dict):
        """Deep merge override into base dict."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def _load_env_overrides(self):
        """Load config overrides from environment variables."""
        env_mappings = {
            "BUGRECON_HACKERONE_TOKEN": ("platforms", "hackerone", "api_token"),
            "BUGRECON_HACKERONE_USER": ("platforms", "hackerone", "api_username"),
            "BUGRECON_BUGCROWD_TOKEN": ("platforms", "bugcrowd", "api_token"),
            "BUGRECON_INTIGRITI_TOKEN": ("platforms", "intigriti", "api_token"),
            "BUGRECON_YESWEHACK_TOKEN": ("platforms", "yeswehack", "api_token"),
            "BUGRECON_GITHUB_TOKEN": ("platforms", "github", "api_token"),
            "BUGRECON_HTTP_PROXY": ("proxy", "http_proxy"),
            "BUGRECON_SOCKS_PROXY": ("proxy", "socks_proxy"),
        }

        for env_var, path in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                self._set_nested(self._data, path, value)

    def _set_nested(self, data: dict, keys: tuple, value: Any):
        """Set a nested dictionary value using a tuple of keys."""
        for key in keys[:-1]:
            data = data.setdefault(key, {})
        data[keys[-1]] = value

    def get(self, *keys, default=None) -> Any:
        """Get a nested config value."""
        data = self._data
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key, default)
            else:
                return default
        return data

    @property
    def proxy(self) -> ProxyConfig:
        p = self._data.get("proxy", {})
        return ProxyConfig(**{k: v for k, v in p.items() if k in ProxyConfig.__dataclass_fields__})

    @property
    def rate_limit(self) -> RateLimitConfig:
        r = self._data.get("rate_limit", {})
        return RateLimitConfig(**{k: v for k, v in r.items() if k in RateLimitConfig.__dataclass_fields__})

    def get_platform(self, name: str) -> PlatformConfig:
        """Get platform-specific configuration."""
        p = self._data.get("platforms", {}).get(name, {})
        return PlatformConfig(**{k: v for k, v in p.items() if k in PlatformConfig.__dataclass_fields__})

    @property
    def categories(self) -> List[str]:
        return self._data.get("categories", [])

    @property
    def output_dir(self) -> Path:
        return Path(self._data.get("general", {}).get("output_dir", "data"))

    @property
    def user_agents(self) -> List[str]:
        return self._data.get("general", {}).get("user_agents", [])

    def save(self, path: Optional[str] = None):
        """Save current config to file."""
        save_path = path or self.config_path
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        with open(save_path, "w") as f:
            yaml.dump(self._data, f, default_flow_style=False)

    def __repr__(self):
        return f"Config(path={self.config_path})"
