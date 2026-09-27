"""Inventory model for MCP server configurations.

The input format is a JSON description of one or more MCP servers as deployed:
transport, authorization settings, declared tools, and exposed resources. It is
defined by this project for offline assessment; it is not an MCP wire format.
See docs/config-schema.md for every field.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Raised when an inventory file does not match the expected schema."""


@dataclass(frozen=True)
class AuthConfig:
    type: str = "none"  # oauth2 | static_token | none
    issuer: str | None = None
    expected_issuer: str | None = None
    validate_issuer: bool = False
    validate_audience: bool = False
    accepted_audiences: tuple[str, ...] = ()
    pkce_required: bool = False
    pkce_methods: tuple[str, ...] = ()
    resource_indicators_required: bool = False
    token_passthrough: bool = False
    downstream_auth: str = "none"  # token_exchange | passthrough | static_credential | none
    static_client_id: bool = False
    dynamic_client_registration: bool = False
    per_client_consent: bool = False


@dataclass(frozen=True)
class Tool:
    name: str
    description: str = ""
    scopes: tuple[str, ...] = ()
    annotations: dict[str, Any] | None = None
    requires_approval: bool = False


@dataclass(frozen=True)
class Resource:
    uri: str
    name: str = ""


@dataclass(frozen=True)
class Server:
    name: str
    transport: str  # stdio | streamable-http | sse
    url: str | None = None
    role: str = "resource_server"  # resource_server | proxy
    auth: AuthConfig = field(default_factory=AuthConfig)
    tools: tuple[Tool, ...] = ()
    resources: tuple[Resource, ...] = ()
    allowed_roots: tuple[str, ...] = ()

    @property
    def is_remote(self) -> bool:
        return self.transport in ("streamable-http", "sse")


@dataclass(frozen=True)
class Inventory:
    name: str
    servers: tuple[Server, ...]
    source: str = "<memory>"


_TRANSPORTS = {"stdio", "streamable-http", "sse"}
_AUTH_TYPES = {"oauth2", "static_token", "none"}
_DOWNSTREAM = {"token_exchange", "passthrough", "static_credential", "none"}


def _tuple(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where} must be a list of strings")
    return tuple(value)


def _bool(raw: dict, key: str, where: str, default: bool = False) -> bool:
    value = raw.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{where}.{key} must be true or false")
    return value


def _parse_auth(raw: dict | None, where: str) -> AuthConfig:
    if raw is None:
        return AuthConfig()
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be an object")
    auth_type = raw.get("type", "none")
    if auth_type not in _AUTH_TYPES:
        raise ConfigError(f"{where}.type must be one of {sorted(_AUTH_TYPES)}")
    downstream = raw.get("downstream_auth", "none")
    if downstream not in _DOWNSTREAM:
        raise ConfigError(f"{where}.downstream_auth must be one of {sorted(_DOWNSTREAM)}")
    return AuthConfig(
        type=auth_type,
        issuer=raw.get("issuer"),
        expected_issuer=raw.get("expected_issuer"),
        validate_issuer=_bool(raw, "validate_issuer", where),
        validate_audience=_bool(raw, "validate_audience", where),
        accepted_audiences=_tuple(raw.get("accepted_audiences"), f"{where}.accepted_audiences"),
        pkce_required=_bool(raw, "pkce_required", where),
        pkce_methods=_tuple(raw.get("pkce_methods"), f"{where}.pkce_methods"),
        resource_indicators_required=_bool(raw, "resource_indicators_required", where),
        token_passthrough=_bool(raw, "token_passthrough", where),
        downstream_auth=downstream,
        static_client_id=_bool(raw, "static_client_id", where),
        dynamic_client_registration=_bool(raw, "dynamic_client_registration", where),
        per_client_consent=_bool(raw, "per_client_consent", where),
    )


def _parse_tool(raw: dict, where: str) -> Tool:
    if not isinstance(raw, dict) or not isinstance(raw.get("name"), str) or not raw["name"]:
        raise ConfigError(f"{where} must be an object with a non-empty 'name'")
    annotations = raw.get("annotations")
    if annotations is not None and not isinstance(annotations, dict):
        raise ConfigError(f"{where}.annotations must be an object")
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise ConfigError(f"{where}.description must be a string")
    return Tool(
        name=raw["name"],
        description=description,
        scopes=_tuple(raw.get("scopes"), f"{where}.scopes"),
        annotations=annotations,
        requires_approval=_bool(raw, "requires_approval", where),
    )


def _parse_server(raw: dict, index: int) -> Server:
    where = f"servers[{index}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be an object")
    name = raw.get("name")
    if not isinstance(name, str) or not name:
        raise ConfigError(f"{where}.name is required")
    where = f"servers[{index}] ({name})"
    transport = raw.get("transport")
    if transport not in _TRANSPORTS:
        raise ConfigError(f"{where}.transport must be one of {sorted(_TRANSPORTS)}")
    if transport != "stdio" and not raw.get("url"):
        raise ConfigError(f"{where}.url is required for remote transports")
    role = raw.get("role", "resource_server")
    if role not in ("resource_server", "proxy"):
        raise ConfigError(f"{where}.role must be 'resource_server' or 'proxy'")
    tools = raw.get("tools", [])
    resources = raw.get("resources", [])
    if not isinstance(tools, list) or not isinstance(resources, list):
        raise ConfigError(f"{where}.tools and .resources must be lists")
    for i, r in enumerate(resources):
        if not isinstance(r, dict) or not isinstance(r.get("uri"), str):
            raise ConfigError(f"{where}.resources[{i}] must be an object with a 'uri'")
    return Server(
        name=name,
        transport=transport,
        url=raw.get("url"),
        role=role,
        auth=_parse_auth(raw.get("auth"), f"{where}.auth"),
        tools=tuple(_parse_tool(t, f"{where}.tools[{i}]") for i, t in enumerate(tools)),
        resources=tuple(Resource(uri=r["uri"], name=r.get("name", "")) for r in resources),
        allowed_roots=_tuple(raw.get("allowed_roots"), f"{where}.allowed_roots"),
    )


def parse_inventory(raw: dict, source: str = "<memory>") -> Inventory:
    if not isinstance(raw, dict) or not isinstance(raw.get("servers"), list):
        raise ConfigError("inventory must be an object with a 'servers' list")
    servers = tuple(_parse_server(s, i) for i, s in enumerate(raw["servers"]))
    names = [s.name for s in servers]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise ConfigError(f"duplicate server names: {duplicates}")
    return Inventory(name=str(raw.get("inventory", Path(source).stem)), servers=servers, source=source)


def load_inventory(path: str | Path) -> Inventory:
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: invalid JSON at line {exc.lineno} ({exc.msg})") from exc
    try:
        return parse_inventory(raw, source=str(path))
    except ConfigError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
