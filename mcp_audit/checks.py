"""Security checks for MCP server configurations.

Each check is a plain function registered with @check. Server-scoped checks
receive one Server; inventory-scoped checks receive the whole Inventory and can
compare servers with each other (for example, tool shadowing).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Callable, Iterator
from urllib.parse import urlparse

from .model import Inventory, Server, Tool

MCP_AUTHZ = "MCP specification 2025-06-18, Basic > Authorization"
MCP_SECURITY = "MCP specification 2025-06-18, Basic > Security Best Practices"
MCP_TOOLS = "MCP specification 2025-06-18, Server > Tools (tool annotations)"
MCP_RESOURCES = "MCP specification 2025-06-18, Server > Resources"
RFC7636 = "RFC 7636: Proof Key for Code Exchange (PKCE)"
RFC8693 = "RFC 8693: OAuth 2.0 Token Exchange"
RFC8707 = "RFC 8707: Resource Indicators for OAuth 2.0"
RFC9068 = "RFC 9068: JWT Profile for OAuth 2.0 Access Tokens (iss/aud validation)"
RFC9700 = "RFC 9700: Best Current Practice for OAuth 2.0 Security"
OWASP_LLM01 = "OWASP Top 10 for LLM Applications 2025: LLM01 Prompt Injection"
OWASP_LLM06 = "OWASP Top 10 for LLM Applications 2025: LLM06 Excessive Agency"


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: str
    server: str
    target: str
    evidence: str
    remediation: str
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "server": self.server,
            "target": self.target,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": list(self.references),
        }


@dataclass(frozen=True)
class Check:
    check_id: str
    title: str
    severity: str
    scope: str  # "server" | "inventory"
    remediation: str
    references: tuple[str, ...]
    func: Callable

    def run(self, subject) -> list[Finding]:
        results = []
        for server, target, evidence, *override in self.func(subject):
            results.append(
                Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=(override[0] if override and override[0] else self.severity),
                    server=server,
                    target=target,
                    evidence=evidence,
                    remediation=self.remediation,
                    references=self.references,
                )
            )
        return results


CHECKS: list[Check] = []


def check(check_id, title, severity, remediation, references=(), scope="server"):
    def register(func):
        CHECKS.append(Check(check_id, title, severity, scope, remediation, tuple(references), func))
        return func

    return register


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BROAD_SCOPE = re.compile(r"(^\*$|:\*$|^admin$|:admin$|^all$|full[_-]?access|^root$|^superuser$)", re.I)
WRITE_SCOPE = re.compile(r"(write|delete|admin|manage|update|create|modify|send|exec|\*)", re.I)
DESTRUCTIVE_VERBS = re.compile(
    r"^(delete|drop|destroy|remove|purge|wipe|truncate|terminate|revoke|rotate|transfer|pay|send|exec|run|kill|reset|overwrite)",
    re.I,
)
READ_VERBS = re.compile(r"^(get|list|read|search|fetch|describe|query|lookup|find)", re.I)

POISON_PATTERNS = [
    (re.compile(r"ignore (all )?(previous|prior|above) instructions", re.I), "instruction override phrase"),
    (re.compile(r"<\s*(important|system|instructions?)\s*>", re.I), "pseudo-system tag"),
    (re.compile(r"do not (tell|inform|mention|reveal)[^.]{0,40}(user|human)", re.I), "concealment from user"),
    (re.compile(r"(~/\.ssh|id_rsa|\.aws/credentials|\.env\b|api[_ -]?key|private key|password)", re.I),
     "reference to credentials or secrets"),
    (re.compile(r"before (using|calling) (any|this|other) tools?", re.I), "pre-emptive instruction to the model"),
    (re.compile(r"(send|forward|post|upload)[^.]{0,60}(to|at) https?://", re.I), "instruction to send data to a URL"),
]
HIDDEN_CHARS = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
MAX_DESCRIPTION = 1024


def _annotation(tool: Tool, key: str):
    return (tool.annotations or {}).get(key)


def _is_destructive(tool: Tool) -> bool:
    if _annotation(tool, "destructiveHint") is True:
        return True
    return bool(DESTRUCTIVE_VERBS.match(tool.name))


def _norm_tool_name(name: str) -> str:
    folded = unicodedata.normalize("NFKC", name).casefold()
    return re.sub(r"[^a-z0-9]", "", folded)


def _uri_host(url: str | None) -> str | None:
    return urlparse(url).netloc if url else None


# ---------------------------------------------------------------------------
# Tool permission checks
# ---------------------------------------------------------------------------


@check(
    "MCP-001",
    "Tool requests broad or wildcard scope",
    "high",
    "Replace wildcard or admin scopes with the narrowest resource-specific scopes the tool needs.",
    (MCP_AUTHZ, OWASP_LLM06),
)
def broad_scopes(server: Server) -> Iterator[tuple]:
    for tool in server.tools:
        broad = [s for s in tool.scopes if BROAD_SCOPE.search(s)]
        if broad:
            yield server.name, f"tool:{tool.name}", f"scopes {list(tool.scopes)} include {broad}"


@check(
    "MCP-002",
    "Read-only tool holds write-capable scopes",
    "high",
    "Split read and write tools, and issue read-only tools a read-only credential. "
    "Annotations are hints and do not constrain what the credential can do.",
    (MCP_TOOLS, OWASP_LLM06),
)
def readonly_with_write(server: Server) -> Iterator[tuple]:
    for tool in server.tools:
        declared_ro = _annotation(tool, "readOnlyHint") is True
        named_ro = bool(READ_VERBS.match(tool.name))
        writes = [s for s in tool.scopes if WRITE_SCOPE.search(s)]
        if writes and (declared_ro or named_ro):
            basis = "readOnlyHint=true" if declared_ro else f"read-style name '{tool.name}'"
            yield server.name, f"tool:{tool.name}", f"{basis} but scopes include {writes}"


@check(
    "MCP-012",
    "Destructive tool does not require human approval",
    "high",
    "Require explicit human confirmation, bound to the specific call, for destructive tools. "
    "Enforce it in the host or gateway, not in the tool description.",
    (MCP_TOOLS, OWASP_LLM06),
)
def destructive_without_approval(server: Server) -> Iterator[tuple]:
    for tool in server.tools:
        if _is_destructive(tool) and not tool.requires_approval:
            basis = "destructiveHint=true" if _annotation(tool, "destructiveHint") is True else "destructive verb in name"
            severity = "critical" if any(BROAD_SCOPE.search(s) for s in tool.scopes) else None
            evidence = f"{basis}; requires_approval=false; scopes {list(tool.scopes)}"
            yield server.name, f"tool:{tool.name}", evidence, severity


@check(
    "MCP-013",
    "Tool annotation contradicts tool behavior or is missing",
    "low",
    "Declare readOnlyHint and destructiveHint explicitly. Under the MCP specification defaults, a tool "
    "without annotations is treated as potentially destructive, so clients cannot make informed approval decisions.",
    (MCP_TOOLS,),
)
def annotation_quality(server: Server) -> Iterator[tuple]:
    for tool in server.tools:
        if not tool.annotations:
            yield server.name, f"tool:{tool.name}", "no annotations declared"
        elif DESTRUCTIVE_VERBS.match(tool.name) and _annotation(tool, "destructiveHint") is False:
            yield server.name, f"tool:{tool.name}", "destructive verb in name but destructiveHint=false", "medium"


# ---------------------------------------------------------------------------
# Transport and authorization checks
# ---------------------------------------------------------------------------


@check(
    "MCP-003",
    "Remote MCP server without OAuth authorization",
    "critical",
    "Protect remote MCP servers as OAuth 2.1 resource servers. Replace static shared tokens with "
    "short-lived, audience-bound access tokens.",
    (MCP_AUTHZ, RFC9700),
)
def remote_without_oauth(server: Server) -> Iterator[tuple]:
    if not server.is_remote:
        return
    if server.auth.type == "none":
        yield server.name, "auth", f"{server.transport} transport at {server.url} with auth.type=none"
    elif server.auth.type == "static_token":
        yield server.name, "auth", "auth.type=static_token (long-lived shared secret)", "medium"


@check(
    "MCP-015",
    "Remote MCP endpoint is not HTTPS",
    "high",
    "Serve remote MCP endpoints over HTTPS only. Bearer tokens sent over plaintext HTTP can be captured and replayed.",
    (MCP_AUTHZ, RFC9700),
)
def plaintext_transport(server: Server) -> Iterator[tuple]:
    if server.is_remote and server.url and urlparse(server.url).scheme != "https":
        host = urlparse(server.url).hostname or ""
        if host not in ("localhost", "127.0.0.1", "::1"):
            yield server.name, "transport", f"url={server.url}"


@check(
    "MCP-004",
    "Token issuer is not validated",
    "high",
    "Validate the 'iss' claim against one expected HTTPS issuer, taken from configuration and not from the token.",
    (MCP_AUTHZ, RFC9068, RFC9700),
)
def issuer_validation(server: Server) -> Iterator[tuple]:
    a = server.auth
    if a.type != "oauth2":
        return
    if not a.validate_issuer:
        yield server.name, "auth.issuer", "validate_issuer=false"
    if a.issuer and urlparse(a.issuer).scheme != "https":
        yield server.name, "auth.issuer", f"issuer {a.issuer!r} is not HTTPS"
    if a.validate_issuer and a.expected_issuer and a.issuer and a.expected_issuer != a.issuer:
        yield server.name, "auth.issuer", f"expected_issuer {a.expected_issuer!r} differs from issuer {a.issuer!r}", "medium"


@check(
    "MCP-005",
    "Token audience is not validated or is too broad",
    "critical",
    "Accept only tokens whose 'aud' is this MCP server's canonical URI. A token minted for another "
    "service must be rejected, even when it comes from the same issuer.",
    (MCP_AUTHZ, RFC8707, RFC9068),
)
def audience_validation(server: Server) -> Iterator[tuple]:
    a = server.auth
    if a.type != "oauth2":
        return
    if not a.validate_audience:
        yield server.name, "auth.audience", "validate_audience=false"
        return
    if "*" in a.accepted_audiences or not a.accepted_audiences:
        yield server.name, "auth.audience", f"accepted_audiences={list(a.accepted_audiences)}"
        return
    if server.url and server.url not in a.accepted_audiences:
        yield (server.name, "auth.audience",
               f"server URL {server.url} is not among accepted_audiences {list(a.accepted_audiences)}", "high")
    foreign = [aud for aud in a.accepted_audiences if _uri_host(aud) and _uri_host(aud) != _uri_host(server.url)]
    if foreign:
        yield server.name, "auth.audience", f"accepts audiences for other hosts: {foreign}", "high"


@check(
    "MCP-006",
    "PKCE not required or allows the plain method",
    "high",
    "Require PKCE with code_challenge_method=S256 for every authorization code flow, and reject 'plain'.",
    (MCP_AUTHZ, RFC7636, RFC9700),
)
def pkce(server: Server) -> Iterator[tuple]:
    a = server.auth
    if a.type != "oauth2":
        return
    if not a.pkce_required:
        yield server.name, "auth.pkce", "pkce_required=false"
    elif "plain" in a.pkce_methods or "S256" not in a.pkce_methods:
        yield server.name, "auth.pkce", f"pkce_methods={list(a.pkce_methods)}"


@check(
    "MCP-007",
    "Inbound access token is passed through to downstream APIs",
    "critical",
    "Never forward the client's token downstream. Exchange it for a new token scoped to the downstream "
    "audience (RFC 8693 token exchange), or use the server's own credential with per-user authorization.",
    (MCP_SECURITY, RFC8693),
)
def token_passthrough(server: Server) -> Iterator[tuple]:
    a = server.auth
    if a.token_passthrough or a.downstream_auth == "passthrough":
        yield server.name, "auth.downstream", f"token_passthrough={a.token_passthrough}, downstream_auth={a.downstream_auth}"


@check(
    "MCP-008",
    "Resource indicators (RFC 8707) not required",
    "medium",
    "Require the 'resource' parameter in authorization and token requests, so that tokens are minted "
    "for this server's audience only.",
    (MCP_AUTHZ, RFC8707),
)
def resource_indicators(server: Server) -> Iterator[tuple]:
    if server.auth.type == "oauth2" and not server.auth.resource_indicators_required:
        yield server.name, "auth.resource_indicators", "resource_indicators_required=false"


@check(
    "MCP-009",
    "Confused-deputy risk in OAuth proxy server",
    "high",
    "When a proxy uses one static client ID with a third-party authorization server, obtain explicit "
    "per-client user consent before forwarding to the third party. Do not rely on a prior consent cookie.",
    (MCP_SECURITY, RFC9700),
)
def confused_deputy(server: Server) -> Iterator[tuple]:
    a = server.auth
    if server.role == "proxy" and a.static_client_id and a.dynamic_client_registration and not a.per_client_consent:
        yield (server.name, "auth.proxy",
               "role=proxy, static_client_id=true, dynamic_client_registration=true, per_client_consent=false")


@check(
    "MCP-016",
    "Proxy uses a static downstream credential for all users",
    "medium",
    "Map each MCP user to their own downstream authorization, using token exchange or per-user OAuth. "
    "A shared service credential makes every user as powerful as the service.",
    (MCP_SECURITY, RFC8693, OWASP_LLM06),
)
def static_downstream(server: Server) -> Iterator[tuple]:
    if server.role == "proxy" and server.auth.downstream_auth == "static_credential":
        yield server.name, "auth.downstream", "downstream_auth=static_credential"


# ---------------------------------------------------------------------------
# Tool metadata integrity
# ---------------------------------------------------------------------------


@check(
    "MCP-010",
    "Tool description contains prompt-injection indicators (tool poisoning)",
    "high",
    "Treat tool descriptions as untrusted input. Pin and review them, show users what the model sees, "
    "and alert when a description changes after approval (rug pull).",
    (MCP_TOOLS, OWASP_LLM01),
)
def tool_poisoning(server: Server) -> Iterator[tuple]:
    for tool in server.tools:
        text = tool.description
        hits = [label for pattern, label in POISON_PATTERNS if pattern.search(text)]
        hidden = sorted({f"U+{ord(c):04X}" for c in text if c in HIDDEN_CHARS})
        if hidden:
            hits.append(f"invisible characters {hidden}")
        if len(text) > MAX_DESCRIPTION:
            hits.append(f"description length {len(text)} > {MAX_DESCRIPTION}")
        if hits:
            severity = "critical" if len(hits) >= 2 else None
            evidence = "; ".join(hits)
            yield server.name, f"tool:{tool.name}", evidence, severity


@check(
    "MCP-011",
    "Tool shadowing across servers",
    "high",
    "Namespace tools per server in the host (for example server.tool), reject duplicate or confusable names, "
    "and flag descriptions that try to change how other servers' tools are used.",
    (MCP_TOOLS, OWASP_LLM01),
    scope="inventory",
)
def tool_shadowing(inventory: Inventory) -> Iterator[tuple]:
    owners: dict[str, list[tuple[str, str]]] = {}
    for server in inventory.servers:
        for tool in server.tools:
            owners.setdefault(_norm_tool_name(tool.name), []).append((server.name, tool.name))
    for key, entries in sorted(owners.items()):
        servers = sorted({s for s, _ in entries})
        if len(servers) > 1:
            names = sorted({t for _, t in entries})
            yield ", ".join(servers), f"tool:{names[0]}", f"name collides after normalization across servers {servers}: {names}"
    for server in inventory.servers:
        for tool in server.tools:
            for other in inventory.servers:
                if other.name == server.name:
                    continue
                for foreign in other.tools:
                    if len(foreign.name) >= 4 and re.search(rf"\b{re.escape(foreign.name)}\b", tool.description):
                        yield (server.name, f"tool:{tool.name}",
                               f"description references tool '{foreign.name}' owned by server '{other.name}'")


# ---------------------------------------------------------------------------
# Resource boundaries
# ---------------------------------------------------------------------------


@check(
    "MCP-014",
    "Resource outside declared access boundary",
    "high",
    "Declare narrow allowed roots. Canonicalize every resource URI before the boundary check, and reject "
    "traversal segments.",
    (MCP_RESOURCES, OWASP_LLM06),
)
def resource_boundaries(server: Server) -> Iterator[tuple]:
    for root in server.allowed_roots:
        parsed = urlparse(root)
        if parsed.scheme == "file" and parsed.path in ("", "/"):
            yield server.name, f"root:{root}", "allowed root is the entire filesystem", "critical"
    for res in server.resources:
        if ".." in urlparse(res.uri).path.split("/"):
            yield server.name, f"resource:{res.uri}", "path traversal segment '..'"
            continue
        if server.allowed_roots and not any(res.uri.startswith(r) for r in server.allowed_roots):
            yield server.name, f"resource:{res.uri}", f"not under allowed_roots {list(server.allowed_roots)}"
        if not server.allowed_roots and res.uri.startswith("file://"):
            yield server.name, f"resource:{res.uri}", "file resource exposed with no allowed_roots declared", "medium"
