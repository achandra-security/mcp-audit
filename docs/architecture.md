# Architecture

## Why offline first

MCP servers are often third-party code with broad credentials. The first review question is not "can I exploit it?". It is "should this be connected at all, and with what configuration?" An offline engine can:

- run in CI on every configuration change, with no network access and no credentials;
- be pointed safely at servers you have not yet vetted;
- produce deterministic, diffable results that suit review gates.

## Flow

```mermaid
sequenceDiagram
    participant U as Reviewer / CI
    participant CLI as cli.py
    participant M as model.py
    participant E as engine.py
    participant C as checks.py
    participant R as report.py
    U->>CLI: mcp-audit scan inventory.json --format sarif
    CLI->>M: load_inventory(path)
    M-->>CLI: Inventory (validated) or ConfigError(file + field)
    CLI->>E: assess(inventory, only, skip)
    loop each registered check
        E->>C: server-scoped check(server) for every server
        E->>C: inventory-scoped check(inventory)
        C-->>E: (server, target, evidence[, severity override])
    end
    E-->>CLI: findings sorted by severity
    CLI->>R: to_text / to_json / to_sarif
    R-->>U: report, exit code 0 / 1 (input error) / 2 (--fail-on hit)
```

## Threat model covered

```mermaid
flowchart LR
    Client[MCP client / agent host] -->|access token| Server[MCP server]
    AS[Authorization server] -->|issues token| Client
    Server -->|downstream call| API[Third-party API]
    ToolDesc[Tool descriptions] -.->|enter model context| Client
    Server -->|resources| Files[(Files / data)]

    classDef risk fill:#fde8e8,stroke:#c0392b,color:#111;
    T1[MCP-004/005/008<br/>token minted for another audience accepted]:::risk
    T2[MCP-007/016<br/>token pass-through, shared credential]:::risk
    T3[MCP-009<br/>confused deputy via static client ID]:::risk
    T4[MCP-010/011<br/>poisoned or shadowing tool metadata]:::risk
    T5[MCP-001/002/012<br/>excessive tool privilege, no approval]:::risk
    T6[MCP-014<br/>resource boundary escape]:::risk
    T1 -.-> Server
    T2 -.-> API
    T3 -.-> AS
    T4 -.-> ToolDesc
    T5 -.-> Server
    T6 -.-> Files
```

## OAuth checks and the standards behind them

| Concern | Expected configuration | Standard |
|---|---|---|
| Token audience | Accept only tokens whose `aud` is this server's canonical URI | MCP Authorization; RFC 8707; RFC 9068 |
| Token issuer | Validate `iss` against one configured HTTPS issuer | RFC 9068; RFC 9700 |
| Code interception | PKCE required, S256 only | RFC 7636; RFC 9700 |
| Downstream calls | Exchange the inbound token for a downstream-audience token instead of forwarding it | MCP Security Best Practices; RFC 8693 |
| Audience binding at issuance | Clients send `resource`, and the AS mints audience-restricted tokens | RFC 8707 |
| Proxy consent | Per-client consent when a proxy uses a static client ID upstream | MCP Security Best Practices (confused deputy) |

## Adding a check

```python
from mcp_audit.checks import check, MCP_TOOLS

@check("MCP-100", "Tool accepts free-form shell input", "high",
       "Constrain inputs with an enum or pattern; never pass model output to a shell.", (MCP_TOOLS,))
def shell_tools(server):
    for tool in server.tools:
        if "shell" in tool.name or "command" in tool.description.lower():
            yield server.name, f"tool:{tool.name}", "tool appears to execute commands"
```

Yield `(server, target, evidence)`, or add a fourth element to override the severity for that instance. Add positive and negative tests in `tests/test_checks.py`.
