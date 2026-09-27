# Inventory schema

An inventory is a JSON object with a `servers` list. It describes MCP servers *as deployed*. It is defined by this project for offline review and is not an MCP wire format. Unknown top-level keys, such as `_comment`, are ignored. Unknown or mistyped values in known fields are rejected with the file and field path.

```json
{
  "inventory": "team-agents-prod",
  "servers": [
    {
      "name": "tickets",
      "transport": "streamable-http",
      "url": "https://tickets-mcp.example.test/mcp",
      "role": "resource_server",
      "auth": {
        "type": "oauth2",
        "issuer": "https://auth.example.test",
        "expected_issuer": "https://auth.example.test",
        "validate_issuer": true,
        "validate_audience": true,
        "accepted_audiences": ["https://tickets-mcp.example.test/mcp"],
        "pkce_required": true,
        "pkce_methods": ["S256"],
        "resource_indicators_required": true,
        "token_passthrough": false,
        "downstream_auth": "token_exchange",
        "static_client_id": false,
        "dynamic_client_registration": false,
        "per_client_consent": true
      },
      "tools": [
        {
          "name": "delete_ticket",
          "description": "Permanently delete a ticket.",
          "scopes": ["tickets:delete"],
          "annotations": {"readOnlyHint": false, "destructiveHint": true},
          "requires_approval": true
        }
      ],
      "resources": [{"uri": "tickets://acme/queue/security", "name": "Security queue"}],
      "allowed_roots": ["tickets://acme/"]
    }
  ]
}
```

## Server fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | yes | Unique within the inventory |
| `transport` | `stdio` \| `streamable-http` \| `sse` | yes | `url` is required for remote transports |
| `url` | string | remote only | The server's canonical URI, which is also its expected token audience |
| `role` | `resource_server` \| `proxy` | no | `proxy` means the server calls third-party APIs on the user's behalf |
| `auth` | object | no | Defaults to `{"type": "none"}` |
| `tools` | list | no | See below |
| `resources` | list of `{uri, name?}` | no | |
| `allowed_roots` | list of URI prefixes | no | The access boundary for resources |

## `auth` fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `type` | `oauth2` \| `static_token` \| `none` | `none` | How callers authenticate |
| `issuer`, `expected_issuer` | string | — | Issuer that mints tokens, and the issuer the server is configured to trust |
| `validate_issuer`, `validate_audience` | bool | false | Whether the server enforces `iss` and `aud` |
| `accepted_audiences` | list | [] | Audiences the server accepts |
| `pkce_required`, `pkce_methods` | bool, list | false, [] | PKCE enforcement and allowed methods |
| `resource_indicators_required` | bool | false | RFC 8707 `resource` parameter enforced |
| `token_passthrough` | bool | false | Inbound token is forwarded downstream |
| `downstream_auth` | `token_exchange` \| `passthrough` \| `static_credential` \| `none` | `none` | How the server authenticates to downstream APIs |
| `static_client_id`, `dynamic_client_registration`, `per_client_consent` | bool | false | Proxy consent model (confused-deputy inputs) |

## Tool fields

| Field | Type | Notes |
|---|---|---|
| `name` | string | Required |
| `description` | string | The text the model sees, checked for poisoning indicators |
| `scopes` | list | OAuth scopes the tool's credential carries |
| `annotations` | object | MCP tool annotations, such as `readOnlyHint` and `destructiveHint` |
| `requires_approval` | bool | Whether the host or gateway enforces human approval before the call |
