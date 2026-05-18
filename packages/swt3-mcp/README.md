# @tenova/swt3-mcp

> Listed on the [MCP Registry](https://github.com/modelcontextprotocol/servers) as `io.tenova/swt3-witness`

MCP server for the SWT3 AI Witness protocol. Adds cryptographic compliance attestation to any MCP-compatible AI agent.

## Why This Exists

In 2026, attackers exploited MCP configuration injection in Flowise to achieve arbitrary code execution across thousands of AI workflow instances. A compromised third-party AI tool (Context.ai) pivoted into Vercel's internal systems. Microsoft disclosed RCE vulnerabilities in Semantic Kernel where a single prompt could execute commands on the host. 65% of firms reported AI agent security incidents. Only 14.4% of agents go live with full security approval.

Every tool call your agent makes is an attack surface. This server witnesses those calls, enforces tool-level policy gates, and produces a cryptographic evidence chain that proves what happened. If an agent is compromised, the audit trail is immutable. If a tool call violates policy, the gate blocks it before execution.

## Zero-config start

```bash
npx @tenova/swt3-mcp
```

That's it. No account, no API key, no configuration. The server starts in demo mode and mints local witness anchors immediately.

When you're ready to persist anchors to the SWT3 ledger, use the `signup` tool from within your agent conversation -- no need to leave your editor.

## Setup

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "swt3": {
      "command": "npx",
      "args": ["@tenova/swt3-mcp"]
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "swt3": {
      "command": "npx",
      "args": ["@tenova/swt3-mcp"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add swt3 -- npx @tenova/swt3-mcp
```

## How it works

```
1. Add server to your MCP config         (one line)
2. Start using AI tools as normal         (zero code changes)
3. Ask your agent to witness inferences   (anchors minted locally)
4. Use the signup tool when ready          (free account, never leave your editor)
5. Anchors persist to the SWT3 ledger     (cryptographic compliance trail)
```

## Three modes

| Mode | Config needed | What happens |
|------|--------------|--------------|
| **Demo** | Nothing | Local-only anchors, instant start |
| **API key only** | `SWT3_API_KEY` | Tenant auto-resolved, anchors persisted |
| **Full config** | `SWT3_API_KEY` + `SWT3_TENANT_ID` | Explicit tenant, anchors persisted |

## Tools

### witness_inference

Mint a cryptographic witness anchor for an AI inference.

```
model_id: "gpt-4o"            # required -- everything else is optional
prompt: "What is 2+2?"        # hashed locally, never sent to server
response: "4"                 # hashed locally, never sent to server
```

Returns verdict (PASS/FAIL), anchor token, and verification URL.

### verify_anchor

Verify the cryptographic integrity of an existing anchor.

```
token: "SWT3-E-VULTR-AI-AIINF1-PASS-1700000000-96b7d56c0245"
```

### list_procedures

Browse the UCT procedure registry. 151+ compliance controls.

```
namespace: "AI"               # optional filter
```

### check_posture

Check current tenant compliance posture. No arguments.

### signup

Get a signup link to create a free account. No credentials pass through the AI.

```
framework: "EU-AI-ACT"        # optional (default: NIST-800-53)
```

Returns a browser URL. Complete signup there, copy your API key, add it to your MCP config.

## Environment variables (optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `SWT3_API_KEY` | demo mode | API key (starts with `axm_`) |
| `SWT3_TENANT_ID` | auto-resolved | Tenant ID (resolved from API key if omitted) |
| `SWT3_ENDPOINT` | `https://sovereign.tenova.io` | Witness endpoint |
| `SWT3_CLEARING_LEVEL` | `1` | Data clearing (0=analytics, 1=standard, 2=sensitive, 3=classified) |
| `SWT3_AGENT_ID` | | Agent identity for AI-ID.1 |
| `SWT3_SIGNING_KEY` | | HMAC-SHA256 signing key (register server-side for validation) |

## Clearing levels

| Level | What leaves the wire |
|-------|---------------------|
| 0 | All metadata |
| 1 | Hashes + model ID + context |
| 2 | Hashes + model ID only |
| 3 | Factors only, model ID hashed |

Raw prompt and response text never leaves your machine at any clearing level.

## Resources

- `swt3://registry/procedures` -- Full UCT procedure catalog
- `swt3://health` -- Service health status

## License

Apache 2.0. Patent pending.

Built by [TeNova](https://tenova.io).
