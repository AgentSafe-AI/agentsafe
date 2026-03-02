# AgentSentry

[![CI](https://github.com/AgentSafe-AI/agentsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentSafe-AI/agentsentry/actions/workflows/ci.yml)
[![Security](https://github.com/AgentSafe-AI/agentsentry/actions/workflows/security.yml/badge.svg)](https://github.com/AgentSafe-AI/agentsentry/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/AgentSafe-AI/agentsentry/branch/main/graph/badge.svg)](https://codecov.io/gh/AgentSafe-AI/agentsentry)
[![Go Report Card](https://goreportcard.com/badge/github.com/AgentSafe-AI/agentsentry)](https://goreportcard.com/report/github.com/AgentSafe-AI/agentsentry)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.24-00ADD8.svg)](go.mod)

**The security trust layer for MCP servers, OpenAI tools, and AI Skills.**

AgentSentry scans tool definitions *before* an AI agent runs them — blocking prompt injection, over-permission, scope mismatches, and known CVEs at the source.

---

## Scan catalog

| Rule | ID | Purpose |
|------|----|---------|
| 🛡️ **Tool Poisoning** | AS-001 | Detect prompt injection hidden in tool descriptions (`ignore previous instructions`, `system:`, `<INST>`) |
| 🔑 **Permission Surface** | AS-002 | Flag tools declaring `exec`, `network`, `db`, or `fs` beyond their stated purpose; detect over-broad input schemas |
| 📐 **Scope Mismatch** | AS-003 | Catch name vs. permission contradictions (`read_config` + `exec` permission) |
| 📦 **Supply Chain (CVE)** | AS-004 | Query the [OSV API](https://osv.dev) for known vulnerabilities in a tool's declared dependencies |

## Risk grades

| Grade | Score | Gateway action |
|-------|-------|----------------|
| **A** | 0–10 | `ALLOW` |
| **B** | 11–25 | `ALLOW` + rate limit |
| **C** | 26–50 | `REQUIRE_APPROVAL` |
| **D** | 51–75 | `REQUIRE_APPROVAL` |
| **F** | 76+ | `BLOCK` |

Score = `Σ (weight × findings)` — weights: Critical **25** · High **15** · Medium **8** · Low **3**

---

## Quick integration

**CLI**
```bash
# install (macOS / Linux — auto-detects arch)
curl -L https://github.com/AgentSafe-AI/agentsentry/releases/latest/download/agentsentry_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed s/x86_64/amd64/) \
  -o /usr/local/bin/agentsentry && chmod +x /usr/local/bin/agentsentry

agentsentry scan --protocol mcp --input tools.json
```

**GitHub Actions** — add one step to your CI:
```yaml
- name: AgentSentry scan
  run: agentsentry scan --protocol mcp --input testdata/tools.json --fail-on block
```

**MCP meta-scanner** — let Claude scan tools for you:
```bash
agentsentry-mcp   # stdio transport, exposes agentsentry_scan to any MCP client
```

**Docker**
```bash
docker run --rm -v $(pwd)/tools.json:/tools.json \
  ghcr.io/agentsafe-ai/agentsentry:latest scan --protocol mcp --input /tools.json
```

---

## Example output

```json
{
  "policies": [
    {
      "ToolName": "run_shell",
      "Action": "BLOCK",
      "Score": {
        "Score": 80, "Grade": "F",
        "Issues": [
          { "RuleID": "AS-001", "Severity": "CRITICAL", "Code": "TOOL_POISONING" },
          { "RuleID": "AS-002", "Severity": "HIGH",     "Code": "HIGH_RISK_PERMISSION" },
          { "RuleID": "AS-004", "Severity": "CRITICAL", "Code": "SUPPLY_CHAIN_CVE",
            "Description": "CVE-2024-1234 in lodash@4.17.15: Prototype pollution" }
        ]
      }
    }
  ],
  "summary": { "total": 3, "allowed": 1, "requireApproval": 1, "blocked": 1 }
}
```

---

## Architecture

```
pkg/adapter/    Protocol converters → UnifiedTool  (MCP · OpenAI · Skills · A2A)
pkg/analyzer/   Scan rules AS-001–AS-004, Engine API, weighted scoring
pkg/gateway/    RiskScore → GatewayPolicy  (ALLOW · REQUIRE_APPROVAL · BLOCK)
pkg/model/      Core types: UnifiedTool · RiskScore · GatewayPolicy
pkg/storage/    SQLite persistence for scan results (modernc.org/sqlite, no CGo)
cmd/agentsentry/ CLI entry point
cmd/mcpserver/  MCP meta-scanner server
```

## Development

```bash
make test           # race detector — must pass before every commit
make lint           # golangci-lint
make coverage       # ≥60% enforced on pkg/ + internal/
make cross-compile  # linux · darwin · windows binaries in dist/
```

TDD workflow: RED → GREEN → REFACTOR. See [`.cursor/skills/tdd-go/SKILL.md`](.cursor/skills/tdd-go/SKILL.md).

---

## Roadmap

- **v0.2** — OpenAI Function Calling · Markdown Skills · A2A adapters
- **v0.3** — REST API · certified JSON/PDF reports · ToolTrust Directory sync
- **v0.4** — K8s + gVisor sandbox for dynamic behavioural analysis
- **v0.5** — MCP/Skills Security Directory (public website, searchable by grade)
- **v1.0** — Browser extension · webhook gateway · signed scan certificates

---

## Contributing

PRs welcome — run `make test` first.

## License

[MIT](LICENSE) © 2026 AgentSafe-AI
