# AGENTS.md — zeek-mcp-server

## Project Scope
MCP server for Zeek-based PCAP analysis, log querying, custom detection script execution, and anomaly summarization.

## Repository Signals
- Detected stack/profile: python, mcp, docker, network-security
- Latest repository commit date: `2026-02-12`

### Key Local Paths
- `server.py`
- `zeek_parser.py`
- `scripts/`
- `pcaps/`
- `Dockerfile`
- `pyproject.toml`

## Recommended Agents (from ~/.claude)
| Agent | Why it applies |
|---|---|
| `python-development` | Async subprocess orchestration and parser behavior. |
| `mcp-integration` | MCP tool interfaces and response contracts. |
| `security-reviewer` | Path traversal controls and bounded execution behavior. |
| `network-noc` | Operational interpretation of connection/anomaly outputs. |
| `code-reviewer` | Final consistency and regression checks. |

## Working Rules
Use these related global rules for this repository:
- `~/.claude/rules/git-workflow.md`
- `~/.claude/rules/security.md`
- `~/.claude/rules/coding-style.md`

## Preferred Commands
- Build container image: `docker build -t zeek-mcp-server .`
- Run in Docker with mounted data: `docker run --rm -it -v "$(pwd)/pcaps:/app/pcaps" -v "$(pwd)/scripts:/app/scripts" -v "$(pwd)/output:/app/output" zeek-mcp-server`
- Local syntax sanity check: `python -m py_compile server.py zeek_parser.py`
- Script entrypoint (if environment has dependencies and Zeek installed): `python server.py`

## Quality Gates
- Keep `_safe_path()` protections intact for all user-supplied paths.
- Preserve timeout and size-bound controls (`ZEEK_TIMEOUT`, `ZEEK_MAX_PCAP_MB`) when extending analysis flows.
- Any new tool must return consistent JSON envelopes and avoid unbounded log output.

## Security and Secrets
- Treat uploaded PCAPs as sensitive forensic material; do not commit captures or derived sensitive artifacts.
- Do not relax path traversal protections or execute arbitrary scripts outside approved directories.
- Keep runtime paths and resource limits configurable by environment variables, not hardcoded host paths.

## Project-Specific Notes
- `scripts/*.zeek` are detection assets; changes should include validation against representative PCAPs.
- Zeek binary availability is required for functional execution; Docker image is the primary reproducible runtime path.
- No direct repo mapping found under `~/.claude/projects`; fallback uses relevant global agent/rule guidance only.

## Maintenance
- Last synchronized: `2026-02-13`
- Recency basis: latest repo commit `2026-02-12`
- Update this file when MCP tools, detection scripts, or runtime constraints change.

## Sources Used
- `server.py`
- `zeek_parser.py`
- `scripts/dns-exfiltration.zeek`
- `Dockerfile`
- `pyproject.toml`
- `~/.claude/agents/python-development.md`
- `~/.claude/agents/mcp-integration.md`
- `~/.claude/agents/security-reviewer.md`
- `~/.claude/agents/network-noc.md`
- `~/.claude/agents/code-reviewer.md`
- `~/.claude/rules/git-workflow.md`
- `~/.claude/rules/security.md`
- `~/.claude/rules/coding-style.md`
