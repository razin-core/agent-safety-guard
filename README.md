# agent-safety-guard

[![CI](https://github.com/razin-core/agent-safety-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/razin-core/agent-safety-guard/actions/workflows/ci.yml)

Lightweight, zero-dependency **`PreToolUse` programmatic safety hook** for CLI AI agents (Antigravity CLI / Claude Code / MCP tool gateways).

Prompt instructions alone are soft guardrails. This hook enforces hard, deterministic policy checks **before** a tool call executes on the host:

- Blocks `systemctl stop/disable/mask/kill` and `pkill/kill` on protected background daemons.
- Blocks destructive SQL (`DROP`, `DELETE`, `TRUNCATE`, `UPDATE`, `INSERT`, `ALTER`) and file overwrites/removals against protected SQLite databases while allowing read-only queries.
- Blocks direct `write_file` / `edit_file` calls targeting protected database paths.
- Blocks recursive `grep`/`rg`/`find` scans on slow FUSE mounts (e.g., `rclone` Google Drive).
- Blocks catastrophic `rm -rf /` or `rm -rf ~` commands.

## Usage

Configure your agent runtime `PreToolUse` hook to pipe tool-call JSON into `safety_guard.py` and optionally point `AGENT_SAFETY_POLICY` to a custom JSON policy file (see `policy.example.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "run_command|write_file|edit_file",
        "hooks": [{ "type": "command", "command": "python3 /path/to/safety_guard.py" }]
      }
    ]
  }
}
```

### Contract & Failure Mode
- **Input (`stdin`):** JSON tool-call payload (`{"toolCall": {"name": "...", "args": {...}}}`).
- **Output (`stdout`):** `{"decision": "allow"}` or `{"decision": "deny", "reason": "..."}`.
- **Malformed JSON:** Fails open by default so truncated stdin does not brick an interactive session; set `AGENT_SAFETY_FAIL_CLOSED=1` to deny malformed payloads.

```bash
echo '{"toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf ~/"}}}' | python3 safety_guard.py
# -> {"decision": "deny", "reason": "BLOCKED BY SAFETY-HOOK: ..."}
```

## Tests
```bash
pytest -q
```
