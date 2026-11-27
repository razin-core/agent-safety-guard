#!/usr/bin/env python3
"""
Programmatic PreToolUse safety guard for AI coding/CLI agents.

Reads a JSON tool-call payload from stdin and returns:
  {"decision": "allow"}
or
  {"decision": "deny", "reason": "..."}

Protects production databases, critical systemd daemons, FUSE mounts,
and root/home directories from accidental destructive tool calls.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any


DEFAULT_POLICY: dict[str, Any] = {
    "protected_services": ["prod-recorder", "telemetry-ingestor"],
    "protected_processes": ["live_recorder.py"],
    "protected_db_paths": [
        "/var/lib/app/prod_history.db",
        "/var/lib/app/prod_history.db-wal",
        "/var/lib/app/prod_history.db-shm",
    ],
    "protected_db_filenames": ["prod_history.db"],
    "protected_fuse_mounts": ["/mnt/cloud_drive", "/mnt/gdrive"],
    "blocked_binaries": [],
}


def load_policy(policy_path: str | None = None) -> dict[str, Any]:
    path = policy_path or os.environ.get("AGENT_SAFETY_POLICY", "").strip()
    policy = {k: list(v) for k, v in DEFAULT_POLICY.items()}
    if path and Path(path).is_file():
        with open(path, "r", encoding="utf-8") as f:
            override = json.load(f)
        for key in policy:
            if isinstance(override.get(key), list):
                policy[key] = [str(item) for item in override[key] if str(item).strip()]
    return policy


def evaluate_tool_call(payload: dict[str, Any], policy: dict[str, Any] | None = None) -> dict[str, str]:
    cfg = policy or load_policy()
    tool_call = payload.get("toolCall") or {}
    tname = str(tool_call.get("name") or "").strip().lower()
    args = tool_call.get("args") or {}

    if tname == "run_command":
        cmd = str(args.get("CommandLine") or args.get("commandLine") or "")
        return _check_command(cmd, cfg)

    if tname in ("write_file", "edit_file"):
        target = str(args.get("Path") or args.get("path") or "").strip()
        for protected in cfg.get("protected_db_paths", []):
            if target.startswith(protected):
                return {
                    "decision": "deny",
                    "reason": f"BLOCKED BY SAFETY-HOOK: direct write to protected database path ({protected}) is forbidden.",
                }

    return {"decision": "allow"}


def _check_command(cmd: str, cfg: dict[str, Any]) -> dict[str, str]:
    if re.search(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(/(\s|$)|/home/[^/\s]+/?(\s|$)|~/(\s|$)|~(\s|$))", cmd):
        return {
            "decision": "deny",
            "reason": "BLOCKED BY SAFETY-HOOK: catastrophic recursive deletion of root or home directory.",
        }

    for svc in cfg.get("protected_services", []):
        pat = re.compile(rf"\bsystemctl\b[^\n;|&]*\b(stop|disable|mask|kill)\b[^\n;|&]*{re.escape(svc)}", re.I)
        if pat.search(cmd):
            return {
                "decision": "deny",
                "reason": f"BLOCKED BY SAFETY-HOOK: stopping or disabling protected service '{svc}' is forbidden.",
            }

    for proc in cfg.get("protected_processes", []):
        pat = re.compile(rf"\b(pkill|killall|kill)\b[^\n;|&]*{re.escape(proc)}", re.I)
        if pat.search(cmd):
            return {
                "decision": "deny",
                "reason": f"BLOCKED BY SAFETY-HOOK: terminating protected process '{proc}' is forbidden.",
            }

    for db_name in cfg.get("protected_db_filenames", []):
        esc = re.escape(db_name)
        sql_pat = re.compile(
            rf"{esc}[^\n;|&]*\b(DROP|DELETE|TRUNCATE|ALTER|UPDATE|INSERT)\b|"
            rf"\b(DROP|DELETE|TRUNCATE)\b[^\n;|&]*{esc}",
            re.I,
        )
        if sql_pat.search(cmd):
            return {
                "decision": "deny",
                "reason": f"BLOCKED BY SAFETY-HOOK: destructive SQL operation on '{db_name}' is forbidden (use read-only mode).",
            }
        rm_pat = re.compile(rf"(\brm\b|\btruncate\b|\bshred\b|>\s*)[^\n;|&]*{esc}", re.I)
        if rm_pat.search(cmd):
            return {
                "decision": "deny",
                "reason": f"BLOCKED BY SAFETY-HOOK: deleting or overwriting '{db_name}' is forbidden.",
            }

    for mount in cfg.get("protected_fuse_mounts", []):
        pat = re.compile(rf"\b(grep|rg|ag|find)\b[^\n;|&]*{re.escape(mount)}", re.I)
        if pat.search(cmd):
            return {
                "decision": "deny",
                "reason": f"BLOCKED BY SAFETY-HOOK: recursive scan on FUSE mount '{mount}' can hang agent sessions.",
            }

    for binary in cfg.get("blocked_binaries", []):
        if re.search(rf"\b{re.escape(binary)}\b", cmd, re.I):
            return {
                "decision": "deny",
                "reason": f"BLOCKED BY SAFETY-HOOK: binary '{binary}' is disallowed by workspace policy.",
            }

    return {"decision": "allow"}


def main() -> None:
    raw = sys.stdin.read()
    if not raw.strip():
        sys.stdout.write(json.dumps({"decision": "allow"}) + "\n")
        return
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        if os.environ.get("AGENT_SAFETY_FAIL_CLOSED", "").lower() in ("1", "true", "yes"):
            sys.stdout.write(json.dumps({"decision": "deny", "reason": "BLOCKED BY SAFETY-HOOK: malformed JSON input."}) + "\n")
        else:
            sys.stdout.write(json.dumps({"decision": "allow"}) + "\n")
        return

    result = evaluate_tool_call(payload)
    sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
