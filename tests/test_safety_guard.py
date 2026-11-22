from safety_guard import DEFAULT_POLICY, evaluate_tool_call


def test_allows_readonly_sqlite_query():
    res = evaluate_tool_call({
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "sqlite3 /var/lib/app/prod_history.db 'SELECT count(*) FROM events;'"},
        }
    }, DEFAULT_POLICY)
    assert res["decision"] == "allow"


def test_blocks_destructive_sql_on_protected_db():
    res = evaluate_tool_call({
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "sqlite3 /var/lib/app/prod_history.db 'DROP TABLE events;'"},
        }
    }, DEFAULT_POLICY)
    assert res["decision"] == "deny"


def test_blocks_stopping_protected_service():
    res = evaluate_tool_call({
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "sudo systemctl stop prod-recorder.service"},
        }
    }, DEFAULT_POLICY)
    assert res["decision"] == "deny"


def test_blocks_direct_file_write_to_protected_db():
    res = evaluate_tool_call({
        "toolCall": {
            "name": "write_file",
            "args": {"Path": "/var/lib/app/prod_history.db"},
        }
    }, DEFAULT_POLICY)
    assert res["decision"] == "deny"


def test_blocks_recursive_grep_on_fuse_mount():
    res = evaluate_tool_call({
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "rg -n keyword /mnt/cloud_drive/docs"},
        }
    }, DEFAULT_POLICY)
    assert res["decision"] == "deny"


def test_blocks_catastrophic_rm_rf_home():
    res = evaluate_tool_call({
        "toolCall": {
            "name": "run_command",
            "args": {"CommandLine": "rm -rf /home/demo"},
        }
    }, DEFAULT_POLICY)
    assert res["decision"] == "deny"
