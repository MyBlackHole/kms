#!/usr/bin/env bash
# kms-cli 测试共享库

KMS_HOST="${KMS_HOST:-127.0.0.1}"
KMS_PORT="${KMS_PORT:-28443}"
ADMIN_TOKEN="${ADMIN_TOKEN:-test-admin-token}"
BINARY="${BINARY:-target/debug/kms-server}"
CLI="${CLI:-target/debug/kms-cli}"
TEST_DIR="${TEST_DIR:-/tmp/kms-cli-test}"

PASS=0
FAIL=0
STEP=0

step() {
    STEP=$((STEP + 1))
    printf "  [STEP %d] %s ... " "$STEP" "$1"
}

pass() {
    echo "✅ $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "❌ $1"
    FAIL=$((FAIL + 1))
}

start_server() {
    lsof -ti "tcp:${KMS_PORT}" 2>/dev/null | xargs kill 2>/dev/null || true
    sleep 1
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR/data"

    cat > "$TEST_DIR/config.toml" << EOF
[server]
host = "$KMS_HOST"
port = $KMS_PORT
workers = 2

[database]
url = "sqlite://${TEST_DIR}/data/kms.db?mode=rwc"
max_connections = 5
run_migrations = true

[crypto]
kek_path = "${TEST_DIR}/data/master.key"
key_rotation_days = 365
max_key_versions = 10

[audit]
log_path = "${TEST_DIR}/data/audit.log"
retention_days = 365
enable_chain = true

[hsm]
mode = "software"

[auth]
admin_token = "$ADMIN_TOKEN"

[policy]
enable_rbac = true
enforce_https = false
EOF

    "$BINARY" --config "$TEST_DIR/config.toml" > "$TEST_DIR/server.log" 2>&1 &
    SERVER_PID=$!

    for i in $(seq 1 30); do
        if curl -s "http://${KMS_HOST}:${KMS_PORT}/api/v1/health" > /dev/null 2>&1; then
            echo "  服务就绪 (${i}s)"
            return 0
        fi
        sleep 1
    done

    echo "❌ 服务启动失败"
    cat "$TEST_DIR/server.log"
    return 1
}

stop_server() {
    if [ -n "${SERVER_PID:-}" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    [ -d "$TEST_DIR" ] && rm -rf "$TEST_DIR"
}

summary() {
    echo ""
    echo "═══════════════════════"
    if [ "$FAIL" -eq 0 ]; then
        echo "全部通过: $PASS 项"
    else
        echo "通过: $PASS, 失败: $FAIL"
    fi
    echo "═══════════════════════"
    return "$FAIL"
}
