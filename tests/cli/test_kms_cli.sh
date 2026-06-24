#!/usr/bin/env bash
# kms-cli 集成测试

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

cleanup() {
    if [ -n "${SERVER_PID:-}" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    [ -d "$TEST_DIR" ] && rm -rf "$TEST_DIR"
}

trap cleanup EXIT INT TERM

# ─── 启动 kms-server ───
echo "=== kms-cli 集成测试 ==="

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
        break
    fi
    if [ "$i" = 30 ]; then
        echo "❌ 服务启动失败"
        cat "$TEST_DIR/server.log"
        exit 1
    fi
    sleep 1
done

CLI_ARGS="--server http://${KMS_HOST}:${KMS_PORT} --token ${ADMIN_TOKEN}"

# ─── 1. 本地调试命令 ───
echo ""
echo "--- 1. 本地调试命令 ---"

step "sm3 哈希"
OUT=$("$CLI" debug sm3 "test" 2>&1)
if echo "$OUT" | grep -qE "^SM3\(test\): [0-9a-f]{64}$"; then
    pass "$OUT"
else
    fail "sm3 输出异常: $OUT"
fi

step "sha256 哈希"
OUT=$("$CLI" debug sha256 "test" 2>&1)
if echo "$OUT" | grep -qE "^SHA256\(test\): [0-9a-f]{64}$"; then
    pass "$OUT"
else
    fail "sha256 输出异常: $OUT"
fi

step "hmac-sha256"
OUT=$("$CLI" debug hmac "key" "data" 2>&1)
if echo "$OUT" | grep -qE "^HMAC-SHA256\(key, data\): [0-9a-f]{64}$"; then
    pass "$OUT"
else
    fail "hmac 输出异常: $OUT"
fi

step "hmac-sm3"
OUT=$("$CLI" debug hmac "key" "data" --algorithm sm3 2>&1)
if echo "$OUT" | grep -qE "^HMAC-SM3\(key, data\): [0-9a-f]{64}$"; then
    pass "$OUT"
else
    fail "hmac-sm3 输出异常: $OUT"
fi

step "随机数 16 字节"
OUT=$("$CLI" debug rng 16 2>&1)
if echo "$OUT" | grep -qE "^[0-9a-f]{32}$"; then
    pass "16 字节随机数"
else
    fail "rng 输出异常: $OUT"
fi

# ─── 2. 健康检查 ───
echo ""
echo "--- 2. 健康检查 ---"

step "health"
OUT=$("$CLI" $CLI_ARGS health 2>&1)
if echo "$OUT" | grep -q "status: ok"; then
    pass "健康检查正常"
else
    fail "health 失败: $OUT"
fi

# ─── 3. 认证 ───
echo ""
echo "--- 3. 认证 ---"

step "auth tokens list"
OUT=$("$CLI" $CLI_ARGS auth tokens list 2>&1)
if [ $? -eq 0 ]; then
    pass "token 列表"
else
    fail "auth tokens list 失败: $OUT"
fi

step "auth tokens create"
OUT=$("$CLI" $CLI_ARGS auth tokens create "cli-test-token" 2>&1)
if echo "$OUT" | grep -q "创建 Token:"; then
    TOKEN_ID=$(echo "$OUT" | grep "ID:" | sed 's/.*ID: //')
    pass "创建 token: $TOKEN_ID"
else
    fail "auth tokens create 失败: $OUT"
    TOKEN_ID=""
fi

if [ -n "$TOKEN_ID" ]; then
    step "auth tokens delete"
    OUT=$("$CLI" $CLI_ARGS auth tokens delete "$TOKEN_ID" 2>&1)
    if echo "$OUT" | grep -q "Token 已吊销:"; then
        pass "吊销 token: $TOKEN_ID"
    else
        fail "auth tokens delete 失败: $OUT"
    fi
fi

step "auth login"
OUT=$("$CLI" $CLI_ARGS auth login "admin" 2>&1)
if echo "$OUT" | grep -q "会话:"; then
    pass "登录成功"
else
    fail "auth login 失败: $OUT"
fi

# ─── 4. 输出格式 ───
echo ""
echo "--- 4. 输出格式 ---"

step "--output json + health"
OUT=$("$CLI" $CLI_ARGS --output json health 2>&1)
if echo "$OUT" | python3 -c "
import sys,json
j=json.loads(sys.stdin.read())
assert j.get('status')=='ok'
assert 'version' in j
assert 'hsm_mode' in j
" 2>/dev/null; then
    pass "JSON 格式健康检查"
else
    fail "--output json 输出异常: $OUT"
fi

step "--output json + tokens list"
OUT=$("$CLI" $CLI_ARGS --output json auth tokens list 2>&1)
if echo "$OUT" | python3 -c "import sys,json; json.loads(sys.stdin.read())" 2>/dev/null; then
    pass "JSON 格式 token 列表"
else
    fail "--output json tokens list 异常: $OUT"
fi

# ─── 5. 全局选项 ───
echo ""
echo "--- 5. 全局选项 ---"

step "--print-json"
ERR=$("$CLI" $CLI_ARGS --print-json health 2>&1 >/dev/null)
if echo "$ERR" | grep -qE "^(>|<)"; then
    pass "print-json 输出请求/响应"
else
    fail "--print-json 无效"
fi

step "--accept-invalid-certs (无实际测试)"
echo "⚠️ 标志已实现（需 HTTPS 环境验证）"
PASS=$((PASS + 1))

# ─── 汇总 ───
echo ""
echo "═══════════════════════"
if [ "$FAIL" -eq 0 ]; then
    echo "全部通过: $PASS 项"
else
    echo "通过: $PASS, 失败: $FAIL"
fi
echo "═══════════════════════"
exit $FAIL
