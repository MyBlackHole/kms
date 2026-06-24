#!/usr/bin/env bash
# 完整认证测试（带 token）
# 测试: health + token, tokens CRUD, login/logout, cert-info

source "$(dirname "$0")/lib.sh"

echo "=== 完整认证测试 ==="
echo "  CLI: $CLI"
echo "  服务: http://${KMS_HOST}:${KMS_PORT}"

start_server || exit 1

CLI_ARGS="--server http://${KMS_HOST}:${KMS_PORT} --token ${ADMIN_TOKEN}"

# ─── health（带 token） ───
step "health（带 token）"
OUT=$("$CLI" $CLI_ARGS health 2>&1)
if echo "$OUT" | grep -q "status: ok"; then
    pass "健康检查"
else
    fail "health 失败: $OUT"
fi

# ─── auth tokens list（空列表） ───
step "auth tokens list"
OUT=$("$CLI" $CLI_ARGS auth tokens list 2>&1)
if [ $? -eq 0 ]; then
    pass "token 列表"
else
    fail "auth tokens list 失败: $OUT"
fi

# ─── auth tokens create ───
step "auth tokens create"
OUT=$("$CLI" $CLI_ARGS auth tokens create "full-test-token" 2>&1)
if echo "$OUT" | grep -q "创建 Token:"; then
    TOKEN_ID=$(echo "$OUT" | grep "ID:" | sed 's/.*ID: //')
    pass "创建 token: $TOKEN_ID"
else
    fail "auth tokens create 失败: $OUT"
    TOKEN_ID=""
fi

# ─── auth tokens delete ───
if [ -n "$TOKEN_ID" ]; then
    step "auth tokens delete"
    OUT=$("$CLI" $CLI_ARGS auth tokens delete "$TOKEN_ID" 2>&1)
    if echo "$OUT" | grep -q "Token 已吊销:"; then
        pass "吊销 token: $TOKEN_ID"
    else
        fail "auth tokens delete 失败: $OUT"
    fi
fi

# ─── auth login ───
step "auth login（带 token）"
OUT=$("$CLI" $CLI_ARGS auth login "admin" 2>&1)
if echo "$OUT" | grep -q "会话:"; then
    pass "登录成功"
else
    fail "auth login 失败: $OUT"
fi

# ─── auth cert-info ───
step "auth cert-info"
OUT=$("$CLI" $CLI_ARGS auth cert-info 2>&1)
if [ $? -eq 0 ]; then
    pass "证书信息"
else
    fail "auth cert-info 失败: $OUT"
fi

# ─── auth logout ───
step "auth logout"
OUT=$("$CLI" $CLI_ARGS auth totp-setup "admin" 2>&1)
SESSION_ID=$(echo "$OUT" | grep "会话:" | sed 's/.*会话: //')
if [ -n "$SESSION_ID" ]; then
    OUT=$("$CLI" $CLI_ARGS auth logout --session "$SESSION_ID" 2>&1)
    if echo "$OUT" | grep -q "已登出"; then
        pass "登出成功"
    else
        fail "auth logout 失败: $OUT"
    fi
else
    fail "无法获取 session_id"
fi

stop_server
summary
