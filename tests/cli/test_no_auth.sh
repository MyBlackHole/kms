#!/usr/bin/env bash
# 无 token 模式测试（新功能验证）
# 测试: health（无 token）、auth login（无 token）
# 不需要设置 KMS_TOKEN，只传 --server

source "$(dirname "$0")/lib.sh"

echo "=== 无 token 模式测试 ==="
echo "  CLI: $CLI"
echo "  服务: http://${KMS_HOST}:${KMS_PORT}"

start_server || exit 1

SERVER_ARGS="--server http://${KMS_HOST}:${KMS_PORT}"

# ─── health（无 token） ───
step "health（无 token）"
OUT=$("$CLI" $SERVER_ARGS health 2>&1)
if echo "$OUT" | grep -q "status: ok"; then
    pass "健康检查（无 token）"
else
    fail "health 失败: $OUT"
fi

# ─── auth login（无 token） ───
step "auth login（无 token）"
OUT=$("$CLI" $SERVER_ARGS auth login "admin" 2>&1)
if echo "$OUT" | grep -q "会话:"; then
    pass "登录成功（无 token）"
    SESSION_ID=$(echo "$OUT" | grep "会话:" | sed 's/.*会话: //')
    echo "  session: $SESSION_ID"
else
    fail "auth login 失败: $OUT"
fi

stop_server
summary
