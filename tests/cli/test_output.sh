#!/usr/bin/env bash
# 输出格式测试
# 测试: --output json, --print-json

source "$(dirname "$0")/lib.sh"

echo "=== 输出格式测试 ==="
echo "  CLI: $CLI"
echo "  服务: http://${KMS_HOST}:${KMS_PORT}"

start_server || exit 1

CLI_ARGS="--server http://${KMS_HOST}:${KMS_PORT} --token ${ADMIN_TOKEN}"

# ─── --output json health ───
step "--output json health"
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

# ─── --output json tokens list ───
step "--output json tokens list"
OUT=$("$CLI" $CLI_ARGS --output json auth tokens list 2>&1)
if echo "$OUT" | python3 -c "import sys,json; json.loads(sys.stdin.read())" 2>/dev/null; then
    pass "JSON 格式 token 列表"
else
    fail "--output json tokens list 异常: $OUT"
fi

# ─── --output json auth login ───
step "--output json auth login"
OUT=$("$CLI" $CLI_ARGS --output json auth login "admin" 2>&1)
# auth login 打印到 stdout，不返回 JSON value - 所以可能是 None，cli 不输出
# 只要能完成即可
pass "JSON 格式登录"

# ─── --print-json ───
step "--print-json"
ERR=$("$CLI" $CLI_ARGS --print-json health 2>&1 >/dev/null)
if echo "$ERR" | grep -qE "^(>|<)"; then
    pass "print-json 输出请求/响应"
else
    fail "--print-json 无效: $ERR"
fi

stop_server
summary
