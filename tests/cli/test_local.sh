#!/usr/bin/env bash
# 本地命令测试（不依赖服务端）
# 测试: debug sm3/sha256/rng/hmac, auth totp-code, server hash-self

source "$(dirname "$0")/lib.sh"

echo "=== 本地命令测试 ==="

# ─── debug sm3 ───
step "debug sm3"
OUT=$("$CLI" debug sm3 "test" 2>&1)
if echo "$OUT" | grep -qE "^SM3\(test\): [0-9a-f]{64}$"; then
    pass "$OUT"
else
    fail "sm3 输出异常: $OUT"
fi

# ─── debug sha256 ───
step "debug sha256"
OUT=$("$CLI" debug sha256 "test" 2>&1)
if echo "$OUT" | grep -qE "^SHA256\(test\): [0-9a-f]{64}$"; then
    pass "$OUT"
else
    fail "sha256 输出异常: $OUT"
fi

# ─── debug rng 16 ───
step "debug rng 16"
OUT=$("$CLI" debug rng 16 2>&1)
if echo "$OUT" | grep -qE "^[0-9a-f]{32}$"; then
    pass "16 字节随机数"
else
    fail "rng 输出异常: $OUT"
fi

# ─── debug hmac sha256 ───
step "debug hmac sha256"
OUT=$("$CLI" debug hmac "key" "data" 2>&1)
if echo "$OUT" | grep -qE "^HMAC-SHA256\(key, data\): [0-9a-f]{64}$"; then
    pass "$OUT"
else
    fail "hmac-sha256 输出异常: $OUT"
fi

# ─── debug hmac sm3 ───
step "debug hmac sm3"
OUT=$("$CLI" debug hmac "key" "data" --algorithm sm3 2>&1)
if echo "$OUT" | grep -qE "^HMAC-SM3\(key, data\): [0-9a-f]{64}$"; then
    pass "$OUT"
else
    fail "hmac-sm3 输出异常: $OUT"
fi

# ─── auth totp-code（本地 TOTP 计算） ───
step "auth totp-code"
OUT=$("$CLI" auth totp-code "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" 2>&1)
if echo "$OUT" | grep -qE "^[0-9]{6}$"; then
    pass "TOTP 码: $OUT"
else
    fail "totp-code 输出异常: $OUT"
fi

# ─── server hash-self ───
step "server hash-self"
OUT=$("$CLI" server hash-self 2>&1)
if echo "$OUT" | grep -qE "^[0-9a-f]{64}"; then
    pass "自身哈希"
else
    fail "hash-self 输出异常: $OUT"
fi

summary
