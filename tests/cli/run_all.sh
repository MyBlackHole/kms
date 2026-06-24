#!/usr/bin/env bash
# kms-cli 全功能测试运行器
# 依次执行所有测试脚本

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="${BINARY:-target/debug/kms-server}"
CLI="${CLI:-target/debug/kms-cli}"
TOTAL_PASS=0
TOTAL_FAIL=0
FAILED_SCRIPTS=0

export BINARY CLI
export KMS_HOST="${KMS_HOST:-127.0.0.1}"
export KMS_PORT="${KMS_PORT:-28443}"
export ADMIN_TOKEN="${ADMIN_TOKEN:-test-admin-token}"
export TEST_DIR="${TEST_DIR:-/tmp/kms-cli-test}"

echo "============================================"
echo "  kms-cli 全功能测试"
echo "  BINARY=$BINARY"
echo "  CLI=$CLI"
echo "  SERVER=http://${KMS_HOST}:${KMS_PORT}"
echo "============================================"
echo ""

# 先确保编译
if [ ! -f "$BINARY" ] || [ ! -f "$CLI" ]; then
    echo "编译二进制..."
    cargo build 2>&1 || exit 1
fi

TESTS=(
    test_local.sh      # 本地命令（不依赖服务端）
    test_no_auth.sh    # 无 token 场景
    test_auth_full.sh  # 完整认证
    test_output.sh     # 输出格式
)

for test in "${TESTS[@]}"; do
    TEST_SCRIPT="$SCRIPT_DIR/$test"
    if [ ! -f "$TEST_SCRIPT" ]; then
        echo "⚠️ 跳过: $test (不存在)"
        continue
    fi
    echo ""
    echo "────────── $test ──────────"
    # 每个脚本有自己的 PASS/FAIL 计数
    # 通过 source 执行以继承 trap/cleanup
    (
        cd "$SCRIPT_DIR" 2>/dev/null || true
        bash "$TEST_SCRIPT"
    )
    RET=$?
    # 从输出中提取通过/失败计数
    # 这里简单处理：RET=0 视为全部通过
    if [ "$RET" -eq 0 ]; then
        :  # 通过
    else
        FAILED_SCRIPTS=$((FAILED_SCRIPTS + 1))
    fi
done

echo ""
echo "============================================"
if [ "$FAILED_SCRIPTS" -eq 0 ]; then
    echo "🎉 全部测试套件通过"
else
    echo "❌ $FAILED_SCRIPTS 个测试套件失败"
fi
echo "============================================"
exit "$FAILED_SCRIPTS"
