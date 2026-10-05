#!/usr/bin/env bash
# 零信任设备网关本地端到端冒烟脚本（仅依赖 curl + python3，无外部服务/凭据）。
# 用法：先在另一个终端执行 mvn spring-boot:run，再运行本脚本。
set -euo pipefail

BASE=${BASE:-http://localhost:8080}
DEVICE_ID="demo-device-001"
MEASUREMENT="a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566778899aabbccddeeff00"

req() { # METHOD PATH [JSON_BODY]
  local method=$1 path=$2 body=${3:-}
  if [[ -n $body ]]; then
    curl -sS -X "$method" -H 'Content-Type: application/json' -d "$body" "$BASE$path"
  else
    curl -sS -X "$method" "$BASE$path"
  fi
}

field() { python3 -c "import sys,json; print(json.load(sys.stdin)$1)"; }

echo "== 1. 当前策略 =="
req GET /api/policy/current; echo

echo "== 2. 使用启动播种的一次性令牌登记设备（公钥仅为演示占位，正式演示见单测中的真实密钥对） =="
DEMO_PUB="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdemoReplaceWithRealGeneratedKeyInUnitTests00000000000000000000000000=="
req POST /api/enrollment/enroll "{\"token\":\"BOOTSTRAP-TOKEN-2026\",\"deviceId\":\"$DEVICE_ID\",\"keyAlgorithm\":\"EC\",\"publicKeySpki\":\"$DEMO_PUB\"}" || true
echo

echo "提示：完整真实密码学链路（设备生成密钥、签名、轮换、宽限、吊销、并发）请运行："
echo "  mvn test"
