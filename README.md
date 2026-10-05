# Zero-Trust Device Gateway (Java / Spring Boot)

一套可在本地完整跑通的**设备身份与零信任准入服务**。设备侧能力用本地
生成的 Ed25519 密钥对模拟，不依赖任何外部服务、真实硬件或外部凭据。

覆盖链路：**首次入网（一次性令牌登记）→ 挑战/证明（challenge-response）
→ 短期会话 → 密钥轮换（新旧密钥宽限期）→ 策略版本切换 / 吊销**。

## 快速开始

```bash
mvn spring-boot:run          # 默认监听 8080
mvn test                     # 运行全部 23 个用例（含业务化日志）
```

测试日志里的 `BUSINESS-CASE` logger 会为每个用例打印
`>>> [业务类] START case: ...` / `<<< [业务类] PASS|FAIL case: ...`，
服务自身的 `[ENROLL] [CHALLENGE] [ATTEST] [ROTATE] [POLICY]` 日志则给出
每条业务结论，因此可以直接从日志看出覆盖了哪些业务、用例和结果。

## HTTP 接口

所有响应均为 JSON；失败返回统一结构
`{ "code", "message", "at", "details" }`，`code` 可被客户端程序化区分。

### 管理端（本地演示/运维）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/admin/tokens` | 签发一次性入网令牌；可带 `{"deviceId":"..."}` 绑定设备 |
| POST | `/api/admin/policy` | 发布新的不可变策略版本（完整基线 + 完整吊销名单） |
| GET  | `/api/admin/policy/current` | 当前策略版本 |
| GET  | `/api/admin/policy/history` | 全部策略版本 |
| GET  | `/api/admin/devices/{id}` | 设备身份、两把密钥的状态、当前是否被吊销 |
| GET  | `/api/admin/decisions?limit=n` | 最近的准入/轮换决策证据 |

### 设备端

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/devices/enroll` | `{deviceId, token, publicKey}` 一次性令牌换身份绑定 |
| POST | `/api/devices/challenges` | `{deviceId, purpose}` 下发一次性挑战，`purpose=ATTEST|ROTATE` |
| POST | `/api/devices/attest` | 用设备私钥对挑战+度量值签名换取短期会话 |
| POST | `/api/devices/sessions/verify` | 校验会话是否仍然有效（含实时吊销检查） |
| POST | `/api/devices/keys/rotate` | 当前密钥签名绑定新密钥，旧密钥进入宽限期 |

## 准入协议

签名算法为 **Ed25519**，公钥以 X.509 SubjectPublicKeyInfo Base64 传输，
密钥身份取其 SHA-256 指纹（hex）。签名内容是一段双方都能重构的规范字符串，
避免二义性：

```
ZTG-ATTEST|1|<challengeId>|<nonce>|<firmwareMeasurement>
ZTG-ROTATE|1|<challengeId>|<nonce>|<oldKeyFingerprint>|<newKeyFingerprint>
```

### 1. 首次入网

1. 管理端签发令牌（可选绑定 `deviceId`），带 TTL。
2. 设备提交 `deviceId + token + publicKey`。
3. 服务端按顺序区分失败原因：
   `TOKEN_UNKNOWN`（404）/ `TOKEN_DEVICE_MISMATCH`（403）/
   `TOKEN_ALREADY_USED`（409）/ `TOKEN_EXPIRED`（403）。
4. 成功时令牌被**原子消费一次**；同设备锁内再次提交返回
   `DEVICE_ALREADY_ENROLLED`（409），已绑定公钥永远不会被覆盖，
   响应中回带当前绑定指纹。

### 2. 挑战、证明与短期会话

1. 设备请求挑战，服务端生成随机 nonce，并把**当前策略版本号固定在挑战上**。
2. 设备对 `challengeId|nonce|度量值` 签名后提交。
3. 校验顺序及可区分错误码：
   - `CHALLENGE_UNKNOWN` / `CHALLENGE_PURPOSE_MISMATCH` /
     `CHALLENGE_DEVICE_MISMATCH`
   - `CHALLENGE_REPLAY`（已消费，含并发失败方）
   - `CHALLENGE_EXPIRED`（超过挑战 TTL）
   - `DEVICE_REVOKED`（以**最新**策略实时判定，立即生效）
   - `DEVICE_KEY_UNKNOWN` / `OLD_KEY_GRACE_EXPIRED`
   - `SIGNATURE_INVALID`（签名不合法或消息被篡改）
   - `MEASUREMENT_UNTRUSTED`（度量值不在挑战所固定版本的受信基线中）
4. 挑战消费是 CAS 原子操作：同一挑战并发提交时**恰好一个成功**，
   其余全部得到 `CHALLENGE_REPLAY`。
5. 成功后发放短期会话令牌（默认 120s），响应和会话都记录
   `policyVersion`、`keyFingerprint`、`measurement`、`decisionId`。
6. `/sessions/verify` 每次都实时检查：会话是否过期（`SESSION_EXPIRED`）、
   设备是否在最新吊销名单中（`SESSION_DEVICE_REVOKED`）。
   **吊销不等待会话自然到期，已发会话立即失效。**

### 3. 密钥轮换与宽限期

1. 设备先申请 `purpose=ROTATE` 的一次性挑战。
2. 轮换请求必须由**当前密钥**对
   `挑战 + 旧指纹 + 新指纹` 签名；用旧/宽限密钥发起会得到
   `ROTATION_SIGNER_NOT_CURRENT`；新旧相同或重用历史密钥分别得到
   `ROTATION_SAME_KEY` / `ROTATION_KEY_SEEN`；被吊销设备得到
   `DEVICE_REVOKED`。
3. 轮换成功后：
   - 新密钥立即成为 `CURRENT`，可直接证明；
   - 旧密钥变为 `OLD_GRACE`，只在宽限期（默认 300s，测试配置为 5s）
     内允许完成证明；
   - 宽限期结束后旧密钥证明返回 `OLD_KEY_GRACE_EXPIRED`，新密钥不受影响。
4. 轮换同样使用一次性挑战，并发提交只有一个成功。

## 策略版本语义

- 策略是**只增不改（append-only）的不可变快照**：`version` 单调递增，
  内含完整的受信度量集合与吊销名单及创建原因。
- 挑战在签发时固定 `policyVersion`：准入只按该版本的基线判定。
  之后发布新版本**不会改写**已经在途或已给出的结论——决策记录里写的
  版本号就是当时使用的规则。
- 吊销属于实时安全状态：准入与会话校验始终用最新版本检查吊销，
  保证吊销立即生效；决策会同时标明证据来自哪一版。
- 发布接口支持乐观并发：请求带 `expectedVersion`，与当前版本不符时
  返回 412 `POLICY_VERSION_CONFLICT`，防止两个管理员互相静默覆盖。
- 每次发布必须提交**完整目标状态**，服务端不做隐式合并，杜绝
  “以为追加其实覆盖”的静默改写。

## 可解释性

每条 ALLOW / DENY 都会生成一条决策记录（`/api/admin/decisions`）：

```json
{
  "decisionId": "dec_...",
  "kind": "ATTEST | ROTATE | SESSION_VERIFY",
  "deviceId": "dev-01",
  "allow": true,
  "policyVersion": 3,
  "challengeId": "chl_...",
  "keyFingerprint": "ab12...",
  "measurement": "sha256:fw-good-1",
  "reason": "ALLOW: valid signature over one-time challenge; measurement trusted under policy v3",
  "at": "2026-10-05T12:00:00Z"
}
```

即：每条结论都能回答“**按哪一版规则（policyVersion）、依据哪份证据
（challenge / key / measurement / decisionId）、为什么允许或拒绝**”。

## 本地手动验证（curl）

```bash
# 1) 发布受信基线（v1）
curl -s localhost:8080/api/admin/policy -H 'Content-Type: application/json' -d '{
  "trustedMeasurements":["sha256:fw-1.0"],
  "revokedDevices":[], "reason":"initial baseline"}'

# 2) 生成 Ed25519 密钥对（需要 openssl 3.x）
openssl genpkey -algorithm Ed25519 -out dev.key
openssl pkey -in dev.key -pubout -outform DER | openssl base64 -A > dev.pub.b64

# 3) 签发并消费一次性入网令牌
TOK=$(curl -s localhost:8080/api/admin/tokens -H 'Content-Type: application/json' \
  -d '{"deviceId":"dev-01"}' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
curl -s localhost:8080/api/devices/enroll -H 'Content-Type: application/json' \
  -d "{\"deviceId\":\"dev-01\",\"token\":\"$TOK\",\"publicKey\":\"$(cat dev.pub.b64)\"}"

# 4) 取挑战、签名、换取会话
CH=$(curl -s localhost:8080/api/devices/challenges -H 'Content-Type: application/json' \
  -d '{"deviceId":"dev-01","purpose":"ATTEST"}')
CID=$(echo "$CH" | sed -n 's/.*"challengeId":"\([^"]*\)".*/\1/p')
NONCE=$(echo "$CH" | sed -n 's/.*"nonce":"\([^"]*\)".*/\1/p')
printf 'ZTG-ATTEST|1|%s|%s|%s' "$CID" "$NONCE" "sha256:fw-1.0" > payload.txt
SIG=$(openssl pkeyutl -sign -inkey dev.key -rawin -in payload.txt | openssl base64 -A)
SESS=$(curl -s localhost:8080/api/devices/attest -H 'Content-Type: application/json' \
  -d "{\"challengeId\":\"$CID\",\"deviceId\":\"dev-01\",
       \"measurement\":\"sha256:fw-1.0\",
       \"publicKey\":\"$(cat dev.pub.b64)\",\"signature\":\"$SIG\"}")
echo "$SESS"

# 5) 吊销设备后再次校验会话 -> SESSION_DEVICE_REVOKED
curl -s localhost:8080/api/admin/policy -H 'Content-Type: application/json' -d '{
  "expectedVersion":1,
  "trustedMeasurements":["sha256:fw-1.0"],
  "revokedDevices":["dev-01"], "reason":"compromised"}'
```

## 配置项

| 属性 | 默认值 | 含义 |
| --- | --- | --- |
| `ztg.token-ttl-seconds` | 300 | 入网令牌有效期 |
| `ztg.challenge-ttl-seconds` | 60 | 挑战有效期 |
| `ztg.session-ttl-seconds` | 120 | 短期会话有效期 |
| `ztg.rotation-grace-seconds` | 300 | 轮换后旧密钥宽限期 |

所有状态保存在内存中，重启即清空，适合本地演示与测试。
