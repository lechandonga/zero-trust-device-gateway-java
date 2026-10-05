# 设备身份与零信任准入协议（本地实现版）

本文档描述本工程实现的零信任设备准入协议：入网、挑战-证明、密钥轮换、
吊销与策略版本语义。设备侧的安全硬件（TPM / 安全元件）由
`SimulatedDevice`（本地生成的 EC P-256 / RSA-2048 密钥对）模拟，
全部链路可在单机、无外部服务、无外部凭据的条件下跑通。

## 1. 总体角色

| 角色 | 实现位置 | 职责 |
| --- | --- | --- |
| 设备（模拟） | `device/SimulatedDevice.java` | 本地生成/持有私钥、给出固件度量、对挑战签名、执行本地轮换 |
| 网关 | HTTP 服务 | 令牌管理、身份绑定、挑战发放、证明验证、会话发放与校验、策略版本管理 |
| 策略（管理侧） | `/api/policy/**` | 发布受信固件度量基线、吊销名单，版本单调递增 |

密钥标识 `keyId = hex(SHA-256(SPKI 公钥编码))`，可确定性地引用一把公钥。

## 2. 首次入网与身份绑定

1. 管理侧调用 `POST /api/enrollment/tokens` 创建一次性令牌，可绑定
   `expectedDeviceId`，带有效期（默认 10 分钟）。
2. 设备本地生成密钥对，调用 `POST /api/enrollment/enroll`，提交
   `{token, deviceId, keyAlgorithm, publicKeySpki}`。
3. 网关按以下顺序给出**可区分的失败原因**（令牌本身不被无效尝试消费）：
   - `DEVICE_ALREADY_ENROLLED`（409）：设备已有身份。重复提交不产生第二身份，
     也绝不覆盖已绑定公钥；同一公钥也不能绑定到第二个身份
     （`PUBLIC_KEY_ALREADY_BOUND`）。
   - `TOKEN_MISMATCH`（401）：令牌不存在。
   - `TOKEN_ALREADY_USED`（401）：一次性令牌已被消费，错误中带消费方设备。
   - `TOKEN_DEVICE_MISMATCH`（401）：令牌绑定了其它设备，**不消费令牌**，
     绑定的正确设备仍可使用。
   - `TOKEN_EXPIRED`（401）：令牌超过有效期。
4. 成功时身份写入、令牌原子标记为已消费（`markConsumed` 只成功一次）。

## 3. 挑战-证明与准入会话

### 3.1 挑战

`POST /api/challenges` → 返回 `{challengeId, nonce, expiresAt, policyVersion}`。

- 一次性：每个挑战只能被成功消费一次；
- 有时效：默认 2 秒（`ztgw.challenge-ttl`）；
- **钉住策略版本**：发放瞬间把当时的策略版本号写入挑战。

### 3.2 证明

设备对规范负载签名（UTF-8，竖线分隔，nonce 入签以防重放/防嫁接）：

```
ATTEST|deviceId|nonce|measurement
```

提交 `POST /api/attestations`：
`{challengeId, deviceId, measurement, signature(base64), keyId(可选)}`。

服务端判定环节（每步进入证据链 `evidence.steps`）：

1. 挑战存在、归属本设备、未消费、未过期：
   `CHALLENGE_NOT_FOUND / CHALLENGE_DEVICE_MISMATCH /
   CHALLENGE_ALREADY_USED / CHALLENGE_EXPIRED`；
2. 实时吊销闸口：设备在**当前**吊销名单上则 `DEVICE_REVOKED`，不发会话；
3. 签名验证：在设备登记公钥上验签。当前密钥角色为 `ACTIVE`；
   轮换宽限期内旧密钥角色为 `PREVIOUS`。
   - 显式 `keyId` 不属于本设备：`KEY_NOT_BOUND`；
   - 验签失败：`INVALID_SIGNATURE`（此时挑战**不消费**，允许合法重试）；
4. 基线匹配：使用**挑战钉住的策略版本**的受信度量集合判定，
   不符 → `MEASUREMENT_UNTRUSTED`；
5. 钉住版本吊销检查：钉住版本已吊销该设备 →
   `DEVICE_REVOKED_AT_PINNED_POLICY`；
6. 原子消费挑战：`synchronized(challenge)` + CAS，保证同一挑战并发提交
   恰好一个成功，其余 `CHALLENGE_ALREADY_USED`；
7. 发放短期会话（默认 5 分钟，可在请求中用 `sessionTtl` 覆盖）。

### 3.3 会话与“吊销立即生效”

会话证据在发放时固定且不可变。`GET /api/sessions/{id}` 每次校验：

- 过期 → `SESSION_EXPIRED`；
- **当前**策略吊销了设备 → `SESSION_REVOKED`。

因此吊销只发布一条新策略，不必遍历或修改已发放会话，
旧会话在下一次使用时立即失效；其历史证据与结论保持原样，可审计。

## 4. 密钥轮换与宽限期

轮换同样复用一次性挑战，负载为：

```
ROTATE|deviceId|nonce|newKeyId
```

流程（`POST /api/devices/{deviceId}/keys/rotate`）：

1. 挑战有效且未消费；设备当前未被实时策略吊销（`DEVICE_REVOKED`）；
2. 轮换授权签名必须由**当前 ACTIVE 私钥**完成（`INVALID_SIGNATURE`），
   新公钥不得与现存新旧公钥相同（`SAME_KEY_NOT_ALLOWED`）；
3. 成功后设备身份变为：`active=新公钥`、`previous=旧公钥`、
   `graceUntil=now+gracePeriod`（默认 2 分钟）。

过渡期密钥可用关系（明确且唯一）：

| 密钥 | 宽限期内 | 宽限期后 / 显式固化后 |
| --- | --- | --- |
| ACTIVE（新） | 可证明、可授权下一次轮换 | 同左 |
| PREVIOUS（旧） | 仅可用于证明，证据 `keyRole=PREVIOUS` | `ROTATION_GRACE_EXPIRED`；固化后 `KEY_NOT_BOUND`/`INVALID_SIGNATURE` |

`POST /api/devices/{deviceId}/keys/finalize` 提前结束过渡期并删除旧公钥。

## 5. 策略版本语义

- 策略 = `{version, createdAt, trustedMeasurements[], revokedDevices[], note}`，
  快照**不可变**；
- 每次 `publish`（全量）/ `revoke` / `unrevoke`（增量）都生成新版本，
  版本号严格 +1，通过 `AtomicReference` 原子发布：并发请求要么看到旧版、
  要么看到新版，绝不会读到半更新的混合规则；
- 全部历史版本保留：`GET /api/policy/versions/{version}`；
- 一次证明的基线/吊销判断**始终基于挑战钉住的版本**，
  策略更新不会静默改写正在进行的准入判定，也不会改写已发放会话的证据；
- 每条准入结论都返回证据 `AdmissionEvidence`：
  `challengeId`、`challengePolicyVersion`、`decisionPolicyVersion`、
  `keyId`、`keyRole`、`measurement`、`baselineMatched`、
  `deviceRevokedAtDecision` 以及逐环节 `steps[]`。

## 6. 错误码一览

| 阶段 | 错误码 |
| --- | --- |
| 入网 | `INVALID_REQUEST`、`TOKEN_MISMATCH`、`TOKEN_ALREADY_USED`、`TOKEN_EXPIRED`、`TOKEN_DEVICE_MISMATCH`、`DEVICE_ALREADY_ENROLLED`、`PUBLIC_KEY_ALREADY_BOUND`、`INVALID_PUBLIC_KEY`、`UNSUPPORTED_KEY_ALGORITHM` |
| 挑战/证明 | `CHALLENGE_NOT_FOUND`、`CHALLENGE_DEVICE_MISMATCH`、`CHALLENGE_ALREADY_USED`、`CHALLENGE_EXPIRED`、`INVALID_SIGNATURE`、`INVALID_SIGNATURE_ENCODING`、`KEY_NOT_BOUND`、`MEASUREMENT_UNTRUSTED`、`ROTATION_GRACE_EXPIRED`、`DEVICE_REVOKED`、`DEVICE_REVOKED_AT_PINNED_POLICY` |
| 轮换 | 同上 + `SAME_KEY_NOT_ALLOWED`、`INVALID_GRACE_PERIOD`、`NO_PREVIOUS_KEY` |
| 会话 | `SESSION_NOT_FOUND`、`SESSION_EXPIRED`、`SESSION_REVOKED` |
| 策略 | `POLICY_VERSION_NOT_FOUND` |
