# Zero Trust Device Gateway（Java / Spring Boot 本地实现）

一套以 HTTP 对外的**设备身份与零信任准入服务**。设备侧能力
（TPM/安全元件的软件替身）由本地生成的 EC P-256 / RSA-2048 密钥对模拟，
从首次入网、日常挑战-证明、密钥轮换、宽限过渡到吊销的整条链路均可在
**单机、无外部服务、无真实硬件、无外部凭据**的条件下完整跑通并验证。

## 能力总览

- **首次入网与身份绑定**：一次性令牌换登记；已用/过期/不匹配/绑错设备
  分别返回 `TOKEN_ALREADY_USED / TOKEN_EXPIRED / TOKEN_MISMATCH /
  TOKEN_DEVICE_MISMATCH`；重复登记返回 `DEVICE_ALREADY_ENROLLED`，
  不产生重复身份、不覆盖已绑定公钥。
- **证明与准入会话**：一次性、有时效、钉住策略版本的挑战；设备对
  `ATTEST|deviceId|nonce|measurement` 签名换取短期会话；
  重放、过期、非法签名、度量不符分别有明确错误码；同一挑战并发提交
  恰好一个成功；设备吊销后已发放会话在下次使用时**立即失效**。
- **密钥轮换与策略**：旧私钥授权轮换，新旧密钥关系为 `ACTIVE/PREVIOUS`，
  旧密钥仅在显式宽限期内可证明（`ROTATION_GRACE_EXPIRED`），可提前固化；
  基线与吊销名单带单调版本号，原子发布、历史保留，
  每条准入结论都带证据（规则版本、密钥角色、度量、逐环节检查）。

## 模块结构

| 包 | 内容 |
| --- | --- |
| `domain` | 令牌、设备身份、挑战、会话、策略快照、准入证据、业务异常 |
| `store` | 内存存储；`PolicyStore` 负责版本化、原子发布与历史保留 |
| `crypto` | 密钥指纹、EC/RSA 签名验签、SPKI 编解码 |
| `device` | `SimulatedDevice`：本地密钥对、固件度量、签名、轮换 |
| `service` | 入网、挑战、证明、轮换、会话校验、策略用例 |
| `web` | REST 控制器与统一错误体 `{code,message,evidence}` |
| `bootstrap` | 启动播种演示令牌与受信基线策略 |
| `tests` | 4 个业务域共 24 个端到端用例（真实 HTTP + 真实签名） |

协议细节、密钥轮换/吊销规则与策略版本语义见
[`docs/zero-trust-protocol.md`](docs/zero-trust-protocol.md)。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/enrollment/tokens` | 签发一次性入网令牌 |
| POST | `/api/enrollment/enroll` | 令牌换身份绑定 |
| POST | `/api/challenges` | 申请一次性证明挑战（钉住策略版本） |
| POST | `/api/attestations` | 提交签名证明，换取准入会话 |
| GET  | `/api/sessions/{id}` | 校验会话（过期/吊销立即拒绝） |
| POST | `/api/devices/{id}/keys/rotate` | 密钥轮换，进入宽限过渡期 |
| POST | `/api/devices/{id}/keys/finalize` | 提前结束过渡期，删除旧公钥 |
| GET  | `/api/policy/current` | 当前策略版本 |
| GET  | `/api/policy/versions` / `/versions/{v}` | 策略历史 |
| POST | `/api/policy/publish` | 全量发布新基线 + 吊销名单 |
| POST | `/api/policy/revoke` / `/unrevoke` | 增量吊销 / 解除吊销 |

签名负载：

- 证明：`ATTEST|deviceId|nonce|measurement`
- 轮换：`ROTATE|deviceId|nonce|newKeyId`

## 本地验证

需要 Java 21+、Maven 3.9+。

```bash
mvn test
```

控制台会按业务域打印覆盖的业务、每个用例名称与结果（✔/✘）及汇总，例如：

```
==================== 业务域: 设备证明与准入会话 ====================
  [✔ 通过] 用例: 证明-01: 合法签名+受信度量换取会话，证据指向正确策略版本与 ACTIVE 密钥
  [✔ 通过] 用例: 证明-06: 同一挑战并发提交时只有一个成功，其余 CHALLENGE_ALREADY_USED
  ...
业务域 [设备证明与准入会话] 执行完毕: 共 8 个用例，通过 8，失败 0
```

覆盖的业务域与边界：

| 业务域 | 测试类 | 覆盖点 |
| --- | --- | --- |
| 首次入网与身份绑定 | `EnrollmentFlowTests`（6） | 成功、令牌重放、过期、不匹配、绑错设备不消费、重复设备不覆盖公钥 |
| 证明与准入会话 | `AttestationFlowTests`（8） | 成功+证据、重放、过期、度量不符、坏签名可重试、8 路并发唯一成功、吊销即时失效、未知挑战 |
| 密钥轮换与吊销 | `RotationFlowTests`（6） | 轮换成功、宽限期内旧/新密钥证明、宽限到期、固化后旧密钥失效、轮换重放、吊销禁止轮换 |
| 策略版本与并发一致性 | `PolicyVersionTests`（4） | 版本不可变、挑战钉住版本不受中途切换影响、吊销版本化、已发放证据不可变 |

启动服务进行手工验证：

```bash
mvn spring-boot:run
# 另一终端
curl -s localhost:8080/api/policy/current
bash scripts/local-demo.sh
```

## 可调参数（`application.properties` / `ztgw.*`）

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `ztgw.enrollment-ttl` | `PT10M` | 入网令牌有效期 |
| `ztgw.challenge-ttl` | `PT2S` | 挑战有效期（过期边界测试依赖较短值） |
| `ztgw.session-ttl` | `PT5S` | 准入会话有效期 |
| `ztgw.default-rotation-grace` | `PT2M` | 轮换默认宽限期 |
| `ztgw.bootstrap-token` / `-device` / `-measurement` | 见配置 | 启动播种的演示令牌与受信基线 |

所有状态均保存在内存中，重启即复位；服务不依赖数据库、网络或任何外部凭据。
