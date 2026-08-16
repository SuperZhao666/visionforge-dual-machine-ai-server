# VisionForge 双机 AI Server 全业务代码审查与低能力 LLM 修复指南

> **仓库**：`SuperZhao666/visionforge-dual-machine-ai-server`  
> **冻结提交**：`a488012430770b4c54259521508aa77cf7ff0193`  
> **总体结论**：当前冻结提交 **不具备正式生产发布条件**。发现 **27 项源码证据已闭合问题**（P0 5、P1 17、P2 5），另有 **3 项必须动态验证的高风险候选项**。

## 1. 审查边界与可信度

- GitHub 代码索引在审查时不可用，审查通过仓库树和逐文件读取完成。
- 当前执行环境无法完整克隆仓库、取得私有 QNN/模型工件、运行 Android/Windows 构建或连接两台真实设备。
- 因此 CONFIRMED 项有源码闭合证据；VERIFY 项必须在真实构建、支付、邮件或物理设备环境验证。
- 本报告不改进瞄准、输入自动化、隐蔽性、反检测或规避平台安全机制，只审查构建、部署、授权、计费、协议和可靠性。

### 证据等级

- **CONFIRMED**：入口、配置、调用方和失败/空效果路径可在源码中闭合。
- **CONDITIONAL_CONFIRMED**：技术断链已确认，但是否构成用户故障取决于产品承诺。
- **VERIFY**：源码显示高风险候选，必须用真实依赖、付款、邮件或物理设备作最终判定。

## 2. 实际业务拓扑

1. **Platform 主站**：账户、邮件验证码、付款、`time_balance`、会话租约、Release、Runtime Catalog。
2. **双机 Sidecar**：独立数据库、卡密、设备配对、entitlement、usage session、usage ticket、HMAC 管理桥。
3. **Windows Host**：C++ 双机运行时，具有正式安全构建门禁。
4. **Android 客户端**：QNN/ONNX Runtime、固定公钥、私有工件依赖和正式 Release 门禁。
5. **外部运行依赖**：Nginx、systemd、SMTP、支付 monitor、Runtime 工件目录、Android OTA。

最危险的问题不是单文件语法，而是“组件各自绿、组合后没有效果”：主站绿但 Sidecar 未部署；Sidecar 绿但 Bridge 密钥不同；付款成功但 entitlement 不变；服务端签票成功但客户端固定公钥拒绝；心跳返回成功但无状态变化。

## 3. 问题总表

| Issue | 严重度 | 状态 | 摘要 |
|---|---:|---|---|
| VF-P0-001 | P0 | 已确认 | Android 正式发布被安全能力门禁主动阻断 |
| VF-P0-002 | P0 | 已确认 | Windows Host 正式安全构建被 CMake 门禁主动阻断 |
| VF-P0-003 | P0 | 已确认 | Android 工程无法从干净检出重建：私有 QNN、模型和运行库工件缺失 |
| VF-P0-004 | P0 | 已确认 | Sidecar 随机生成 usage-ticket 私钥，可能与 Android 固定公钥不匹配 |
| VF-P0-005 | P0 | 条件性已确认 | 主站付款余额与双机 Sidecar 授权彼此孤立，付款可能不交付双机权益 |
| VF-P1-001 | P1 | 已确认 | 主部署脚本只启动 Platform，不安装或启动双机 Sidecar |
| VF-P1-002 | P1 | 已确认 | Admin Bridge 密钥只写入 Sidecar，Platform 不会获得同一密钥 |
| VF-P1-003 | P1 | 已确认 | 启用管理员 TOTP 后可能锁死全部管理员：运行依赖缺少 pyotp |
| VF-P1-004 | P1 | 已确认 | 默认部署不生成 SMTP 配置，但注册强制依赖邮件验证码 |
| VF-P1-005 | P1 | 已确认 | 默认部署缺少 Runtime Catalog 的签名、HMAC 和工件目录配置 |
| VF-P1-006 | P1 | 已确认 | 支付监控器未部署、未监控，也未纳入 readiness |
| VF-P1-007 | P1 | 已确认 | Android OTA 通道只存在于独立文档，主部署不会安装 |
| VF-P1-008 | P1 | 已确认 | 旧 `/api/client/heartbeat` 无鉴权、无落库、无状态变化，却固定返回成功 |
| VF-P1-009 | P1 | 已确认 | 无发布记录时 `/api/client/version` 伪造硬编码版本和目录 URL |
| VF-P1-010 | P1 | 已确认 | 部署 smoke 只检查首页，制造“整站已就绪”的假绿灯 |
| VF-P1-011 | P1 | 已确认 | Android 旧身份密钥升级/重绑定迁移被项目文档明确列为发布阻断项 |
| VF-P1-012 | P1 | 已确认 | Android 商业壳缺失：账户、购买、更新、帮助、EULA、错误报告未迁移 |
| VF-P1-013 | P1 | 已确认 | 仓库没有 CI 工作流，测试和发布门禁不会自动执行 |
| VF-P1-014 | P1 | 已确认 | 版本号、APK/Host 哈希和发布证据在多个文件间漂移 |
| VF-P1-015 | P1 | 已确认 | README 指示复制根 config.py，但运行时只读取 app.config/.env |
| VF-P1-016 | P1 | 已确认 | 架构文档含历史 320x320/CAT6-only 等过时口径，会误导修复 |
| VF-P1-017 | P1 | 已确认 | 所谓 portable fallback 构建仍被 QNN SDK/工件全局硬依赖 |
| VF-P2-001 | P2 | 已确认 | 支付金额槽位默认只有 1 个，15 分钟内同类订单只能有一笔 |
| VF-P2-002 | P2 | 已确认 | VF_APP_ROOT 可配置项被 systemd 单元硬编码路径抵消 |
| VF-P2-003 | P2 | 已确认 | 部署 QR 工具导入 qrcode，但依赖未声明 |
| VF-P2-004 | P2 | 已确认 | Python requirements 只有宽松下限，无运行锁和测试锁 |
| VF-P2-005 | P2 | 已确认 | Platform 使用不轮转 FileHandler，长期运行可写满磁盘 |
| VF-V-001 | P0-CANDIDATE | 必须动态验证 | `onnxruntime-android:1.27.0` 可能无法从配置仓库解析 |
| VF-V-002 | P1-CANDIDATE | 必须动态验证 | 邮件验证码可能缺少足够的多维限流和 SMTP 配额保护 |
| VF-V-003 | P1-CANDIDATE | 必须动态验证 | 未发现主库、Sidecar 库、密钥和发布清单的一致代灾备契约 |

## 4. 低能力 LLM 强制执行协议

每次只下发一个 Issue ID。禁止让模型一次“修完整个项目”。

### 4.1 固定顺序

1. 确认 `git status --short` 为空，检出冻结提交，创建 `fix/<ISSUE_ID>-<slug>`。
2. 只读取本 Issue 的证据文件、直接依赖和必要测试。
3. 先得到 **RED**：执行现有失败路径或新增失败测试，保存命令、退出码和关键输出。没有 RED 不得改代码。
4. 用不超过 10 行说明根因，必须回答“为什么当前会阻断/无效果/假成功”。
5. 只做最小补丁。需要触碰未允许领域或发现协议/SKU 歧义时停止并报告。
6. 得到 **GREEN**：单元、集成、业务可观察结果均通过；编译或 HTTP 200 不等于完成。
7. 检查 diff：不得出现 secret、跳过检查、关闭门禁、永远通过测试或无关重构。
8. 按固定 12 字段报告，等待人工审查再合并。

### 4.2 固定报告格式

```text
TASK_ID:
BASE_COMMIT:
FILES_READ:
RED_COMMAND_AND_OUTPUT:
ROOT_CAUSE:
FILES_CHANGED:
PATCH_SUMMARY:
GREEN_COMMAND_AND_OUTPUT:
BUSINESS_ACCEPTANCE:
SECURITY_INVARIANTS:
ROLLBACK:
UNRESOLVED:
```

### 4.3 全局禁止项

- 不得只把 formalSecureDataPlaneImplemented 或 VFDUAL_FORMAL_SECURITY_IMPLEMENTED 从 false/OFF 改为 true/ON。
- 不得删除、注释、短路或吞掉签名、哈希、重放保护、TLS、HMAC、TOTP、授权、计费和发布校验。
- 不得把“HTTP 200”“首页可打开”“Debug 能编译”当作业务完成。
- 不得用空模型、随机同名文件、伪造支付回调或永远通过的测试冒充真实依赖。
- 不得提交或打印私钥、SMTP 密码、支付密钥、桥接密钥、验证码、会话票据。
- 不得直接跨库写 Sidecar SQLite；跨域交付必须使用幂等、可重试、可审计的应用层协议。
- 不得一次修多个 Issue，不得在未获准时扩大修改路径或进行大范围重构。
- 不得修改目标识别效果、控制算法、输入注入、隐蔽/规避逻辑。
- 密码学、密钥轮换、计费语义、SKU 映射、旧身份迁移必须经过人工设计审查。

### 4.4 可复制的单任务提示词

```text
你只修复任务 <ISSUE_ID>。基线提交必须是 a488012430770b4c54259521508aa77cf7ff0193。
先读取本修复文档中该 Issue 的全部内容并检查 git status。
严格执行 RED 复现 → 根因 → 最小补丁 → GREEN → 业务验收 → 回滚说明。
不得扩大任务范围，不得删除安全/签名/哈希/计费/鉴权检查，不得翻转能力标志冒充实现，
不得返回伪成功，不得跳过测试，不得打印或提交 secret。未运行的测试必须写 NOT RUN 和原因。
最后只按文档规定的 12 个字段报告。
```

## 5. 修复波次

### W0｜冻结依赖、CI 与发布事实源

- 顺序：`VF-P2-004` → `VF-P1-013` → `VF-P1-014`
- 退出条件：后续修复可在固定依赖中复现，版本和哈希只有一个事实源。

### W1｜构建、密钥和正式安全门禁

- 顺序：`VF-P0-003` → `VF-V-001` → `VF-P0-004` → `VF-P0-001` → `VF-P0-002` → `VF-P1-011` → `VF-P1-017`
- 退出条件：干净构建可重现，三端协议/密钥互操作；没有翻转门禁的伪修复。

### W2｜部署接线与真实 readiness

- 顺序：`VF-P1-001` → `VF-P1-002` → `VF-P1-003` → `VF-P1-004` → `VF-P1-005` → `VF-P1-006` → `VF-P1-007` → `VF-P1-010` → `VF-P2-002` → `VF-P2-003` → `VF-P2-005`
- 退出条件：完整模式部署后，注册、支付依赖、Sidecar、Bridge、Runtime、OTA 均可观测。

### W3｜删除假成功与配置/文档漂移

- 顺序：`VF-P1-008` → `VF-P1-009` → `VF-P1-015` → `VF-P1-016`
- 退出条件：核心接口不返回无状态成功，配置和当前规范均唯一。

### W4｜付款到权益与用户商业闭环

- 顺序：`VF-P0-005` → `VF-P2-001` → `VF-P1-012` → `VF-V-002`
- 退出条件：SKU、付款、entitlement 和 App 用户旅程一致且幂等。

### W5｜灾备、升级、真机与长稳

- 顺序：`VF-V-003`
- 退出条件：灾备、真机升级、故障注入和 72 小时 soak 全部通过。

## 6. 逐项修复说明

### VF-P0-001｜P0｜已确认｜Android 正式发布被安全能力门禁主动阻断

**实际业务症状**：Release 构建不能合法产出；若只翻转标志，会得到表面可发布、实际没有安全证据的伪工件。

**根因**：正式握手、认证数据面、重放/篡改/故障测试及发布证据没有闭环，门禁用于阻止误发布。

**证据定位**
- `android_inference_benchmark/app/formal-security-capability.properties`
- `android_inference_benchmark/app/formal-security-loader.gradle`
- formalSecureDataPlaneImplemented=false。
- Release 任务会校验能力标志及正式安全资产，缺失时抛错终止。

**低能力 LLM 的修复步骤**
1. 先保存当前 Release 门禁失败日志，禁止先改 capability 文件。
1. 逐项实现握手、票据、nonce/序号、重放、乱序、截断、篡改、过期和断线恢复状态机。
1. 给每项能力增加自动负面测试和可机器生成的证据清单。
1. 由人工安全审查确认协议与实现一致后，才允许更新能力标志。
1. Release 构建必须校验证据、协议版本、工件哈希和提交 SHA。

**GREEN 与业务验收**
- 正常双机连接通过；错误签名、重复 nonce、过期票据、篡改帧全部 fail-closed。
- 删掉任一证据或破坏任一安全测试后 Release 必须重新失败。
- 真实 Android 与 Host 完成异常包、断网和恢复测试。

**禁止的伪修复**
- 只把标志改为 true。
- 把门禁从 Gradle 生命周期移除。
- 用纯 Mock 网络测试代替真实互操作。

**人工门禁**：必须

**回滚**：恢复 capability=false，撤销未通过安全审查的 APK 和发布清单。

### VF-P0-002｜P0｜已确认｜Windows Host 正式安全构建被 CMake 门禁主动阻断

**实际业务症状**：Host 无法以“正式安全实现完成”的状态发布；绕过后会与 Android/Sidecar 的安全声明失配。

**根因**：Host 端协议验证、异常帧、票据和恢复测试没有达到门禁定义。

**证据定位**
- `dual_machine_runtime/formal_security_capability.cmake`
- `dual_machine_runtime/formal_security_loader.cmake`
- `dual_machine_runtime/CMakeLists.txt`
- VFDUAL_FORMAL_SECURITY_IMPLEMENTED 为 OFF。
- 正式安全加载器在能力未实现时终止构建。

**前置任务**：`VF-P0-001`、`VF-P0-004`

**低能力 LLM 的修复步骤**
1. 保存现有正式构建失败证据。
1. 补齐 Host 的 fail-closed 状态机和稳定错误码。
1. Android、Host、Sidecar 共用同一协议 schema、测试向量和 key-id 规则。
1. 完成单元、模糊/负面和真实互操作测试后交人工审查。

**GREEN 与业务验收**
- 错误签名、未知 key id、重放、乱序、截断、过期均不能进入业务数据面。
- 正式模式失败后不得自动降级到未认证通道。
- 能力证据不完整时 CMake 仍必须失败。

**禁止的伪修复**
- 只把 OFF 改为 ON。
- 把 FATAL_ERROR 改为 WARNING。
- 安全失败后自动降级明文。

**人工门禁**：必须

**回滚**：恢复正式安全门禁为 OFF，并撤销对应 Host 工件。

### VF-P0-003｜P0｜已确认｜Android 工程无法从干净检出重建：私有 QNN、模型和运行库工件缺失

**实际业务症状**：新机器、CI 和灾备环境无法构建 APK；发布依赖某台机器上不可审计的遗留文件。

**根因**：私有和大体积依赖没有受控制品库、锁定清单与可复现下载流程。

**证据定位**
- `android_inference_benchmark/app/build.gradle`
- `android_inference_benchmark/app/src/main/cpp/CMakeLists.txt`
- `.gitignore`
- `qnn_workspace/**`
- `analysis_output/**`
- Gradle/CMake 固定引用仓库外或被忽略的 QNN SDK、运行库、模型和生成物。
- 缺文件时构建硬失败，且哈希/大小校验已接入生命周期。

**前置任务**：`VF-P1-013`、`VF-P1-014`

**低能力 LLM 的修复步骤**
1. 在空 qnn_workspace/analysis_output 的干净目录执行构建，形成完整缺失清单。
1. 建立 artifact-lock.json：工件 ID、版本、来源、许可证、SHA-256、大小、目标路径。
1. 建立受认证的私有制品库和单一 fetch_artifacts 工具：临时下载→哈希验证→原子移动。
1. Gradle/CMake 只读锁定缓存，不自动寻找个人路径或 latest。
1. CI 使用最小权限凭据，日志只显示工件 ID/哈希。

**GREEN 与业务验收**
- 第二台干净机器仅凭仓库、凭据和 lock 可重建。
- 篡改任一字节时在编译前失败。
- 缓存完整时离线可重复构建；缓存缺失时输出精确列表。

**禁止的伪修复**
- 删除哈希/大小校验。
- 用空模型或随机同名库通过构建。
- 把供应商私有 SDK/生产模型直接公开提交。

**人工门禁**：必须

**回滚**：回退到上一份已验证 artifact-lock；不得回退安全校验。

### VF-P0-004｜P0｜已确认｜Sidecar 随机生成 usage-ticket 私钥，可能与 Android 固定公钥不匹配

**实际业务症状**：Sidecar、服务器和 App 都显示健康，但服务端签发的票据被已发布客户端固定拒绝，激活/启动没有效果。

**根因**：生产签名密钥缺少密钥仪式、key id、指纹预检、轮换和灾备恢复协议。

**证据定位**
- `server/visionforge-platform/deploy/bootstrap_dual_machine_sidecar.sh`
- `server/visionforge-platform/dual_machine_service/token_service.py`
- `dual_machine_runtime/production_usage_ticket_v1_public.pem`
- `android_inference_benchmark/app/build.gradle`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/DualMachineReleaseSecurityConfig.java`
- bootstrap 在密钥不存在时生成新 RSA 私钥/公钥。
- Android Release 固定嵌入仓库公钥并校验预期哈希。
- 新部署或灾备若生成新私钥，其签名与客户端公钥不匹配。

**低能力 LLM 的修复步骤**
1. 生产模式禁止自动生成长期私钥；缺失即 fail-fast。
1. 从密钥管理系统注入与发布客户端公钥匹配的私钥。
1. 启动时从私钥派生公钥指纹，与签名 release manifest 比较；不一致不得 ready。
1. 票据加入 key_id；客户端只接受受控的当前/上一把公钥。
1. 按“先发布兼容客户端→切换服务端签发→撤销旧 key”顺序轮换。
1. 灾备必须恢复数据库、key id 和密钥引用的同一代快照。

**GREEN 与业务验收**
- 固定测试票据在 Android 和 Host 均通过。
- 错误私钥、未知 key id、篡改、过期均拒绝。
- 生产使用错误私钥时服务启动失败而非继续运行。

**禁止的伪修复**
- 关闭客户端签名校验。
- 从未认证网络动态下载任意公钥。
- 把生产私钥提交仓库。

**人工门禁**：必须

**回滚**：恢复上一把未泄露且与发布清单匹配的密钥；已泄露时只能撤销和轮换。

### VF-P0-005｜P0｜条件性已确认｜主站付款余额与双机 Sidecar 授权彼此孤立，付款可能不交付双机权益

**实际业务症状**：若产品承诺“主站购买即可使用双机 App”，用户会付款成功、主站 time_balance 增加，但 Sidecar entitlement 不变化。若本就独立售卖，当前界面和文档必须明确隔离。

**根因**：SKU、计费单位和授权域没有统一产品契约，也没有幂等跨域交付流程。

**证据定位**
- `server/visionforge-platform/app/services/payment_service.py`
- `server/visionforge-platform/app/routes/shop.py`
- `server/visionforge-platform/dual_machine_service/card_service.py`
- `server/visionforge-platform/dual_machine_service/routes.py`
- `docs/DUAL_MACHINE_FEATURE_GAP_DECISION_MATRIX.md`
- payment_service 的交付只写主库 time_balance/订单状态。
- Sidecar 使用独立卡密、数据库、entitlement 和 usage session。
- 未发现付款事务向 Sidecar 发可靠交付事件。
- 主站按小时售卖，Sidecar 有日/周/月/永久等不同语义。

**前置任务**：`VF-P1-012`、`VF-P2-001`

**低能力 LLM 的修复步骤**
1. 产品负责人先书面确定两套权益是否互通以及逐 SKU 映射。
1. 独立产品方案：重命名入口、订单描述和激活说明，禁止暗示互通。
1. 统一交付方案：主库新增 fulfillment_outbox；支付事务只原子写订单和事件。
1. 独立 worker 按 event_id 调受认证 Sidecar fulfillment API；Sidecar 对 event_id 建唯一约束。
1. 未知 SKU 进入人工队列，不能猜；加入重试、死信、补偿和人工重放。

**GREEN 与业务验收**
- staging 付款后 entitlement 精确变化一次。
- 重复回调、重复 worker、超时和重启不重复增权。
- Sidecar 不可用时订单保留可恢复状态，不向用户虚报到账。

**禁止的伪修复**
- 支付事务内同步跨网络调用 Sidecar。
- 直接跨库写 Sidecar SQLite。
- 按用户名、金额或时间模糊匹配交付对象。

**人工门禁**：必须

**回滚**：停止交付 worker，保留 outbox 和审计；按批准补偿流程处理未完成事件。

### VF-P1-001｜P1｜已确认｜主部署脚本只启动 Platform，不安装或启动双机 Sidecar

**实际业务症状**：首页、登录和 8000 端口正常，但激活、配对、usage session 和后台双机管理全部不可用。

**根因**：没有明确 platform-only 与 full-dual-machine 两种部署模式，也没有组合就绪检查。

**证据定位**
- `server/visionforge-platform/README.md`
- `server/visionforge-platform/deploy/final_setup.sh`
- `server/visionforge-platform/deploy/bootstrap_dual_machine_sidecar.sh`
- `server/visionforge-platform/deploy/vf-dual-machine.service`
- README 主路径指向 final_setup.sh。
- final_setup 只处理 vf.service 和首页/HTTPS。
- Sidecar 仅有独立 bootstrap，主流程未调用。

**前置任务**：`VF-P1-002`、`VF-P1-010`

**低能力 LLM 的修复步骤**
1. 定义显式模式，默认不得含糊。
1. full 模式由一个顶层脚本顺序安装 Platform、Sidecar、共享配置和 Nginx。
1. 每步失败停止并输出回滚清单。
1. 完成后检查两个 unit、两个本地端口、公共 API 和受认证 bridge。
1. platform-only 模式必须隐藏/禁用所有双机入口。

**GREEN 与业务验收**
- 干净 Ubuntu 一次部署成功且重跑幂等。
- 主机重启后两个服务自动恢复。
- 停止 Sidecar 时 readiness 红、liveness 仍可区分。

**禁止的伪修复**
- 只在文档让运维再手工跑一次。
- 吞掉 Sidecar 错误仍报告整站 ready。

**人工门禁**：常规代码审查

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-P1-002｜P1｜已确认｜Admin Bridge 密钥只写入 Sidecar，Platform 不会获得同一密钥

**实际业务症状**：Sidecar 已启动，但 Platform 后台调用固定 bridge unavailable，管理操作没有效果。

**根因**：共享密钥的单次生成、双端分发、重启顺序和一致性探针没有原子化。

**证据定位**
- `server/visionforge-platform/deploy/bootstrap_dual_machine_sidecar.sh`
- `server/visionforge-platform/deploy/create_single_server_env.py`
- `server/visionforge-platform/app/services/dual_machine_admin_client.py`
- `server/visionforge-platform/dual_machine_service/admin_bridge_auth.py`
- bootstrap 只把 DUAL_MACHINE_ADMIN_BRIDGE_SECRET 写入 Sidecar service.env。
- Platform env 生成器不含该变量。
- 客户端拒绝空/过短 secret，Sidecar 又要求匹配 HMAC。
- bootstrap 不重启 Platform。

**前置任务**：`VF-P1-001`

**低能力 LLM 的修复步骤**
1. 顶层部署只生成一次高熵 secret。
1. 以 0600 权限原子写入 Platform 和 Sidecar 环境文件，不打印明文。
1. 两端只输出 SHA-256 指纹前缀用于诊断。
1. 顺序：写配置→Sidecar health→重启 Platform→Platform bridge probe。
1. 轮换采用受控同时重启或双密钥短窗口。

**GREEN 与业务验收**
- Platform 完成 bridge 只读 probe 和可回滚测试调用。
- 任一端错密钥时明确认证失败，不降级。
- 重跑部署不会无故换密钥。

**禁止的伪修复**
- 源码硬编码 secret。
- 关闭 HMAC。
- 把 secret 放 URL。

**人工门禁**：常规代码审查

**回滚**：恢复上一份双端一致的密钥文件并同时重启两个服务。

### VF-P1-003｜P1｜已确认｜启用管理员 TOTP 后可能锁死全部管理员：运行依赖缺少 pyotp

**实际业务症状**：生产配置 ADMIN_TOTP_SECRET 后，所有合法验证码仍被判错，后台完全无法登录。

**根因**：可选导入与强制安全配置组合没有启动前置校验，依赖声明不完整。

**证据定位**
- `server/visionforge-platform/app/security.py`
- `server/visionforge-platform/app/routes/auth.py`
- `server/visionforge-platform/requirements.txt`
- verify_totp 在 pyotp 导入失败时固定返回 False。
- 管理员配置 TOTP 后必须校验。
- requirements.txt 未声明 pyotp。

**前置任务**：`VF-P1-010`、`VF-P2-004`

**低能力 LLM 的修复步骤**
1. 把 pyotp 加入锁定运行依赖。
1. 配置 TOTP 但模块不可导入时服务必须 fail-fast，不进入 ready。
1. 区分“未启用 TOTP”和“依赖损坏”。
1. 增加有效、错误、过期、相邻窗口测试。

**GREEN 与业务验收**
- 正确码可登录，错误/过期码拒绝。
- 移除 pyotp 后启动失败而不是登录全失败。
- 日志不含 secret/验证码。

**禁止的伪修复**
- 导入失败时返回 True。
- 自动忽略 TOTP。
- 打印 TOTP secret。

**人工门禁**：常规代码审查

**回滚**：保留启动 fail-fast；不得回退到静默锁死版本。

### VF-P1-004｜P1｜已确认｜默认部署不生成 SMTP 配置，但注册强制依赖邮件验证码

**实际业务症状**：网站能开、注册入口存在，但发送验证码失败，新用户不能注册。

**根因**：“开放注册”模式未声明 SMTP 是硬依赖，首页检查掩盖了功能缺失。

**证据定位**
- `server/visionforge-platform/app/routes/time_api.py`
- `server/visionforge-platform/app/services/email_service.py`
- `server/visionforge-platform/app/config.py`
- `server/visionforge-platform/deploy/create_single_server_env.py`
- `server/visionforge-platform/deploy/validate_single_server_env.py`
- 注册必须发送/校验邮箱码。
- SMTP 凭据缺失时 email_service 失败。
- 默认 env 和验证器不要求 SMTP。

**前置任务**：`VF-P1-010`、`VF-V-002`

**低能力 LLM 的修复步骤**
1. 增加 OPEN_REGISTRATION=true/false。
1. 开放时启动校验 SMTP 主机、端口、用户、密码、发件人和 TLS。
1. 关闭时后端稳定返回 registration_disabled，前端隐藏入口。
1. readiness 检查安全连接或最近投递成功时间。
1. staging 用受控邮箱做验证码 E2E。

**GREEN 与业务验收**
- 邮件真实送达，一次性码成功，重放/过期失败。
- SMTP 故障 readiness 红并给用户可解释错误。
- 日志不含验证码和 SMTP 密码。

**禁止的伪修复**
- 验证码回显给客户端。
- SMTP 失败时使用固定码。
- 只隐藏前端而保留匿名注册。

**人工门禁**：常规代码审查

**回滚**：暂时关闭开放注册，保留已有用户登录。

### VF-P1-005｜P1｜已确认｜默认部署缺少 Runtime Catalog 的签名、HMAC 和工件目录配置

**实际业务症状**：主站可运行，但 Runtime 发布/下载接口返回 503 或无法提供受信工件，客户端更新没有效果。

**根因**：可选发布模块未纳入部署模式、密钥管理和 readiness。

**证据定位**
- `server/visionforge-platform/app/config.py`
- `server/visionforge-platform/app/routes/runtime_api.py`
- `server/visionforge-platform/app/services/runtime_catalog_service.py`
- `server/visionforge-platform/deploy/create_single_server_env.py`
- Catalog 发布/下载要求 Ed25519、HMAC、目录等配置。
- 默认 env 生成器没有生成这些变量。

**前置任务**：`VF-P1-010`、`VF-P1-014`

**低能力 LLM 的修复步骤**
1. 增加 ENABLE_RUNTIME_CATALOG 显式模式。
1. 启用时从密钥管理系统注入签名/HMAC，启动前检查目录、权限和公钥指纹。
1. 发布使用临时文件→哈希→签名→fsync→原子 rename。
1. 下载只按不可变 manifest/数据库记录取文件。
1. 建立吊销和回滚操作。

**GREEN 与业务验收**
- 发布测试工件后客户端可下载并验证签名/哈希。
- 篡改工件或 manifest 后拒绝。
- 未启用时返回明确 disabled，而非伪空目录。

**禁止的伪修复**
- 关闭签名/HMAC。
- 按用户输入路径读取任意文件。
- 把私钥放静态目录。

**人工门禁**：必须

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-P1-006｜P1｜已确认｜支付监控器未部署、未监控，也未纳入 readiness

**实际业务症状**：用户能创建订单并扫码，但外部 monitor 不在线时没有回调，订单永久 pending、权益不交付。

**根因**：外部支付采集器被当作隐含条件，没有变成受管服务和可观察依赖。

**证据定位**
- `server/visionforge-platform/app/routes/payment.py`
- `server/visionforge-platform/app/services/payment_service.py`
- `server/visionforge-platform/deploy/create_single_server_env.py`
- `server/visionforge-platform/deploy/final_setup.sh`
- `server/visionforge-platform/deploy/gen_qr.py`
- 支付依赖 VMQ/V免签风格监控器的签名心跳和回调。
- 主部署不安装、配置或检查 monitor。
- env 只生成部分密钥，不形成完整拓扑。

**前置任务**：`VF-P1-010`、`VF-P2-001`

**低能力 LLM 的修复步骤**
1. 明确 monitor 是受管服务还是外部依赖，并锁定版本。
1. 生成 endpoint/identity/secret，双端比对非敏感指纹。
1. 保存 last_monitor_heartbeat_at 和版本。
1. 心跳过期时 payment readiness=degraded，并按策略禁止新订单。
1. staging 执行真实 pending→paid→fulfilled；测试重复、过期、伪造回调。

**GREEN 与业务验收**
- 在线时真实支付 E2E 通过。
- 停止 monitor 后阈值内状态变 degraded。
- 重复回调不重复余额/entitlement。

**禁止的伪修复**
- 用手工 curl 伪造生产付款验收。
- 关闭验签。
- 心跳过期仍静默接新订单。

**人工门禁**：必须

**回滚**：关闭新订单入口，保留 pending 订单和回调审计。

### VF-P1-007｜P1｜已确认｜Android OTA 通道只存在于独立文档，主部署不会安装

**实际业务症状**：已安装客户端无法从正式渠道获取 APK 更新，修复和协议升级无法可靠送达。

**根因**：移动发布渠道与主部署、发布清单和 smoke test 分离。

**证据定位**
- `docs/ANDROID_MOBILE_RELEASE_CHANNEL.md`
- `server/visionforge-platform/deploy/final_setup.sh`
- `server/visionforge-platform/deploy/nginx.conf`
- OTA 文档要求额外 Nginx location、manifest/APK 目录。
- final_setup 只安装主站 Nginx 并检查首页。

**前置任务**：`VF-P1-013`、`VF-P1-014`

**低能力 LLM 的修复步骤**
1. 把 OTA location 纳入主 Nginx 模板或显式 include。
1. 创建 root-owned、Nginx 只读目录。
1. manifest 包含版本、最低兼容、APK URL、大小、SHA-256、key id、发布时间。
1. 先上传临时 APK 并校验，再原子发布 manifest。
1. smoke 下载 manifest/APK 并核验类型、大小、哈希、缓存头。

**GREEN 与业务验收**
- 干净部署后 manifest/APK 可获取。
- 错误哈希/不兼容版本被客户端拒绝。
- 发布中断时旧 manifest 仍有效。

**禁止的伪修复**
- 客户端忽略 APK 哈希/签名。
- 直接覆盖正在下载的 APK。
- 发布目录全局可写。

**人工门禁**：常规代码审查

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-P1-008｜P1｜已确认｜旧 `/api/client/heartbeat` 无鉴权、无落库、无状态变化，却固定返回成功

**实际业务症状**：误用旧端点的客户端看到“心跳成功”，但 lease、余额、last_seen 和在线状态完全不变。

**根因**：遗留遥测端点与权威会话端点命名相近，空实现仍使用成功响应。

**证据定位**
- `server/visionforge-platform/app/routes/client_api.py`
- `server/visionforge-platform/app/routes/time_api.py`
- `server/visionforge-platform/app/main.py`
- 旧端点只 logger.debug 后返回 ok=true。
- 默认日志级别 INFO，debug 通常也不保留。
- 真正计费心跳是 `/api/client/session-heartbeat`；不存在路由覆盖，风险是命名混淆和伪成功。

**低能力 LLM 的修复步骤**
1. 搜索全部调用方，确认迁移范围。
1. 若废弃，返回 410 并给 replacement；若保留遥测，则重命名、鉴权并定义持久化语义。
1. OpenAPI 与客户端常量只暴露一个权威会话心跳。
1. 增加契约测试：成功心跳必须产生可观察状态变化。

**GREEN 与业务验收**
- 旧端点不再返回伪成功。
- 权威心跳更新 lease/last_seen/计费且重试幂等。
- 端到端客户端只调用权威路径。

**禁止的伪修复**
- 只把日志级别改为 INFO。
- 两个端点各改一半状态。
- 无鉴权端点扣余额。

**人工门禁**：常规代码审查

**回滚**：可暂时保留旧路径，但必须明确返回 deprecated/410，不能恢复 ok=true。

### VF-P1-009｜P1｜已确认｜无发布记录时 `/api/client/version` 伪造硬编码版本和目录 URL

**实际业务症状**：客户端认为存在最新版本，随后下载失败；不同版本接口对同一事实给出矛盾答案。

**根因**：开发占位 fallback 被保留为生产成功响应。

**证据定位**
- `server/visionforge-platform/app/routes/client_api.py`
- `server/visionforge-platform/app/services/release_service.py`
- 无数据库 Release 时仍返回固定版本 `v17.8.81_update_lease_bridge_hardened` 和目录 URL。
- 另一更新接口在无发布时返回 404。

**前置任务**：`VF-P1-014`

**低能力 LLM 的修复步骤**
1. 所有版本端点统一调用 ReleaseService。
1. 无发布时统一 404/503 + `no_published_release`。
1. 删除硬编码版本和目录 URL。
1. 发布记录必须引用具体文件、大小、SHA-256、签名和兼容范围。

**GREEN 与业务验收**
- 无发布时所有接口一致失败。
- 有发布时 URL 指向不可变文件且哈希匹配。
- 撤销后不再返回该版本。

**禁止的伪修复**
- 换一个硬编码版本。
- 返回目录而非文件。
- 无发布返回空对象+200。

**人工门禁**：常规代码审查

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-P1-010｜P1｜已确认｜部署 smoke 只检查首页，制造“整站已就绪”的假绿灯

**实际业务症状**：部署脚本退出 0，但注册、支付、Sidecar、Bridge、Runtime、OTA 可以同时不可用。

**根因**：liveness、readiness 和业务 smoke 没有分层，且未按部署模式声明依赖。

**证据定位**
- `server/visionforge-platform/deploy/final_setup.sh`
- `server/visionforge-platform/deploy/validate_single_server_env.py`
- `server/visionforge-platform/app/main.py`
- final_setup 只 curl 8000 根页和 HTTPS 根页。
- 验证器不检查 SMTP、TOTP、Sidecar、Bridge、支付心跳、签名密钥或发布工件。

**前置任务**：`VF-P1-001`、`VF-P1-002`、`VF-P1-003`、`VF-P1-004`、`VF-P1-005`、`VF-P1-006`、`VF-P1-007`

**低能力 LLM 的修复步骤**
1. 新增 `/health/live` 只证明进程存活。
1. 新增 `/health/ready` 按模式检查 DB、Sidecar、Bridge、SMTP、支付心跳、签名材料、目录/工件。
1. 只返回稳定状态码和非敏感摘要。
1. final_setup 在 ready 后执行只读 bridge、注册模式、版本一致性、支付心跳 smoke。
1. systemd/负载均衡使用正确端点。

**GREEN 与业务验收**
- 逐个断开依赖时 readiness 精确变红，恢复后变绿。
- liveness 不因外部依赖短暂失败而反复重启。
- 部署仅在启用业务全部就绪时退出 0。

**禁止的伪修复**
- readiness 永远 200。
- 健康接口输出 secret/内部堆栈。
- 把所有外部故障当进程死亡。

**人工门禁**：常规代码审查

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-P1-011｜P1｜已确认｜Android 旧身份密钥升级/重绑定迁移被项目文档明确列为发布阻断项

**实际业务症状**：旧用户升级后可能丢失设备身份，导致配对、票据或权益失效，甚至必须清数据。

**根因**：只验证了新安装，没有旧 key→新 key 的双阶段迁移和失败恢复协议。

**证据定位**
- `android_inference_benchmark/README.md`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/**`
- `server/visionforge-platform/dual_machine_service/**`
- README 明确指出新 alias 测试不能证明旧安装迁移。
- 文档要求版本化 alias、服务端重绑/撤销/恢复，并称其为开放发布阻断项。

**前置任务**：`VF-P0-004`

**低能力 LLM 的修复步骤**
1. 定义状态机 legacy_active→new_pending→server_confirmed→legacy_retired。
1. 新 key 生成后保留旧 key，直到服务端确认且本地持久化。
1. 重绑必须同时由旧/新身份签名一次性 challenge。
1. 服务端保存迁移审计和恢复窗口。
1. 断网、崩溃、回滚时回到可恢复状态。
1. 建立跨历史版本物理设备矩阵。

**GREEN 与业务验收**
- 正常升级、断网、崩溃、重复重试、回滚再升级均恢复。
- 单持旧 key 或单持新 key 不能接管。
- 旧 key 只在确认后撤销。

**禁止的伪修复**
- 启动即删除旧 alias。
- 仅按设备 ID 无证明重绑。
- 把旧用户当新用户丢弃权益。

**人工门禁**：必须

**回滚**：停止新迁移并保持旧身份 active；已撤销旧 key 的设备走受审计恢复。

### VF-P1-012｜P1｜已确认｜Android 商业壳缺失：账户、购买、更新、帮助、EULA、错误报告未迁移

**实际业务症状**：面向付费用户时无法在 App 内完成购买/恢复权益/更新/支持；失败只表现为“没效果”而缺少诊断。

**根因**：核心运行时被抽取，但商业用户旅程和支持流程没有一起迁移。

**证据定位**
- `docs/DUAL_MACHINE_FEATURE_GAP_DECISION_MATRIX.md`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MainActivity.java`
- `android_inference_benchmark/app/src/main/**`
- 差距矩阵明确列出这些能力缺失或未迁移。
- MainActivity 主要提供 Card、Inference、Control。

**前置任务**：`VF-P0-005`、`VF-P1-007`

**低能力 LLM 的修复步骤**
1. 产品先定义最低商业壳。
1. 优先实现权益状态、更新检查、帮助/脱敏诊断、隐私/EULA。
1. 购买入口必须等待 VF-P0-005 的 SKU/交付语义批准。
1. 错误显示稳定错误码、重试性和 correlation_id。

**GREEN 与业务验收**
- 新用户能从安装到获得合法 entitlement 再启动会话。
- 过期、离线、维护、票据错、版本不兼容都有明确提示。
- 更新与正式 OTA manifest 一致。

**禁止的伪修复**
- 在 App 硬编码付款成功/entitlement。
- Toast“成功”代替服务端确认。
- 错误报告上传 secret/票据/完整设备标识。

**人工门禁**：必须

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-P1-013｜P1｜已确认｜仓库没有 CI 工作流，测试和发布门禁不会自动执行

**实际业务症状**：修复可在未运行测试、未验证私有工件和未触发安全门禁时直接进入 main。

**根因**：代码抽取未迁移持续集成和受保护发布流程。

**证据定位**
- `.github/workflows/**`
- `server/visionforge-platform/tests/**`
- `android_inference_benchmark/**`
- `dual_machine_runtime/**`
- 冻结仓库树中没有 `.github` 目录。
- 虽存在测试/门禁，但没有统一自动触发和分支保护。

**前置任务**：`VF-P0-003`、`VF-P1-014`、`VF-P2-004`

**低能力 LLM 的修复步骤**
1. Server job：锁依赖、导入、pytest、迁移/启动 smoke。
1. Sidecar job：pytest、DB、HMAC/票据负面测试。
1. Host job：CMake/build/unit；正式安全未完成时明确 blocked/expected fail。
1. Android 公共 job：wrapper 校验、依赖解析、lint/unit/gate。
1. QNN/模型/真机用受保护私有 runner；缺前置条件不得 green-skip。
1. main 设置必需检查和人工审查。

**GREEN 与业务验收**
- 故意破坏 TOTP、Bridge、manifest 或门禁时 CI 失败。
- 私有工件不可用时显示 blocked/failed。
- 工件附 commit、锁文件和哈希清单。

**禁止的伪修复**
- continue-on-error 掩盖核心检查。
- 缺私有依赖时跳过并标绿。
- workflow YAML 写生产 secret。

**人工门禁**：必须

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-P1-014｜P1｜已确认｜版本号、APK/Host 哈希和发布证据在多个文件间漂移

**实际业务症状**：服务器、Android、Host 和文档可能判断出不同的当前版本，造成错误升级、错误兼容判断或发布旧工件。

**根因**：版本、哈希和兼容范围由人工在多个文件重复维护，没有唯一发布事实源。

**证据定位**
- `dual_machine_runtime/README.md`
- `dual_machine_runtime/release_version.txt`
- `android_inference_benchmark/app/build.gradle`
- `docs/DUAL_MACHINE_FEATURE_GAP_DECISION_MATRIX.md`
- `release/**`
- README、release_version.txt、Gradle 和差距矩阵中的版本/工件证据不一致。
- 部分证据引用当前检出中不存在或被忽略的路径。

**前置任务**：`VF-P1-007`、`VF-P1-009`、`VF-P1-013`

**低能力 LLM 的修复步骤**
1. 建立不可变且签名的 release-manifest.json。
1. 字段至少含 release_id、commit、协议版本、各组件版本、URL、大小、SHA-256、key id、兼容范围。
1. Gradle/CMake/文档/服务器版本接口均由 manifest 或统一 version 文件生成。
1. CI 检查代码常量、工件和 manifest 一致。
1. 已发布 manifest 不原地修改，修正必须新建 release_id。

**GREEN 与业务验收**
- 一致性脚本当前修复后通过。
- 篡改任一版本/工件后 CI 失败。
- 服务器、OTA、Runtime、Android、Host 返回同一 release_id。

**禁止的伪修复**
- 只手工改几个字符串。
- 同版本号覆盖不同二进制。
- 目录名充当版本证明。

**人工门禁**：常规代码审查

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-P1-015｜P1｜已确认｜README 指示复制根 config.py，但运行时只读取 app.config/.env

**实际业务症状**：运维按文档填写配置后认为已生效，服务实际仍用另一套默认值，支付/域名/安全配置没有效果。

**根因**：历史配置机制未清理，文档、示例和代码代表不同代。

**证据定位**
- `server/visionforge-platform/README.md`
- `server/visionforge-platform/config.example.py`
- `server/visionforge-platform/run.py`
- `server/visionforge-platform/app/config.py`
- README 要求 config.example.py→config.py。
- run.py 启动 app.main，运行代码读取 app.config/.env。
- 根 config.py 未进入启动链，示例还含淘汰 PAYJS 变量。

**前置任务**：`VF-P1-010`

**低能力 LLM 的修复步骤**
1. 确定 `.env + app.config` 为唯一入口。
1. 删除或归档根 config.example.py。
1. 提供完整 `.env.example`，标注模式、默认、敏感性和验证规则。
1. 检测遗留根 config.py 时 fail-fast 或给一次性迁移提示，不能静默忽略。
1. 删除淘汰变量或建立正式映射。

**GREEN 与业务验收**
- 修改 .env 后行为可观察变化。
- 遗留 config.py 不会静默无效。
- 文档变量与代码变量双向一致。

**禁止的伪修复**
- 再加第三套配置加载器。
- 多个来源用不透明优先级覆盖。
- 示例文件填生产值。

**人工门禁**：常规代码审查

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-P1-016｜P1｜已确认｜架构文档含历史 320x320/CAT6-only 等过时口径，会误导修复

**实际业务症状**：低能力 LLM 可能根据旧文档恢复错误 ROI、网络能力或协议假设，制造回归。

**根因**：历史决策和当前规范混在同一文档，没有适用提交和状态标记。

**证据定位**
- `docs/DUAL_MACHINE_FEATURE_GAP_DECISION_MATRIX.md`
- `android_inference_benchmark/README.md`
- `android_inference_benchmark/app/src/main/**`
- `dual_machine_runtime/**`
- 差距矩阵自身说明部分内容早于后续 416/无线 fallback 迁移。
- 当前 README/代码体现更新架构。

**前置任务**：`VF-P1-014`

**低能力 LLM 的修复步骤**
1. 把历史内容移到 docs/archive，并写适用提交范围。
1. 建立 current contract，由 schema、常量和 release manifest 生成。
1. 文档 CI 检查尺寸/catalog、网络能力、协议版本和端点。
1. 任何 contract 变更必须同时改测试。

**GREEN 与业务验收**
- 旧口径只在 archive 且带 SUPERSEDED。
- 文档一致性脚本通过。
- 新开发者按 current 文档完成构建/E2E。

**禁止的伪修复**
- 删除全部历史证据。
- 只改文档不加契约测试。
- 让 LLM按多数文档投票决定规范。

**人工门禁**：常规代码审查

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-P1-017｜P1｜已确认｜所谓 portable fallback 构建仍被 QNN SDK/工件全局硬依赖

**实际业务症状**：无 QNN 环境无法构建 QA/兼容变体；“fallback”在实际构建中没有效果。

**根因**：产品变体和 Native target 没有按能力拆分，所有构建共用专有前置条件。

**证据定位**
- `android_inference_benchmark/app/build.gradle`
- `android_inference_benchmark/app/src/main/cpp/CMakeLists.txt`
- CMake 缺 QNN SDK/头/库即 FATAL_ERROR。
- QNN 工件校验全局绑定 Gradle 生命周期。

**前置任务**：`VF-P0-003`

**低能力 LLM 的修复步骤**
1. 先确认产品是否真正支持 portable。
1. 若支持，拆成 qnnProduction 与 portableQa；QNN 任务只绑定前者。
1. portableQa 使用实际存在且许可明确的 CPU/NNAPI/ORT 路径。
1. 公共预处理/后处理/schema 用共享契约测试。
1. 若不支持，删除误导声明并明确缺 QNN 时失败。

**GREEN 与业务验收**
- 无 QNN 可构建 portableQa，且不含占位 QNN 文件。
- qnnProduction 缺工件仍严格失败。
- 两变体在允许误差内满足输出契约。

**禁止的伪修复**
- 生产构建静默降级。
- 空 JNI 库通过链接。
- 删除 QNN 哈希校验。

**人工门禁**：常规代码审查

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-P2-001｜P2｜已确认｜支付金额槽位默认只有 1 个，15 分钟内同类订单只能有一笔

**实际业务症状**：并发购买时第二位用户得到 PAYMENT_SLOT_OCCUPIED，低流量测试正常、上线后随机无法下单。

**根因**：回调仅靠金额归属，为避免串单而以极低容量换安全。

**证据定位**
- `server/visionforge-platform/app/services/payment_service.py`
- PAYMENT_AMOUNT_SLOT_COUNT=1。
- 金额复用窗口约 15 分钟。

**前置任务**：`VF-P1-006`

**低能力 LLM 的修复步骤**
1. 优先使用可回传唯一 trade/order id 的支付协议。
1. 短期仍按金额时，设计可证明不冲突的唯一金额池并计算容量/过期/舍入。
1. 使用数据库唯一约束和事务分配。
1. 测试并发、取消、超时、延迟/重复回调和金额舍入。

**GREEN 与业务验收**
- 目标峰值并发可下单且唯一归属。
- 重复/延迟回调不串单。
- 容量耗尽时拒绝而非错误交付。

**禁止的伪修复**
- 只把槽位数调大。
- 按最近订单猜归属。
- 用浮点直接比较金额。

**人工门禁**：必须

**回滚**：恢复保守单槽位并限流，优先保证不串单。

### VF-P2-002｜P2｜已确认｜VF_APP_ROOT 可配置项被 systemd 单元硬编码路径抵消

**实际业务症状**：指定非默认根目录时，脚本写一个位置、systemd 从另一个位置启动，可能运行旧代码或直接失败。

**根因**：可配置路径没有贯穿 unit 模板。

**证据定位**
- `server/visionforge-platform/deploy/final_setup.sh`
- `server/visionforge-platform/deploy/vf.service`
- `server/visionforge-platform/deploy/vf-dual-machine.service`
- final_setup 支持 VF_APP_ROOT。
- 两个 unit 固定 `/home/ubuntu/vf-platform`。

**前置任务**：`VF-P1-001`

**低能力 LLM 的修复步骤**
1. 选择真正支持或删除该选项并 fail-fast。
1. 支持时用受控模板渲染 WorkingDirectory/ExecStart/EnvironmentFile。
1. 执行 systemd-analyze verify、daemon-reload 和真实启动。
1. readiness 显示运行提交和非敏感根目录标识。

**GREEN 与业务验收**
- 默认和一个非默认路径均部署成功。
- 进程 cwd、环境、静态目录指向同一发布目录。
- 不会启动旧目录残留版本。

**禁止的伪修复**
- 软链接掩盖不一致。
- 声称支持但只测默认路径。

**人工门禁**：常规代码审查

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-P2-003｜P2｜已确认｜部署 QR 工具导入 qrcode，但依赖未声明

**实际业务症状**：运维运行二维码工具直接 ImportError，辅助部署流程不可用。

**根因**：部署工具依赖未与运行依赖分层和锁定。

**证据定位**
- `server/visionforge-platform/deploy/gen_qr.py`
- `server/visionforge-platform/requirements.txt`
- gen_qr.py 导入 qrcode。
- requirements.txt 不含 qrcode/Pillow。

**前置任务**：`VF-P2-004`

**低能力 LLM 的修复步骤**
1. 建立 requirements-deploy.lock，固定 qrcode 与图像后端版本/哈希。
1. 工具检查输出目录、输入 URL 和覆盖策略。
1. 增加生成 PNG、解码内容和非零尺寸 smoke。

**GREEN 与业务验收**
- 干净环境安装 deploy lock 后成功。
- 缺依赖时明确失败，不输出损坏文件。
- 二维码不含 secret。

**禁止的伪修复**
- 脚本内自动 pip install。
- 捕获 ImportError 后仍报告成功。

**人工门禁**：常规代码审查

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-P2-004｜P2｜已确认｜Python requirements 只有宽松下限，无运行锁和测试锁

**实际业务症状**：同一提交在不同时间安装出不同依赖；默认环境也不能可靠运行 pytest。

**根因**：直接依赖、完整运行锁、开发测试锁和升级流程未分离。

**证据定位**
- `server/visionforge-platform/requirements.txt`
- `server/visionforge-platform/tests/**`
- 依赖使用宽松下限。
- 缺完整解析锁、哈希及 pytest/dev 环境定义。

**前置任务**：`VF-P1-013`

**低能力 LLM 的修复步骤**
1. 建立 requirements.in 与带哈希 requirements.lock。
1. 建立 requirements-dev.in/lock 并包含运行锁。
1. CI/生产只安装 lock。
1. 依赖升级使用独立 PR 和完整回归。

**GREEN 与业务验收**
- 两台干净机器得到一致依赖树。
- pytest 无需临时装包。
- 锁哈希被改时安装失败。

**禁止的伪修复**
- 继续使用 latest 兼容。
- 把整个个人开发环境无审查 freeze。
- 测试时临时联网安装。

**人工门禁**：常规代码审查

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-P2-005｜P2｜已确认｜Platform 使用不轮转 FileHandler，长期运行可写满磁盘

**实际业务症状**：日志持续增长最终可能让 SQLite、支付、会话和系统服务同时写失败。

**根因**：日志输出和宿主机保留策略没有统一。

**证据定位**
- `server/visionforge-platform/app/main.py`
- `server/visionforge-platform/deploy/**`
- main.py 写 `server_logs/server.log`。
- 仓库未发现配套 logrotate/轮转配置。

**前置任务**：`VF-P1-010`

**低能力 LLM 的修复步骤**
1. 优先使用 journald，或使用 RotatingFileHandler/logrotate。
1. 定义大小、数量、压缩、天数和磁盘告警。
1. 加入 correlation_id，脱敏 secret/验证码/票据。
1. 做 72 小时 soak 和磁盘低水位测试。

**GREEN 与业务验收**
- 压力写日志后占用有上限。
- 轮转不丢关键审计。
- 敏感字段测试通过。

**禁止的伪修复**
- 关闭全部日志。
- 只靠人工清理。
- 删除唯一支付/授权审计。

**人工门禁**：常规代码审查

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-V-001｜P0-CANDIDATE｜必须动态验证｜`onnxruntime-android:1.27.0` 可能无法从配置仓库解析

**实际业务症状**：若 Android AAR 实际未发布或仓库不可见，构建在依赖解析阶段硬失败。

**根因**：版本可能超出 Android AAR 可用范围，或缺少受控镜像和校验锁。

**证据定位**
- `android_inference_benchmark/app/build.gradle`
- `Gradle repository/verification configuration`
- Gradle 固定 `com.microsoft.onnxruntime:onnxruntime-android:1.27.0`。
- 公开索引信息不一致，必须以 Gradle 实际解析为准。

**前置任务**：`VF-P0-003`

**低能力 LLM 的修复步骤**
1. 清空缓存运行 `./gradlew :app:dependencies --configuration debugRuntimeClasspath`。
1. 保存实际仓库、POM/AAR 和 SHA-256。
1. 若可解析，写 verification metadata；若不可解析，选择实际发布且 API 兼容的版本。
1. 版本变化后运行编译、模型加载和推理契约测试。

**GREEN 与业务验收**
- 干净缓存稳定解析。
- AAR 受校验元数据约束。
- 输入/输出 schema 与业务行为不变。

**禁止的伪修复**
- 盲目降级。
- 关闭依赖校验。
- 从不可信网盘复制 AAR。

**人工门禁**：常规代码审查

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-V-002｜P1-CANDIDATE｜必须动态验证｜邮件验证码可能缺少足够的多维限流和 SMTP 配额保护

**实际业务症状**：可能被同 IP 多邮箱或多 IP 同邮箱耗尽 SMTP 配额，影响正常注册。

**根因**：通用 API 限速未必覆盖高成本邮件动作。

**证据定位**
- `server/visionforge-platform/app/routes/time_api.py`
- `server/visionforge-platform/app/services/email_service.py`
- `server/visionforge-platform/deploy/nginx.conf`
- 已见单地址冷却和通用 Nginx 限速，但未在完整环境证明 IP、目标、账户、全局配额和失败退避组合保护。

**前置任务**：`VF-P1-004`

**低能力 LLM 的修复步骤**
1. 在 staging 测同 IP 多邮箱、同邮箱多 IP、并发和 SMTP 失败重试。
1. 若有缺口，增加 IP/目标/设备/全局令牌桶和每日配额。
1. SMTP 失败采用有上限退避。
1. 响应不泄露邮箱是否存在；监控发送率、拒绝和限流命中。

**GREEN 与业务验收**
- 攻击模式下真实发送量受预算约束。
- 正常用户可注册。
- 多进程/重启后限流仍有效。

**禁止的伪修复**
- 回显验证码。
- 仅进程内字典做多实例限流。
- 无限重试 SMTP。

**人工门禁**：常规代码审查

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

### VF-V-003｜P1-CANDIDATE｜必须动态验证｜未发现主库、Sidecar 库、密钥和发布清单的一致代灾备契约

**实际业务症状**：若恢复只还原数据库或重新生成密钥，会出现票据全失效、Bridge 失配、重复交付和审计断裂。

**根因**：跨组件状态和密钥没有机器可执行的恢复点目标与顺序。

**证据定位**
- `server/visionforge-platform/deploy/**`
- `server/visionforge-platform/dual_machine_service/**`
- `release/**`
- 源码含多数据库和多类长期密钥。
- 仓库中未定位到可验证的一致性备份/恢复演练；线上可能有外部系统，故必须动态确认。

**前置任务**：`VF-P0-004`、`VF-P0-005`、`VF-P1-014`

**低能力 LLM 的修复步骤**
1. 先检查现网外部备份覆盖、加密、频率和最近演练。
1. 若缺失，定义 recovery generation：主库、Sidecar 库、key id/引用、release manifest、配置版本。
1. 恢复前阻断写流量，验证指纹，再按 Sidecar→Platform→worker 启动。
1. 重放待处理回调/outbox并验证不重复交付。
1. 定期演练 RPO/RTO。

**GREEN 与业务验收**
- 隔离环境全业务 smoke 通过。
- 恢复不生成新生产签名密钥。
- 重复回调/outbox不重复交付。

**禁止的伪修复**
- 只复制 SQLite 主文件忽略一致性/WAL。
- 恢复时自动生成生产私钥。
- 直接在生产试恢复。

**人工门禁**：必须

**回滚**：回退到上一份已验证配置或工件，并保留审计记录。

## 7. 真实环境动态验证矩阵

以下测试是上线硬条件。低能力 LLM 可以准备脚本，但真实密钥、付款、物理设备和灾备切换必须由人工执行。

### DV-01｜干净 Ubuntu 完整部署

**步骤**
1. 从空主机执行唯一 full-dual-machine 入口。
1. 重跑一次验证幂等并重启主机。

**通过标准**
- 两个 systemd unit active。
- liveness/readiness 分层正确。
- Platform bridge probe 成功。

### DV-02｜管理员 TOTP

**步骤**
1. 测试正确、错误、过期验证码。
1. 隔离环境移除 pyotp 后重启。

**通过标准**
- 合法码成功、非法码拒绝。
- 依赖缺失时启动 fail-fast。

### DV-03｜真实邮件注册

**步骤**
1. 向受控邮箱请求验证码并注册。
1. 重放验证码并关闭 SMTP 重试。

**通过标准**
- 真实送达、一次使用、重放失败。
- SMTP 故障触发 degraded/ready 失败。

### DV-04｜支付监控和幂等

**步骤**
1. 验证 monitor 签名心跳。
1. 完成 staging 真实付款。
1. 重复回调并在回调中途重启。

**通过标准**
- pending→paid→fulfilled 恰好一次。
- 余额/entitlement 不重复。
- 心跳过期按策略停止新订单。

### DV-05｜付款到双机 entitlement

**步骤**
1. 按批准 SKU 购买。
1. 制造 Sidecar 5xx、超时和重复 worker。

**通过标准**
- 最终交付一次且有 correlation_id。
- 失败可重试，不虚报到账。

### DV-06｜Usage-ticket 密钥互操作

**步骤**
1. 服务端签固定测试票据，Android/Host 验证。
1. 测试错误私钥、未知 key id、篡改和过期。

**通过标准**
- 正确票据两端接受。
- 错误票据全部 fail-closed。
- 错私钥时生产服务不 ready。

### DV-07｜Android 干净构建

**步骤**
1. 清 Gradle 缓存解析依赖。
1. 按 artifact-lock 拉取私有工件。
1. 执行 QA/Release 对应任务。

**通过标准**
- 依赖和哈希稳定。
- 缺/改工件早期失败。
- 正式门禁未满足时 Release 仍失败。

### DV-08｜真实双机生命周期

**步骤**
1. 激活、配对、开始、连续心跳、停止。
1. 测试断网、乱序、重启、票据到期和时钟偏差。

**通过标准**
- 设备与服务端状态一致。
- 计费/授权恰好一次。
- 无幽灵会话和无授权继续运行。

### DV-09｜Android 旧版升级迁移

**步骤**
1. 上一受支持版本创建 legacy identity 后覆盖升级。
1. 各迁移阶段断网、杀进程、回滚再升级。

**通过标准**
- 身份与权益不丢。
- 旧 key 仅确认后退役。
- 失败可恢复且不可无证明接管。

### DV-10｜Runtime Catalog 与 OTA

**步骤**
1. 发布签名 Runtime/APK。
1. 下载并核验 manifest、大小、SHA-256、签名。
1. 篡改工件并回滚 manifest。

**通过标准**
- 正确工件可用、篡改拒绝。
- 所有端点同一 release_id。
- 中断发布不破坏上一版。

### DV-11｜灾备恢复

**步骤**
1. 恢复同一代主库、Sidecar 库、密钥引用和 manifest。
1. 重放待处理回调/outbox并做全业务 smoke。

**通过标准**
- 不生成新生产签名密钥。
- 不重复交付。
- RPO/RTO 达标。

### DV-12｜72 小时稳定性

**步骤**
1. 持续合法心跳、更新检查、注册失败和支付查询。
1. 观察日志、SQLite/WAL、文件句柄、内存、CPU、磁盘。

**通过标准**
- 磁盘增长受控。
- 无资源泄漏、锁死或心跳漂移。
- 告警可触发并恢复。

## 8. 上线 Go/No-Go

- [ ] Android 与 Host 正式安全门禁只由真实实现、负面测试和人工审查解除。
- [ ] usage-ticket 私钥与已发布客户端公钥指纹一致，具备 key id、轮换和恢复。
- [ ] 干净检出可按 artifact-lock 重建，不依赖个人机器路径。
- [ ] 完整部署同时接通 Platform、Sidecar、Bridge、SMTP、支付 monitor、Runtime、OTA。
- [ ] 注册邮件真实送达，支付真实回调，重复回调不重复交付。
- [ ] 产品批准主站余额与双机 entitlement 的关系，付款后权益可审计。
- [ ] 无状态 heartbeat 和硬编码版本伪成功已删除。
- [ ] Release manifest 是唯一版本/哈希事实源。
- [ ] 旧身份升级在真实设备上通过断网、崩溃和回滚。
- [ ] CI、分支保护、灾备恢复和 72 小时 soak 已通过。

任意一项未勾选，结论均为 **NO-GO**。

## 9. 最终完成定义

- 干净检出加受控私有工件可重建所有声明支持的工件。
- 生产模式必需配置在监听业务流量前验证，缺失时 fail-fast 或明确禁用。
- Platform、Sidecar、Host、Android 使用同一协议版本、key id、发布清单和测试向量。
- 核心 API 的每个成功响应都有数据库变化、持久事件或可验证输出。
- 支付、余额、Sidecar entitlement、退款/撤销具有幂等、审计和补偿。
- liveness、readiness、业务 smoke 分离，不存在首页绿而核心业务红。
- 正式安全门禁只能由真实实现、自动测试和人工审查解除。
- CI、分支保护、签名发布和灾备演练生效。

## 10. 结论

当前项目的主要风险不是“算法效果不够好”，而是正式构建被门禁、部署未接通组件、配置入口失真、支付与授权域分离、接口伪成功、密钥与发布证据漂移。必须先恢复可复现性和业务事实，再讨论功能增强。只让页面、编译或单个组件变绿，不算修复完成。

机器可读任务账本：`visionforge_repair_task_ledger.json`。
