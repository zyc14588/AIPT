# 安全（SECURITY）

> 公开安全设计合同。机器权威见 [../authority/registry/decisions.json](../authority/registry/decisions.json)。
> **本节全部为设计目标，B000 未实现任何运行时代码。**

## 信任边界

- **来源只读**：游戏与代码来源以固定 Commit 独立只读检出，运行目录分离（`R2-Q004`）；Codex 对远端仓库只读（`R10-Q005`）。
- **Agent 不可直接写状态**：Agent 只提交意图；Core 经 Schema、授权、规则、不变量校验后提交权威事件（`R5-Q008`）。
- 外层容器/OS 沙箱 + Harness 沙箱 + 只读来源 + 最小权限，纵深防御（`R4-Q014`）。

## 信息隔离与 ACL

- 每席位独立 Session 与显式信息投影（`R2-Q016`）；每次模型调用前由 Core 生成席位授权视图（`R5-Q006`）。
- **ACL 先于检索**：先过滤语料，再精确/混合检索与引用验证（`R5-Q017`）。
- 内容使用显式可见性标签，未标记 fail-closed（`R13-Q015`）。

## 数据/内容分类

六类字段级分类（`R4-F002`），远端发送按分类实施：

- `PUBLIC`：可公开。
- `UNRELEASED_REMOTE_ALLOWED`：未发布但允许按策略发送远端模型。
- `TABLE_HIDDEN_REMOTE_ALLOWED`：桌面隐藏信息，按策略允许远端。
- `LOCAL_ONLY_SECRET`：**默认阻塞**远端发送；仅诊断 break-glass 可外发且运行失格（`R6-F002`）。
- `HUMAN_PRIVATE`：真人隐私数据。
- `CREDENTIAL`：凭据。

## 提示注入防护

规则书、模组和日志内容一律作为**不可信数据**处理，防提示注入（`R5-Q018`）。

## 凭据与密钥

- 凭据字段只写不读，保存后只返回引用与验证状态（`R7-Q005`）。
- 可替换凭据提供器；首版加密本地文件与环境变量引用（`R7-Q006`）。
- Codex 的 GitHub 只读凭据通过受控 Credential Helper/代理注入，Codex 不读取令牌（`R11-F002`）。

## 本地端点与界面

- 本地模型端点默认仅 **Loopback**（`R6-Q020`）。
- 本地 Web UI 使用动态 Loopback 端口（`R7-Q014`）；loopback llama.cpp 首版不设置 API Key（`R7-Q017`）。

## 不可豁免门禁

Commit/Tree、哈希/签名、凭据、隐藏信息、权威状态、账本完整性等硬门禁**不得**被管理员覆盖（`R16-Q003`）。开发 Break-glass 仅可越过非完整性门禁且产物无生产/发行资格（`R16-Q004`）。

## 私有提示词政策

本公共仓库不含私有提示词正文。全部提示词资产仅保存在本地加密 Git 仓库、无远端、不公开（`R13-F001`、`R0-Q009`）。

## 设计状态声明

以上均为**冻结设计合同**，安全能力由后续批次实现；B000 仅安装本文档。

## 相邻文档

- [../authority/README.md](../authority/README.md) · [../authority/DECISION_MATRIX.md](../authority/DECISION_MATRIX.md) · [../architecture/README.md](../architecture/README.md) · [../evidence/README.md](../evidence/README.md)
- [返回仓库首页](../../README.md)
