# 证据与审计（EVIDENCE）

> 公开证据流水线设计合同。机器权威见 [../authority/registry/decisions.json](../authority/registry/decisions.json)。
> **本节全部为设计目标；B000 使用简化的 Bootstrap 证据路径（见文末）。**

## 权威来源

- **事件账本是证据权威**：PostgreSQL 追加式哈希链事件账本；快照/投影可重建（`R4-Q008`、`R4-Q009`）。
- 只有已推送权威远端的不可变 Commit 可正式审计（`R9-Q004`）。

## 流水线：RAW_CAPTURE → AUDIT_READY → AUDIT_RESULT

1. `RAW_CAPTURE`：AIPT Evidence Exporter 捕获原生证据（`R10-Q004`、`R9-F001`）。
2. `AUDIT_READY`：Codex CLI 只读核验远端 Commit、规范化证据并生成审计包（`R9-F001`、`R10-Q005`）。
3. `AUDIT_RESULT`：GPT 主审产出结构化审计结论（`R9-F001`、`R10-F003`）。

Canonical JSON 为机器权威；审计包以版本化 JSON Manifest 为机器权威（`R10-Q002`）。

## 披露 Profile

- `PUBLIC`：默认不加密。
- `EXTERNAL_AUDITOR`：含未发布内容时默认加密。
- `PRIVATE_FULL`：强制加密（`R10-Q012`）。

## 哈希、分块、签名与加密

- 所有包执行**确定性规范化**：同语义输入产生同根哈希（`R10-Q003`）。
- 超体积证据**内容寻址分块**与分卷，不截断必需证据（`R10-Q009`）。
- 签名默认 Ed25519 并保留算法替换接口；签名密钥与证据加密密钥用途/材料分离（`R10-Q014`、`R10-Q013`）。
- 签名密钥版本化轮换并保留旧包验证能力（`R10-Q015`）。
- 开发包可选签名，签名不赋予生产资格（`R10-Q016`）。

## 角色分工

| 角色 | 职责 |
|---|---|
| AIPT / Harness | 产出 `RAW_CAPTURE` |
| Codex CLI | 只读核验、规范化、生成 `AUDIT_READY`；只写独立 audit-output（`R10-Q005`、`R11-Q003`） |
| GPT | 主要实质审计，产出 `AUDIT_RESULT`（`R10-F003`） |
| Claude Web | 独立第二审计；`FAIL`/`BLOCKED` 触发 `AUDIT_DISPUTE` 与 `MERGE_HOLD`（`R10-F003`） |

## 开发与生产的验证差异

- 开发：允许引用封存父包的增量包；生产/发行使用自包含包（`R10-Q008`）。
- 开发命令证据较轻（记录命令/退出码即可）；生产/发行测试、构建、迁移与资格命令保存完整执行身份（`R11-F001`、`R12-F004`）。
- 生产/发行追加完整证据资格、签名与核心环境完整性验证（`R10-F002`）。
- 开发可风险接受；生产和发行双审计冲突不能仅靠风险接受合并（`R16-Q005`）。

## B000 Bootstrap 简化证据路径

`AIPT-M0-B000` 尚无 Evidence Adapter 与 CI（`BOOTSTRAP-Q001`）：

- 以**最终本地确定性验收 + GPT 治理/文档审计**关闭批次；
- 保存最终必需验收结果、候选 Commit 与远端核验记录，不保存探索过程（`R12-F004`）；
- `AIPT-M0-B001` 建立公共 CI 后追溯验证 B000；该简化路径**不适用于** B001 之后的普通批次。

## 相邻文档

- [../authority/README.md](../authority/README.md) · [../authority/DECISION_MATRIX.md](../authority/DECISION_MATRIX.md) · [../security/README.md](../security/README.md) · [../milestones/MVP.md](../milestones/MVP.md)
- [返回仓库首页](../../README.md)
