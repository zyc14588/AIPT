# 证据与审计（EVIDENCE）

> 公开证据流水线设计合同。机器权威见 [../authority/registry/decisions.json](../authority/registry/decisions.json)。
> M0-B006 已实现最小 `RAW_CAPTURE` exporter/verifier 与三阶段公开 Schema。当前 merged B005 implementation 为 `MERGED_POST_MERGE_SECURITY_BLOCKED`：其 offline remote-provenance model 为 `NOT_ACCEPTED`。`ONLINE_GITHUB_REMOTE_PROVENANCE_V1` 已 `AUTHORITY_DEFINED`，治理 lifecycle 已 `CLOSED`；R1 production implementation 为 `IMPLEMENTED_PENDING_INDEPENDENT_ACCEPTANCE`。B000 使用简化的 Bootstrap 证据路径（见文末）。
> `B006 = MERGED_CLOSED`：Candidate `3987b8d4c26ac079d01c214ba90e113eeffd5713`（tree `4271a3fb71236a8b003b4d9ddc84727c6fec8d46`，CI `32577246851` success）；implementation merge `35acba9fb629f50087def3b720df304fadfd2158`（相同 tree），post-merge CI `32578143923` success。

## 当前能力矩阵

| 能力 | 状态 |
|---|---|
| `RAW_CAPTURE_EXPORT` | `IMPLEMENTED_MINIMAL` |
| `AUDIT_READY_SCHEMA` | `IMPLEMENTED` |
| `AUDIT_READY_GENERATOR` | `MERGED_POST_MERGE_SECURITY_BLOCKED` |
| `AUDIT_READY_VERIFIER` | `MERGED_POST_MERGE_SECURITY_BLOCKED` |
| `OFFLINE_REMOTE_PROVENANCE_MODEL` | `NOT_ACCEPTED` |
| `ONLINE_GITHUB_REMOTE_PROVENANCE_V1` | `AUTHORITY_DEFINED_IMPLEMENTATION_PENDING_R1` |
| `RUN_EVIDENCE_CLOSURE` | `IMPLEMENTED_B005` |
| `REPLAY_EVIDENCE_CONTRACT` | `IMPLEMENTED_B005` |
| `DEFECT_FAMILY_OCCURRENCE_CONTRACTS` | `IMPLEMENTED_B005` |
| `RUN_REPORT_CANONICAL_AND_DERIVATIVES` | `IMPLEMENTED_B005` |
| `AUDIT_RESULT_SCHEMA` | `IMPLEMENTED` |
| `AUDIT_RESULT_GENERATOR` | `NOT_IMPLEMENTED` |
| `SIGNING` | `NOT_IMPLEMENTED` |
| `ENCRYPTION` | `NOT_IMPLEMENTED` |
| `CHUNKING` | `IMPLEMENTED_B005_CONTENT_ADDRESSED` |

原有公开 Schema 根 [aipt-evidence.schema.json](../../schemas/evidence/v1/aipt-evidence.schema.json) 保持字节不变：Draft 2020-12、根为严格三阶段 `oneOf`、未知 version/stage/字段拒绝。M0-B006 runtime 仍只生成 `RAW_CAPTURE`。Merged B005 添加了 `AUDIT_READY` contracts 与 implementation，但该 implementation 因 remote provenance security failure 尚未被接受或关闭；`AUDIT_RESULT` 仍只有 Schema，没有 generator。

## 最小 RAW_CAPTURE

[`internal/evidence`](../../internal/evidence) 的原生 Go exporter 从 B003 ledger 读取一个完整 stream，输出权限为目录 `0700`、文件 `0600` 的精确三文件目录：

- `events.ndjson`：sequence `1..N`，每行由既有 `internal/protocol.CanonicalJSON` 生成 canonical JSON + 单 LF；保留数据库 exact `payload_canonical` TEXT，`committed_at` 规范化为 UTC RFC3339Nano。
- `manifest.json`：canonical JSON + LF，绑定 source repo/commit/tree、`LEDGER_STREAM`、verified count/tail、normalization version，以及 `events.ndjson` 的 exact byte length/SHA-256。
- `ROOT.sha256`：`SHA-256(manifest.json exact bytes)` 的 lowercase 64hex + LF。

Exporter 在同一文件系统的私有临时 sibling 中写入、fsync、调用独立 verifier 自检后才 rename 发布；existing final（包括 symlink）拒绝，失败清理临时目录，不留下貌似完成的 final。Verifier 要求精确文件集、无 extra/symlink、canonical bytes、root/asset hash、完整 sequence/stream/count/tail、payload SHA、previous-hash chain 与 UTC 时间；它只验证 capture 自身一致性，不复制 B003 event-hash preimage。

稳定错误类别覆盖 `AIPT_EVIDENCE_INVALID_INPUT`、`AIPT_EVIDENCE_UNSAFE_PATH`、`AIPT_EVIDENCE_TARGET_EXISTS`、`AIPT_EVIDENCE_LEDGER_VERIFY_FAILED`、`AIPT_EVIDENCE_STREAM_CHANGED`、`AIPT_EVIDENCE_WRITE_FAILED` 与 `AIPT_EVIDENCE_BUNDLE_INVALID`；包装错误仍保留 B003 原始 ledger 校验错误的 `errors.Is` 语义，错误文本不回显 payload。

PostgreSQL source 先调用 B003 `postgres.VerifyStream` 得到 `N/H`，再以 read-only transaction 只执行 `SELECT ... sequence <= N ORDER BY sequence ASC`，要求精确 N 条且最后 hash 为 H；结束前重读 cursor，变化则返回 `AIPT_EVIDENCE_STREAM_CHANGED`。公共 CI 只连接 digest-pinned、loopback-only 的 ephemeral PostgreSQL 18.4，并只使用完全合成 PUBLIC 数据；不得连接生产数据库。

RAW_CAPTURE 是本地原生证据，M0-B006 不自动外传，不调用网络、远端模型、construction Harness 或 GitHub API。Manifest/root 语义不含 export wall clock、hostname、PID、username、本机绝对路径、DSN 或 credential；没有 `max-events` 成功截断模式。B005 不改变这些语义。

## B005 AUDIT_READY blocked merged implementation

Merge `c07e1aae94f681733ad73c1800423248bcc72376`（tree `828defa8ea85a757b43d1a04ce05016ebeea9020`）的 CI `33767358596` 为 success，但 post-merge security 为 `FAIL`；没有 lifecycle records，且该 merge 不是 final accepted merge。以下描述仅记录当前 blocked implementation，不表示其 remote provenance 已满足 Authority。

R1 [`GenerateAuditReady`](../../internal/evidence/audit_ready.go) 首先验证并持有 RAW_CAPTURE 描述符，再由内建固定 HTTPS 核验器向 `api.github.com` 匿名 GET 精确 Git commit object，逐字核对 Commit 与 Tree。公开生成与独立验证接口不接受 verifier/client/endpoint/proxy/CA 注入；测试替身只存在于 package-private seam。8 字段 canonical `remote-provenance.json` 作为强制 PUBLIC/CONTRACT logical asset 进入 bundle index 与 root；时间、HTTP metadata、凭据和本机 locator 不进入 receipt。规范化、private sibling、fsync、自验证、输入稳定性复验与 no-replace publish 继续有效。旧 c07e1aa merge 的离线 remote claim 保持 NOT_ACCEPTED；R1 尚待独立验收。

新增的 additive schemas 为：

- [Run Evidence Closure](../../schemas/evidence/v1/aipt-run-evidence-closure.schema.json)：绑定 Run Manifest、source、PostgreSQL ledger tail、action receipts、projection、Rule、RNG、replay、coverage、defect occurrence、anomaly、gate 与 model/Harness evidence identity。
- [Defect contracts](../../schemas/evidence/v1/aipt-defect-contracts.schema.json)：分离 family 与 occurrence；稳定 projection 经 canonical JSON → SHA-256。不同 fingerprint 只能产生 `SEMANTIC_DUPLICATE_CANDIDATE`。状态名称由外部 Authority policy 提供，B005 只执行显式图与 append-only hash-linked decisions。
- [Run Report](../../schemas/evidence/v1/aipt-run-report.schema.json)：Canonical JSON 为权威，Markdown/CSV/JUnit/静态 HTML 均可逐字节再生；生命周期严格为 `PROVISIONAL → FINALIZING → SEALED`，SEALED 后只能新增 addendum，不能隐式 unseal。
- [Bundle Index](../../schemas/evidence/v1/aipt-audit-ready-bundle-index.schema.json)：内含版本化 `aipt.core-evidence-classification/v1` 权威，显式覆盖 `RAW_CAPTURE`、Run closure、Replay、Defect family/occurrence、Run Report 与 derivatives；RAW 三件套确定性继承 `RAW_CAPTURE`，四种 report derivatives 必须继承 canonical Run Report classification。缺失/未知 classification 失败关闭，声明与每个 core descriptor 一并进入确定性 bundle/root 身份。部署 `ExportProfile` 提供 inline/chunk/size/count 参数；大资产按 exact bytes SHA-256 分块、跨逻辑资产安全去重并逐字节重组，从无成功截断模式。

命令 `go run ./cmd/aipt-audit-ready generate --spec <request>` 与 `verify --bundle <directory> --repository <https-identity>` 使用固定在线核验入口。`mirror_path` / `--mirror <bare-mirror>` 可选，且只能返回 `LOCAL_OBJECT_MATCH` 辅助一致性事实；网络不可用、限流、404 或不支持 provider 时均不可使用镜像兜底。Git 子进程固定 executable/argv，无签名显示、hooks、fsmonitor、lazy fetch；每个 stdout/stderr 在捕获前上限 4096 bytes，整体 deadline 5 秒，取消时终止其进程组。

Owner Authority [AIPT-MVP-B005 Remote Provenance Authority 001](../authority/amendments/AIPT_MVP_B005_REMOTE_PROVENANCE_AUTHORITY_001.md) 与 machine policy [remote-provenance-policy.json](../authority/registry/remote-provenance-policy.json) 现冻结：Development MVP 仅支持 `PUBLIC_GITHUB_REPOSITORY`；内建 `GITHUB_PUBLIC_HTTPS_API_V1` 必须对固定 `api.github.com` endpoint 执行无凭据、禁止 redirect、bounded、fail-closed 的 online exact Commit/Tree verification。AUDIT_READY generation 与 independent verification 各自重新执行一次，不信任 bundle 内既有 claim、旧 cache 或 mirror fallback。Private GitHub 与 non-GitHub remotes 当前均为 unsupported。

R1 还必须生成 deterministic `aipt.remote-provenance/v1` receipt，字段仅为 `schema`、`version`、`policy_id`、`provider`、`repository`、`commit`、`tree`、`status`，并绑定进 deterministic bundle/root。Receipt 不记录 verification time、HTTP metadata、request identity、rate-limit state、主机/本地路径、credential 或 response body。同一 stable provenance fact tuple 产生相同 canonical bytes；legacy RAW_CAPTURE v1 语义保持不变。

正式 N01–N50 负向矩阵位于 [b005-negative-matrix.json](../../testdata/evidence/v1/b005-negative-matrix.json)；N36–N41 对应 security repair F1-N01…F1-N06，N42–N49 对应 F2-N01…F2-N08，N50 对应 F3-N01。Authority recovery 与逐项 acceptance mapping 位于 [B005 Authority Matrix](B005_AUTHORITY_MATRIX.md)。公共 PostgreSQL gate 只使用 ephemeral loopback 18.4 与 synthetic PUBLIC 数据，重复生成必须 file-set/bytes/root 完全相同；该 smoke 不计 qualification。

## 权威来源

- **事件账本是证据权威**：PostgreSQL 追加式哈希链事件账本；快照/投影可重建（`R4-Q008`、`R4-Q009`）。
- 只有已推送权威远端的不可变 Commit 可正式审计（`R9-Q004`）。

## 流水线：RAW_CAPTURE → AUDIT_READY → AUDIT_RESULT

1. `RAW_CAPTURE`：AIPT Evidence Exporter 捕获原生证据（`R10-Q004`、`R9-F001`）。
2. `AUDIT_READY`：Codex CLI 只读核验远端 Commit、规范化证据并生成审计包（`R9-F001`、`R10-Q005`）。
3. `AUDIT_RESULT`：GPT 主审产出结构化审计结论（`R9-F001`、`R10-F003`）。

Canonical JSON 为机器权威（`R8-Q021`）；审计包以版本化 JSON Manifest 为机器权威（`R9-Q002`）；版本化审计 Schema 在公开仓库维护（`R10-Q002`）。

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
| Claude Web | 独立第二审计；`FAIL`/`BLOCKED` 触发 `AUDIT_DISPUTE` 与 `MERGE_HOLD`（`R10-F003`、`R9-F003`） |

## 开发与生产的验证差异

- 开发：允许引用封存父包的增量包；生产/发行使用自包含包（`R10-Q008`）。
- 开发命令证据较轻（记录命令/退出码即可）；生产/发行测试、构建、迁移与资格命令保存完整执行身份（`R11-F001`、`R12-F004`）。
- 生产/发行追加完整证据资格、签名与核心环境完整性验证（`R10-F002`、`R9-Q015`、`R9-F002`、`R10-Q016`）。
- 开发可风险接受；生产和发行双审计冲突不能仅靠风险接受合并（`R16-Q005`）。

## B000 Bootstrap 简化证据路径

`AIPT-M0-B000` 尚无 Evidence Adapter 与 CI（`BOOTSTRAP-Q001`）：

- 以**最终本地确定性验收 + GPT 治理/文档审计**关闭批次；
- 保存最终必需验收结果、候选 Commit 与远端核验记录，不保存探索过程（`R12-F004`）；
- `AIPT-M0-B001` 建立公共 CI 后追溯验证 B000；该简化路径**不适用于** B001 之后的普通批次。

## 相邻文档

- [../authority/README.md](../authority/README.md) · [../authority/DECISION_MATRIX.md](../authority/DECISION_MATRIX.md) · [../security/README.md](../security/README.md) · [../milestones/MVP.md](../milestones/MVP.md)
- [返回仓库首页](../../README.md)

R1 验证：历史 N01–N50 matrix 字节不变，新增 [P01–P12](../../testdata/evidence/v1/b005-r1-remote-provenance-matrix.json) 与真实 Git helper/output 安全夹具。所有公共 CI 测试使用内部合成响应，实际 GitHub 请求与模型调用均为 0；这些夹具不代表真实桌测或 qualification。在线验收仅在 Owner 本地执行，独立 CI catalogue 以接受的 main 为信任依据。
