# UNREGISTERED P1 B000 Authority Amendment-002

任务：`UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-002`

状态：`CANDIDATE_FROZEN`（尚未 accepted；不得 merge、closeout 或启动 B000 implementation）

## 修订结论

本 Amendment 只替换 `UNREGISTERED-AIPT-P1-B000` 的验收执行语义：历史 P0 gates 在它们实际冻结的精确 predecessor 上运行；未来 P1 candidate 则由独立的 P0 preservation、controlled P1 delta、P1 B000 validation 和 B001 compatibility gates 验证。

它不修改 Base Authority，不修复或放宽历史 P0 validator，也不改变 Playtest Package、Runtime Adapter Input、mapping、visibility、digest、provenance、B001 compatibility、runtime boundary 或任何业务目标。

## 为什么原合同不可满足

Base Authority 同时要求新增 P1 package/validator，并要求 P0-B000 至 P0-B003 在 P1 candidate 上全部 PASS。冻结的 P0-B003 validator 对 `aipt/` 和 `scripts/aipt/` 执行历史精确闭集检查，因此这两项合法新增会被它按设计拒绝。

在 `UNREGISTERED@358d6d9d08a86818e34fd0c0d9a62bfe66e73abe` 的隔离副本中已再次复现：

- clean predecessor 的 P0-B003 PASS；
- 只新增 `aipt/p1-b000/playtest-package.json` 时，P0-B003 报告 unexpected path；
- 只新增 `scripts/aipt/validate-p1-b000.mjs` 时，P0-B003 报告 validator inventory drift。

机器证据见 [`unregistered-aipt-p1-b000-authority-amendment-002-predecessor-evidence.json`](../registry/unregistered-aipt-p1-b000-authority-amendment-002-predecessor-evidence.json)。真实 UNREGISTERED source 未被修改。

## 为什么不修改历史 P0 validator

P0 validator 的职责是验证 P0 当时冻结的 exact closed set。加入 P1 path exception、successor mode、wildcard、ignore 或 conditional bypass，会把历史证明改写成新的证明，破坏可追溯性。

因此四个历史 validator 的路径和 SHA-256 固定为：

| Gate | Path | SHA-256 |
|---|---|---|
| P0-B000 | `scripts/aipt/validate-p0-b000.mjs` | `bf27739727b86a4c174ea52da54fb17e741d7c7e95062ccbe1cf16da96ecb7d2` |
| P0-B001 | `scripts/aipt/validate-p0-b001.mjs` | `d464034da401d1056b42d9910bd87d85adf6d9f6a39df44be81e6dc0b5b1bb71` |
| P0-B002 | `scripts/aipt/validate-p0-b002.mjs` | `d1508d6449f4436064ac567dc9f58050837fab9e4f051512985f26358faa82b5` |
| P0-B003 | `scripts/aipt/validate-p0-b003.mjs` | `ef08ce52d27b33dfb00152c2d29dc9056a0b09fdadeafcc2dd9f1d1c59ddfe45` |

四个 gate 必须在 Node.js `24.19.0`、无依赖安装、无网络、无模型调用的环境中运行。

## 精确 predecessor validation

唯一 P0 predecessor identity 是：

```text
repository = zyc14588/UNREGISTERED
commit     = 358d6d9d08a86818e34fd0c0d9a62bfe66e73abe
tree       = 5585271c78d1fe5cd8357c7b36a501bee34f0240
```

`origin/main`、`main`、`latest`、当前 branch 或当前 HEAD 都不能替代该 identity。执行 checkout 必须是分离、clean、detached 的 exact commit；不得 overlay candidate、修改 predecessor 文件、注入 symlink 或从环境替换 source。

四个 P0 gates 已在该 exact checkout 上真实 PASS。若未来该 exact predecessor 无法通过冻结 gates，结果只能是 `FAIL_PREDECESSOR_P0_VALIDATION`，不能由 P1 candidate 修复或掩盖。

## 为什么还需要 P0 preservation

只在旧 commit 上跑 P0 会留下漏洞：旧 commit PASS，但 candidate 可以偷改 P0 asset。因此 successor 必须同时通过 `P0_PRESERVATION_GATE`。

Canonical inventory 由冻结 commit 的完整 tracked Git tree 自动生成，candidate 无权声明或删减保护集。它绑定 path、mode、Git blob、exact blob SHA-256、artifact role 与 protection class，见 [`unregistered-aipt-p1-b000-authority-amendment-002-p0-inventory.json`](../registry/unregistered-aipt-p1-b000-authority-amendment-002-p0-inventory.json)。

136 个 predecessor entries 中：

- 133 个 `PRESERVE_EXACT`：任何修改、删除、rename、replacement、mode drift、hash drift 或 logical identity drift 均拒绝；其中包括全部 P0 manifests、P0 validators、`aipt/p0-b000` 至 `p0-b003`、campaign/source/policy 与其他 predecessor tracked assets。
- 3 个 `CONTROLLED_SUCCESSOR_MODIFICATION`：`.github/workflows/aipt-content-gate.yml`、`aipt/README.md`、`aipt/status.json`。它们是 Base Authority 已明确预留给 successor 的 CI/documentation/lifecycle control surfaces，不是可任意修改的豁免；只能在 controlled delta 中出现，并仍由 P1 gate 验证其语义。

该三项分类是从冻结 Base Authority 的七条 implementation allowlist 与 predecessor tree 的交集确定，不由 candidate 选择。

## Controlled P1 delta

最终 authority 不是未 canonicalize 的 textual diff，而是 predecessor/candidate Git tree entry 比较。路径必须是 relative POSIX NFC；case-fold、Unicode normalization、duplicate canonical path、symlink、submodule 和 non-blob 均 fail closed。

允许新增的精确路径只有：

```text
aipt/p1-b000/compatibility-evidence.json
aipt/p1-b000/playtest-package.json
aipt/p1-b000/runtime-adapter-input.json
scripts/aipt/validate-p1-b000.mjs
```

允许受控修改的精确路径只有：

```text
.github/workflows/aipt-content-gate.yml
aipt/README.md
aipt/status.json
```

不允许删除任何 predecessor path。不允许 `aipt/**`、`scripts/aipt/**` 等无界 glob。任何 allowlist 外 addition/modification/deletion 都产生 `FAIL_P1_DELTA_POLICY`。

## P0 gate 与 P1 gate 的职责边界

P0 gates 只回答：冻结 P0 predecessor 是否仍满足它当时的合同。

P0 preservation 与 controlled delta 回答：successor 是否保留全部 immutable predecessor 内容，且只包含 Base Authority 已授权的 P1 差异。

P1 B000 gate 回答：package schema/identity、source commit/tree/digest、mapping、visibility、adapter input、provenance、negative probes、control-surface semantics 与 B001 compatibility 是否成立。P0 validator 不负责理解 P1。

## 正式验收公式

```text
P0_PREDECESSOR_IDENTITY == PASS
AND P0_GATES(EXACT_FROZEN_PREDECESSOR) == PASS
AND P0_PRESERVATION(P1_CANDIDATE, PREDECESSOR) == PASS
AND P1_ALLOWED_DELTA(P1_CANDIDATE, PREDECESSOR) == PASS
AND P1_B000_VALIDATION(P1_CANDIDATE) == PASS
AND AIPT_B001_COMPATIBILITY(P1_CANDIDATE) == PASS
```

证据必须分别使用 `predecessor_validation_target` 与 `candidate_validation_target`，不能用模糊的单一 `validation_target`。未来 candidate evidence 服从 [`aipt-predecessor-successor-acceptance-evidence.schema.json`](../../../schemas/authority-amendment/v2/aipt-predecessor-successor-acceptance-evidence.schema.json)。

明确禁止两种错误模型：

1. 把 historical P0 closed-set validator 直接跑在 P1 candidate 上并作为 P0 compatibility required gate；
2. 因为存在 preservation/delta gate 就跳过历史 P0 validators。

## Failure semantics

| Failure | Result |
|---|---|
| predecessor identity、checkout 或任一 P0 gate 失败 | `FAIL_PREDECESSOR_P0_VALIDATION` |
| candidate 修改/删除/rename protected predecessor asset | `FAIL_P0_PRESERVATION` |
| candidate 出现未授权 addition/modification/deletion | `FAIL_P1_DELTA_POLICY` |
| 合法 delta 的 package/mapping/visibility/adapter/P1 gate 失败 | `FAIL_P1_B000_VALIDATION` |
| B001 protected baseline 回归 | `FAIL_B001_REGRESSION` |

不存在 `PASS_WITH_WARNINGS`。

## 保持不变的 Authority

以下身份与语义不因本 Amendment 改变：

- Base Authority 与 Amendment-001-R1/repair 的 accepted history；
- effective Authority validator `c6f0c8e01397200ce15f48bf1fc2412d9db477dddc37d3f99e0478d26956dd0c`；
- effective B001 validator `319c8d4a3466c20d14e2d5fc74cc246c9b796d36f884fcc39e2b0a25317351c4`；
- Playtest Package schema `88e55b63c8a6366c872edf0d886202a5c375e224c801433364332ddc4e4e7549`；
- Runtime Adapter Input schema `935b88f2409e604d01a13657a7790dae16e19ebe0c4e96f054c580102ec17413`；
- PostgreSQL queue migration `47f02a5a2129473caa0db5e359a0b294a01b2a96329d9f6fa08ac87cc429c997`；
- Campaign → Suite → Case → Run、Attempt internal-only、immutable Run Manifest、PostgreSQL queue authority、WIP=1、deterministic selection、lease/heartbeat/expiry/recovery 与 append-only attempt history；
- `run_core_implemented=false`、`agent_orchestration_implemented=false`、`real_model_gateway_implemented=false`、`real_model_calls=0`、`real_playtest_executed=false`。

## Effective Authority 与生命周期

当前 effective chain 仍是 Base Authority + accepted Amendment-001-R1 + accepted repair/supersessions。未接受的 Amendment-002 candidate 不自动生效。只有 Owner 另行授权并完成合法 merge 后，effective chain 才追加 Amendment-002，且仅 acceptance execution semantics 改变。

治理回归也区分 target：effective Authority validator、B001 validator、Amendment-001 与 Amendment-002 在当前 Amendment candidate 上运行；已关闭且带历史 candidate-scope 的 repair 与 Base closeout validator 在 exact detached AIPT Base closeout `8d6a438d051fb635e769285215e70536958a8f42`（tree `9ef6f121bd0d9a6484d7cc39a22450250e9ac489`）上重放。`scripts/ci/run-checks.mjs` 仍在当前 candidate 上运行完整 composite aggregate，并给 repair、closeout 与包含这两项的 historical standalone-entrypoint subcheck 附带独立 target identity。standalone 所需的 first-party workspace link 仅通过 pnpm `11.4.0`、`--offline --frozen-lockfile --ignore-scripts` 在临时 target 内生成，且安装后 Git target 仍须 clean。既有 workflow command 通过 Amendment-002 的 closed-governance wrapper 执行同一 exact replay。这样既实际执行历史 validators，又不把后续 append-only Amendment 文件错误归类为旧 repair/closeout candidate scope，也不需要修改历史 validator。

历史 target replay 不继承当前 candidate job 的 `GITHUB_*` execution identity；否则旧 validator 会把当前 job SHA 错绑到 detached Base HEAD。replay 的身份只来自临时 target 自己的 exact Git commit/tree，当前 candidate 仍在它自己的 gate 中单独绑定 GitHub head SHA。这是 target 隔离，不是跳过或放宽 identity validation。

toolchain CI 的冻结 pnpm install 会生成 `node_modules/` workspace metadata；该目录不是 candidate tree 或 candidate delta。workflow 在确认 candidate 没有 tracked `node_modules` 后，只把 `node_modules/` 写入该 checkout 自己的 `.git/info/exclude`，再执行 frozen install。任何 tracked dependency path 仍进入 commit delta 并被 scope gate 拒绝，任何 `node_modules/` 之外的 untracked path 仍使 candidate lifecycle 失败；最终冻结 worktree 仍须 clean。

本阶段必须保持：

```text
Amendment-002 accepted          = false
Amendment-002 merge_authorized  = false
Amendment-002 closeout_authorized = false
B000 implementation_started     = false
B000 candidate_created          = false
B000 merge_authorized           = false
```

Candidate 与真实 remote CI 冻结后立即停止，等待 Owner 的独立 merge/closeout authorization。
