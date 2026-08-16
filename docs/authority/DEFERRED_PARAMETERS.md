# 延期参数（DEFERRED PARAMETERS）

> 本页由机器种子 `DEFERRED_PARAMETERS.json` 生成。机器权威为
> [registry/deferred-parameters.json](registry/deferred-parameters.json)。
> 16 项参数中，**`DEFER-016` 已 `RESOLVED`**（B001 已冻结精确工具链版本，见
> [../../tools/toolchain.lock.json](../../tools/toolchain.lock.json)）；其余 15 项**尚未冻结**：
> 任何文档不得把它们写成已实现或已关闭的能力。
> 状态名与含义：

- `OPEN_EXTERNAL_DEPENDENCY`：等待外部依赖确定。
- `DEFERRED_TO_*`：延期到指定的测量/登记/基线批次。
- `DEPLOYMENT_CONFIGURABLE`：按部署 Profile 配置，不进入冻结值。
- `FUTURE_CAPABILITY`：明确为未来能力。
- `ADMIN_DECISION_PENDING` / `UNAPPROVED`：等待管理员决定/批准。
- `UNKNOWN`：信息未确认。
- `ENVIRONMENT_PROBE_PENDING`：等待环境探测。
- `POLICY_FROZEN_TEXT_NOT_DRAFTED`：政策已冻结、正文未起草。
- `DEFERRED_TO_AIPT-M0-B001`：由 B001 批次决定。
- `RESOLVED`：已由指定批次资格化并冻结；`value` 写入冻结值，`blocks` 清空（当前仅 `DEFER-016`）。

## 完整延期参数表（共 16 项）

| 参数 ID | 名称 | 状态 | 当前值 | 未冻结原因 | 阻塞范围 | 不阻塞范围 | 未来关闭条件 |
|---|---|---|---|---|---|---|---|
| `DEFER-001` | platform_integration_m1_engine_batch | `OPEN_EXTERNAL_DEPENDENCY` | （未设置） | TRPG_PLATFORM 中负责稳定游戏引擎接口的具体 M1 批次尚未确定。 | AIPT-PLATFORM-INTEGRATION unfreeze | AIPT-STANDALONE M0；AIPT-STANDALONE development MVP | TRPG_PLATFORM 指定稳定游戏引擎接口的具体 M1 批次并满足平台集成解冻四条件 |
| `DEFER-002` | local_gguf_model_identity | `DEFERRED_TO_MODEL_REGISTRATION` | （未设置） | 本地 llama.cpp 模型名称和 GGUF 尚未选定。 | local model role certification | M0；remote DeepSeek MVP path | 完成本地模型目录登记与 GGUF 选型 |
| `DEFER-003` | local_model_performance_thresholds | `DEFERRED_TO_BENCHMARK` | （未设置） | 需在实际 8060S/128GB 统一内存主机上基准测量后冻结。 | production local-model role eligibility | M0 | 在实际本地主机上完成基准测量并冻结门槛 |
| `DEFER-004` | formal_campaign_minimum_run_count | `DEFERRED_TO_VARIANCE_BASELINE` | （未设置） | 六场仅为默认模板，正式最低运行数需根据成本与方差确定。 | production/release campaign minimum policy | development MVP eight-run qualification | 依据成本与方差基线确定正式最低运行数 |
| `DEFER-005` | runtime_concurrency_limits | `DEFERRED_TO_RESOURCE_CERTIFICATION` | GLOBAL_WIP_1_INITIAL | 首个纵向切片固定 WIP=1；后续并发需资源池资格测试。 | parallel scale-out | serial MVP | 通过资源池资格测试（首个纵向切片固定 WIP=1） |
| `DEFER-006` | audit_bundle_default_size_limits | `DEPLOYMENT_CONFIGURABLE` | （未设置） | 包大小、内联阈值与分块大小为部署 Profile 可配置项。 | （无） | M0 | 部署 Profile 确定包大小/内联/分块阈值 |
| `DEFER-007` | tpm_signer_delivery_milestone | `FUTURE_CAPABILITY` | （未设置） | 生产签名先支持本地可替换密钥提供器，TPM 接入时间待定。 | TPM-backed signer claim | development；production with non-TPM local signer | 生产签名提供器规划确定 TPM 接入时间 |
| `DEFER-008` | human_calibration_sample_size | `DEFERRED_TO_FIRST_HUMAN_DATASET` | （未设置） | 当前无真人桌测记录；发布前必须校准但样本数尚未基准化。 | human-equivalence claims；final human calibration gate | synthetic development playtests | 首个真人数据集确定校准样本数 |
| `DEFER-009` | release_coverage_thresholds | `DEFERRED_TO_MVP_BASELINE` | （未设置） | 规则、模组与组合覆盖率阈值需根据首个 MVP 增长曲线冻结。 | release coverage gate | M0；prototype development MVP | 首个 MVP 覆盖增长曲线确定发布阈值 |
| `DEFER-010` | claude_known_truth_acceptance_thresholds | `ADMIN_DECISION_PENDING` | （未设置） | 已知真值套件保留，但由管理员查看硬/软指标后批准 Auditor Profile。 | secondary auditor production eligibility | GPT-only prototype design audit；development pass | 管理员查看硬/软指标后签署批准 Auditor Profile |
| `DEFER-011` | claude_model_improvement_status | `UNKNOWN` | （未设置） | Claude Pro 的 Model Improvement 状态尚未确认。 | production/release Claude Web audit unless explicit Incognito privacy evidence | development break-glass audit with attestation | 确认 Claude Model Improvement 状态 |
| `DEFER-012` | claude_opus5_auditor_profile | `UNAPPROVED` | （未设置） | 备用 Opus 5 Profile 尚未经过管理员批准。 | formal Opus 5 fallback | Fable 5 development attempts | 管理员批准 Opus 5 Auditor Profile |
| `DEFER-013` | claude_opus48_auditor_profile | `UNAPPROVED` | （未设置） | 备用 Opus 4.8 Profile 尚未经过管理员批准。 | formal Opus 4.8 fallback | M0 development | 管理员批准 Opus 4.8 Auditor Profile |
| `DEFER-014` | unregistered_custom_license_final_legal_text | `POLICY_FROZEN_TEXT_NOT_DRAFTED` | LicenseRef-UNREGISTERED-NC-SA-1.0 | 许可政策已冻结，但最终法律正文未起草且应在发布前法律审阅。 | formal publication of the custom content license | AIPT B000 documentation；draft licensing boundary documentation | 起草正式许可正文并通过发布前法律审阅 |
| `DEFER-015` | rootless_docker_capability | `ENVIRONMENT_PROBE_PENDING` | Docker confirmed; rootless/isolated context unknown | 当前确认普通用户可运行 Docker，具体 rootless/隔离 Context 能力待探测。 | production Evidence Adapter Docker certification | B000 | 探测并认证 rootless/隔离 Docker Context |
| `DEFER-016` | go_node_pnpm_postgresql_exact_versions | `RESOLVED` | Go 1.26.5 / Node 24.19.0 / pnpm 11.4.0 / PostgreSQL 18.4 | B001 资格批次与公共 CI 已冻结精确版本（`tools/toolchain.lock.json`） | （无） | B000 | 已由 B001 关闭 |

## 必须公开强调的延期项

- 平台本体具体 M1 游戏引擎批次（`DEFER-001`）：`AIPT-PLATFORM-INTEGRATION` 保持 `FROZEN_WAITING_M1_ENGINE`。
- 本地 GGUF 模型与性能阈值（`DEFER-002`/`DEFER-003`）：本地模型角色资格未定，不阻塞 M0 与远端 MVP 路径。
- 正式 Campaign 最低场数与并发上限（`DEFER-004`/`DEFER-005`）：开发 MVP 使用八场资格（六场基础 + 两场 Mutant Qualification），正式政策未冻结。
- 发布覆盖率阈值与真人校准样本数（`DEFER-008`/`DEFER-009`）：发布前必须真人校准，样本数与阈值尚未基准化。
- Claude `Model Improvement` 状态与备用 Profile 批准（`DEFER-010` 至 `DEFER-013`）：第二审计生产资格未达成。
- 《未登记》自定义许可最终法律正文（`DEFER-014`）：政策冻结、正文未起草，须发布前法律审阅。
- rootless Docker 实际资格（`DEFER-015`）：等待环境探测。
- Go/Node/pnpm/PostgreSQL 精确版本（`DEFER-016`）：**已 `RESOLVED`**——Go 1.26.5 / Node.js 24.19.0 LTS / pnpm 11.4.0 / PostgreSQL 18.4，由 B001 资格批次与公共 CI 冻结（[../../tools/toolchain.lock.json](../../tools/toolchain.lock.json)）。

## 相邻文档

- [Authority Index](README.md) · [DECISION_MATRIX.md](DECISION_MATRIX.md) · [PROJECT_STATUS.md](PROJECT_STATUS.md) · [registry/deferred-parameters.json](registry/deferred-parameters.json) · [../supply-chain/README.md](../supply-chain/README.md)
- [返回仓库首页](../../README.md)
