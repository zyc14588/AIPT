# 里程碑 MVP（MILESTONE MVP）

2026-10-09 当前 B007：REMOTE004 和 LOCAL 启动前001已分别由同一代理082、083独立限定验收。新的 current010 真实游戏构造检查一次通过：生产 Table 接受委派 GAME，45项来源、15个 Core 事件精确回放、私有审计、B006 once/Inspect、5项导出及篡改拒绝成立，自有进程和数据库已回收；这项新实际结果仍待完整复审。组件测试1125 PASS、25条件SKIP，六项强制拒绝全PASS。REMOTE观察到5个 Node Worker Probe 后代；旧失败的隐藏计数仍未观察。LOCAL核对真实GGUF摘要与seals15，模型文件页已释放，原生入口17.9KB仍驻留，RSS未测量，未取得实际启动后三阶段缓存验收。本快照完整运行/隐私HIGH、生产来源绑定、公开PR及候选/精确合并各5/5 CI仍OPEN；native/真实模型/正式DIAG/QUAL均0。M0=100%、MVP=69.2%、总体=81.8%，B007唯一WIP1，runtime_ready=false、paid_callable=false。公开限定事实与摘要见 docs/pilot/reviews/q014-current010-pre-model-scoped-facts.json；下文为历史快照。


2026-10-09 当前 B007（Q014 私有链限定通过，生产入口修复候选待验收）：同一只读代理074已核对无模型实际链1 PASS、0 FAIL、0 SKIP，15个真实 Core 事件精确回放、原始 fresh 匿名 HTTPS 来源、AES-256 私有审计、原 B006 once/Inspect、5项安全导出、篡改拒绝和实际 Owner join 均成立；审计测试目录及自有数据库在直接 join 后退休，原始证据保留。完整实现因 Q005-074-F1 未通过：生产表桌仍拒绝委派 GAME，此前私有链未覆盖该构造入口。现在已在 Q014 原授权内补齐委派 GAME 同一 SETUP 所有权适配，隔离候选131项 race 检查通过；真实生产构造回归与 REMOTE/LOCAL 启动前无模型边界仍待验收。完整运行/隐私 HIGH、公开 PR、候选及精确合并各5/5 CI和本地在线不可变目录仍 OPEN。实际 native 启动、生成/计数及三阶段缓存事实留在全部前置门禁后、原 USD5 一次非 QUAL DIAG 内取得。本轮模型/native/Worker/正式DIAG/QUAL均0，runtime_ready=false、paid_callable=false，M0=100%、MVP=69.2%、总体=81.8%，B007唯一WIP1。下文保留历史快照。

2026-10-08 当前 B007（Q014 首次隔离可行性已限定验收）：精确静态夹具退出0，同一只读代理061核对原始证据，主方再核对46项文件一致。PREP现有及实际新增线程保持五组Cap0/NNP1，SETUP严格仅bit31/NNP1；34个静态哨兵全部直接wait，其中32个正常退出、2个预期负例，SETUP及PREP均由直接Owner join。已清理123,425,447字节Q014阶段自有可重建文件。现在推进生产CA交接与固定角色启动/回收适配；生产角色、真实整链、完整运行/隐私HIGH及候选和精确合并各5/5 CI仍待验收。旧FAIL和冻结来源保持，原USD5/一次非QUAL DIAG条件不变；模型/正式DIAG/QUAL均0，runtime_ready=false、paid_callable=false，M0=100%、MVP=69.2%、总体=81.8%，B007唯一WIP1。下文保留历史快照。

2026-10-08 当前 B007（Q014 Owner 已批准）：已单独登记固定静态SETUP受限后继授权，active PREP仍全线程Cap0；先验证SETUP仅own USER域CAP_SETFCAP的隔离可行性，目前首夹具未执行，完整运行/隐私HIGH尚未通过。旧Q013三次FAIL与全部历史、来源verifier和已接受UNREGISTERED规则/输入、旧B005/B006冻结。原USD5/一次非QUAL DIAG、完整同一代理复审、真实整链和候选及合并各5/5 CI验收均保留；模型/正式DIAG/QUAL均0，M0=100%、MVP=69.2%、总体=81.8%，B007唯一WIP1，runtime_ready=false、paid_callable=false。下文保留历史快照。

2026-10-08 当前 B007（Q014 待 Owner 决策）：同一只读代理057已完成UID映射EPERM定位事实与Q014文字材料的限定静态审查，主方递归核对18项文件一致；未发现材料阻断，但不代表架构、可行性或完整运行/隐私HIGH通过。Q014拟新增一个仅在自身用户命名空间保留CAP_SETFCAP的固定静态SETUP，处理已有冻结角色的创建和直接回收，active PREP继续全线程Cap0；这是新信任角色，现有Q013授权不覆盖，尚未授权、实现或执行。原003/004/005全部FAIL，追踪诊断不改判；USD5、一次非QUAL DIAG、原来源/完整独立与候选及合并各5/5 CI验收均保留。B007唯一WIP1，M0=100%、MVP=69.2%、总体=81.8%，runtime_ready=false、paid_callable=false，模型/正式DIAG/QUAL均0。自有245,266,637字节阶段临时编译文件已清理，原失败和审计材料保留。下文保留历史快照。

当前进展（2026-10-08，Q013失败已定位，Q014提案尚未授权）：只读strace诊断重建并核对了005相同静态程序字节；现场clone嵌套命名空间成功，但PREP写入子进程uid_map的0→0映射返回EPERM，失败子进程退出253并被直接wait4回收。外层完整权限/CA入场和拒绝变更检查通过，仅属限定观察事实；原003/004/005全部FAIL，不被追踪改记可行性或HIGH通过。拟以单独的受限静态SETUP角色处理固定执行子进程映射/生命周期，维持active PREP Cap0；这是新信任角色，需要Owner决定，目前只有待复审文字材料，SETUP未实现或执行。Q013四个已完成夹具/诊断的245,266,637字节自有临时编译文件已清理，宿主固定CA核验不变，模型/正式DIAG/QUAL均0；M0=100%、MVP=69.2%、总体=81.8%，B007唯一WIP1、runtime_ready=false。下文保留历史快照。

当前进展（2026-10-08，Q013 更正版005实际验证未通过）：固定封存来源、私有只读CA物化、两端全部33个当前线程的稳定Cap0/NoNewPrivs=1核验及外层新鲜CA入场通过；两别名和整个文件系统的13项变更拒绝控制通过，恢复能力的四项检查通过。实际程序仍在创建自有嵌套USER/MNT子进程时退出2，日志未记录cmd.Run的具体errno，不能把可能原因写成已实测结论。003/004/005原始FAIL全部保留，完整可行性及HIGH未通过，生产实施与模型调用停止，仅开展同一代理的只读失败诊断。自有PREP已退出join，005的61,330,173字节临时编译文件已清理；模型/正式DIAG/QUAL均0，B007仍唯一WIP1。下文保留历史快照。

当前进展（2026-10-08，Q013 更正版004实际验证未通过）：私有 CA 物化正控制通过；PREP 对12及25个线程的完整稳定清单均核实五组能力为0、NoNewPrivs=1，包含13个实际新增线程。外部 Parent 对33个线程的独立完整稳定权限检查也通过，但未满足与 PREP 较早25个线程样本数量一致的门禁，故 fresh CA_ADMIT、嵌套子进程和整体验收未完成。003及004原始 FAIL 保留，不作为完整权限或可行性通过证据；生产实施停止，仅交同一代理只读诊断更正范围。直接自有子进程已退出并 join，004的61,307,484字节临时编译文件已清理。实际模型/正式 DIAG/QUAL均0，完整运行/隐私 HIGH、精确候选与合并 CI、B007关闭均待验收。下文保留历史快照。

当前进展（2026-10-08，Q013 首个实际可行性验证未通过）：固定 CA 快照及私有 tmpfs 三对象/UID0/mode0400/精确字节/全部只读别名/无写描述符的限定正控制成功；完整线程核验在 stable-thread-inventory-before-after 阶段停止，不能据此宣称全部线程/未来线程、外层第二次入场或嵌套子进程验收通过。原实际 FAIL 与 stdout 完整保留；后续生产实施和再运行停止，仅进行同一代理的只读诊断。直接自有 PREP 已 join，61,298,807 字节临时程序/缓存已清理，宿主 CA 未变。实际模型调用/正式 DIAG/QUAL 均 0；完整运行/隐私 HIGH、候选/合并 CI 与 B007 关闭仍未通过。Q012/Q011及旧业务历史保持原字节。

当前进展（2026-10-08，Q013 Owner 已批准）：已登记固定封存来源 → PREP 私有只读 tmpfs 的受限后继授权；仅授权先进行无网络、无模型的可行性验证，随后实现与完整独立/CI 验收。Q012 原封存 memfd 挂载失败（EINVAL/22）及历史保持原字节；新方案尚未验证，runtime_ready=false、paid_callable=false，完整运行/隐私 HIGH 仍 OPEN。实际模型调用、正式 DIAG、QUAL 均为 0；原 USD5 预算及所有前序验收要求不变。

2026-10-08 当前 B007：Owner 已批准 Q012 固定系统 CA 封存桥接并单独登记。最终闭网、无模型夹具确认快照 UID0/mode0400/全 seals 和精确字节通过，同固定目标的普通文件只读挂载对照通过；封存 CA memfd 的绑定挂载返回 EINVAL(22)。已按 Q012 的失败停止条件保留原始结果，生产桥接未实施。两次夹具更正经同一代理限定静态复核，均未授予完整运行/隐私 HIGH。Q013 私有只读 tmpfs 与 PREP 全线程能力清空后继仅为待 Owner 决策提案，尚未批准或验证可行。旧 B005/B006/Q011/Q012 与历史字节保留；实际模型、正式 DIAG、QUAL 均0，公开候选与精确合并 CI 5/5 尚待完成。M0=9/9（100%），MVP=9/13（69.2%），总体=18/22（81.8%），B007唯一WIP1，runtime_ready=false。三次夹具的183192905字节自有临时程序与缓存已清理。下文保留历史快照。


Q011 私有加密证据后继（Owner 已批准）

仅允许新增 PRIVATE_FULL AES-256-GCM 证据入口与 B007 Reports 适配器；旧 B005/B006 业务、验证与历史字节保持精确。游戏来源仍为 Q009 接受的 45 项 PROTOTYPE，canonical=false。加密、报告与单次队列执行器组件已实现。独立 037 复审保留上下文组合容量及私有终结元数据两项阻断（Q005-037-F1/F2）和原 036 失败历史。后续兼容修复保留完整状态、源正文与当前可核实的 SEEN 源事实，采用逐次精确往返的可读 GM 表示；13 个合法参考状态、65 条离线完整 Worker 请求通过，最大 8049B，214 项定向 race 检查及六项实际隔离 PostgreSQL 检查通过（含四项矛盾元数据反例），均仅为 NON_CANON 组件验证。独立 038 复审限定通过原 F1/F2 的指定反例及组件修复，原失败与审查器输入错误记录均保留；新增 Parent/PREP 入口已构建，35 项定向 race 和一项真实隔离 PostgreSQL 单次排队检查通过，均未启动模型；完整 Parent/PREP、发布链与 runtime/privacy HIGH 尚待验收，公开候选 PR 与候选/合并 CI 5/5 尚待完成。真实模型调用、DIAG、QUAL 均为 0；USD 5 及原调用/输入/输出/1800 秒上限保持不变。M0 9/9、MVP 9/13、总体 18/22；B007 为唯一 WIP1。


Q009 source adoption update (2026-10-08): Owner accepted the exact 45-entry UNREGISTERED Task0 PROTOTYPE; public PR5 merged `d37ae9b38bce84f8bfc164306fee2bebf73178b7` with tree `d802d28c7275e3e75ada5d6ef3edeb7fb57eb7b9` and canonical package SHA-256 `f87f011f8c57c3eef371ad1e8f5569effd035957158fd17ba7fa63655c86e13d`. Candidate and merge public push CI each passed 2/2; the same Owner-authorized read-only reviewer accepted only exact source/origin/CI scope. Separate Q009 authority, input annex and immutable offline CI control catalogue preserve the old Q003 seventeen-source closure and permissions, every historical failure, and the accepted INT001 pair. Actual AIPT source loading/RunManifest binding, role authentication, Task0 driver and full runtime/privacy acceptance remain pending. B007 stays WIP1; M0=9/9, MVP=9/13, overall=18/22; model/DIAG calls=0, QUAL=0/8. [Source authority](../pilot/authorities/task0-prototype-source-successor-q009.json) and [CI evidence](../pilot/evidence/task0-q009/evidence-index.json) contain control metadata only.

2026-10-07 当前 B007：Owner 已同意 Q005 仅更换独立只读审查代理实例，原代理三次自动内容筛查中止记录保留。新代理先复核固定源码与证据，完整运行及隐私复审、原USD5预算、精确CI 5/5和三阶段定向模型缓存检查继续生效。已完成模块的限定测试与构建输入已持久保存，完整启动器、Task0执行器和实际运行验收尚未完成。B007新增真实模型/诊断/资格运行仍为0，M0=100%，MVP=69.2%，总体=81.8%，runtime_ready=false。下文保留历史状态。


2026-10-07 当前 B007：Owner 已批准 Q004 完整本地运行闭包后继，允许新增独立运行/隔离启动器身份，以同一固定源码、模型、模板和原USD5预算推进。Q004已单独登记，原候选、关闭历史、模型登记和认证字节保留；实现、完整输入核验、受控认证与独立验收尚未完成。B007新增真实模型/诊断/资格运行仍为0，M0=100%，MVP=69.2%，总体=81.8%，runtime_ready=false。下文较早的待审批状态作为历史保留。


2026-10-07 当前 B007：Q003 角色投影模块范围独立审查通过；数字规则和缓存模块的五项局部缺口已独立验证修复，第010次 PID/ready 复审为21项独立探针及5项仓库用例通过，完整运行身份尚未通过。Owner 已选择模型文件缓存定向释放，真实已登记文件缓存检查的驻留量为27.05 GiB→0；服务器尚未启动，实际启动后与退出后检查尚未执行。现有入口摘要未固定传递共享库，新增完整本地运行闭包身份 Q004 提案待Owner决策，维持同一固定源码、模型、模板和USD5预算。B007新增真实模型、诊断和资格运行均为0；M0=100%，MVP=9/13（69.2%），总体=18/22（81.8%），runtime_ready=false。下文保留历史记录。


2026-10-06 当前 B007：Owner 已批准 Q003 独立输入附件，12 份固定源及原五文件的字节身份已核验；源正文保存在私人输入目录。Q002 精确新闭包和 PostgreSQL 全局预算的独立只读复审在其范围内 PASS（16 项探针），尚不构成真实调用或 B007 关闭验收。继续实现角色投影、任务0驱动、生产传输与本地完整输入证明。真实模型调用、诊断与资格运行均为0；M0=100%，MVP=9/13（69.2%），总体=18/22（81.8%）。下文保留历史记录。


2026-10-06 当前 B007：Owner 已批准 Q002 新闭包身份；精确单文件产物已构建，16 项预算测试及 8 个子测试（含 PostgreSQL 18.4）通过，独立复审进行中。原五文件输入包缺少真实任务0需要的角色与情报资料，已准备 12 项固定源输入附件 Q003，等待 Owner 决策，尚未接入运行。真实模型调用、诊断运行与资格运行均为0；M0=100%，MVP=9/13（69.2%），总体=18/22（81.8%），B007尚未关闭。下文早期记录保留其当时状态。


2026-10-06 B007 预算预检：21项实际Git历史保护测试、16项预算race测试项及六项固定前序重放通过。独立纯离线复现确认旧闭包的一次调用可产生33次上游请求，无法证明已批准的32次总上限。已准备新增单文件闭包后继补丁，原闭包与前序身份不变，新增闭包身份须Owner单独决策；新补丁未执行，真实调用和资格运行仍为0，B007尚未关闭。


2026-10-06 当前状态：Owner 已批准 B007 后继门禁规则、新增真实任务0诊断驱动及一次5美元非资格试跑预算。已登记独立授权；B007为唯一 GLOBAL_WIP=1 批次，B006与全部前序关闭依据保持不变。真实调用前必须证明上游生成限额、费用预留及持久预算记账；目前B007真实模型/诊断/qualification=0。M0=100%，MVP=9/13（69.2%），总体=18/22（81.8%），runtime_ready=false。


2026-10-06 最新关闭状态：`AIPT-MVP-B006` 已具备精确 Candidate `6e04f9f86ff10af05e61f3be60880a96b09d7295` / tree `65dfcf8e5d21fd4dcf6ff1c1b10d0b28e23d6237`、合法 merge `11653c8fa8cf42a15b481e29b33df68eeef10c7a`、候选 CI `37420245124` 及合并 CI `37420903891`（attempt 1）全部 5/5 success、同一独立只读 Codex 审查 PASS（24 probes，六项 finding 全部 VERIFIED_FIXED）与真实 PostgreSQL 18.4 39 项 race 集成 PASS。治理-only direct closeout 以独立不可变 CI catalogue、review 和 canonical append-only lifecycle records 生效。B006=MERGED_CLOSED，GLOBAL_WIP=0，下一批 B007 尚未开始；M0=9/9（100%），MVP=9/13（69.2%），总体=18/22（81.8%）。B006 新增真实模型/桌测/qualification=0，qualification=0/8，runtime_ready=false，MVP Development Pass 仍未授予；首个阻塞为 B007 实际驱动和非资格真实诊断 pilot。

> 以下较早的状态、失败审查和授权说明作为历史快照保留；当前机器状态以 `registry/project-status.json` 和上述不可变关闭依据为准。


2026-10-06 最新状态：Owner 另行批准 `B006-PREDECESSOR-GATES-SUCCESSOR-Q001=A`，将 B005/INT001 门禁按固定已验收版本完整重放，并严格核验当前工作树、main 及每个历史状态投影；原验证代码、历史测试及关闭依据不改写。已登记独立授权 `registry/b006-predecessor-gates-successor.json`。B006 本地审查发现的配置、自停止完成、例外历史、CI 字节绑定和前序状态历史缺口均已修复，仍待同一只读代理对最终精确候选复审、公开 PR 与精确 CI 验收。M0=100%，MVP=8/13（61.5%），总体=17/22（77.3%）；真实模型和 qualification=0，runtime_ready=false。


2026-10-06 当前状态：B002 空 RNG 数组的最小后继修复已获 Owner 批准并应用；B006 是唯一 GLOBAL_WIP=1 批次，正在完成后继规则、当前测试、公开 PR 与同一独立只读复审。原 B002 关闭快照及失败证据保留。M0 100%，MVP 8/13（61.5%），总体 17/22（77.3%）；真实资格 Run 0/8，runtime_ready=false。


2026-10-06 B006 验收阻塞：共用控制/Web/stdio 的 87 项 Go unit/race 与 TypeScript 契约测试通过；真实 PostgreSQL 18.4 集成确认前序 B002 在 rng_requests=[] 时提交成功但回放失败。最小修复仅在隔离副本中通过 Run Core 全套 race 与 2 项 PostgreSQL race 集成，活动 B002 字节未改动；需 Owner 批准明确的 post-closeout 后继修复例外后继续。MVP 仍为 8/13，真实 qualification 为 0/8。
2026-10-06 最新状态：B005 已正式 MERGED_CLOSED；B006 共用权威运行控制/Web/stdio IPC 已启动，GLOBAL_WIP=1。M0=100%，MVP=8/13（61.5%），总体=17/22（77.3%）；0/8 真实 qualification Runs，MVP Development Pass=NOT_GRANTED。以下前序状态记录按历史快照保留。

> 开发 MVP 资格合同。机器权威见 [../authority/registry/decisions.json](../authority/registry/decisions.json)；
> 延期参数见 [../authority/registry/deferred-parameters.json](../authority/registry/deferred-parameters.json)。

## 冻结实施序列与当前状态

MVP 的机器权威是 [batch-graph.json](../authority/registry/batch-graph.json)，固定串行顺序为：

```text
AIPT-MVP-B000 → AIPT-MVP-B001 → UNREGISTERED-AIPT-P1-B000
→ AIPT-MVP-B002 → AIPT-MVP-B003 → AIPT-MVP-B004
→ INT-AIPT-UNREGISTERED-MVP-001（只读）
→ AIPT-MVP-B005 → AIPT-MVP-B006 → AIPT-MVP-B007
→ AIPT-MVP-B008 → AIPT-MVP-B009 → AIPT-MVP-B010
```

`AIPT-MVP-B000 = MERGED_CLOSED`：final Candidate `9a4d5e0ad09fbc9c3e13536d02cd131f992836f2`（tree `895ccfc569435c390a1aaeea566167a2d61a4de6`，CI `32869412683` success）由 implementation merge `1a26e023af1b56c057590a46de2f63c3b4220923` 精确集成，post-merge CI `32907168240` success；finding `AIPT-MVP-B000-POSTMERGE-LIFECYCLE-001` = `CLOSED`。

`AIPT-MVP-B001 = MERGED_CLOSED`：Candidate `85ef3489405694cf0764867a97fb21b09fda5894`（tree `44a885569c59c428fb173e0847dc49a8111b526c`，CI `32932281680` success）由 implementation merge `ad8e39b23f5888cfb9a7f8f15f9dd996964d8f16` 精确集成，post-merge CI `32939064547` success，并由 `AIPT-MVP-B001-CLOSEOUT-001` 关闭。其历史交付精确为版本化 `Campaign → Suite → Case → Run` Test Plan、不可变 canonical-SHA-256 Run Manifest、PostgreSQL 18.4 权威 Queue/Lease/Attempt 与 formal WIP=1。

`UNREGISTERED-AIPT-P1-B000 = MERGED_CLOSED`：accepted merge `fe0965977447caf8cd7b6e58252bc1b991b7cc6f`，post-merge CI `33186880614` success，AIPT canonical lifecycle closeout `411bf2997cd0f10ba1a022ac687d27a1bd19eb36`。

`AIPT-MVP-B002 = MERGED_CLOSED`：Owner 批准的 R1 Candidate `dd634f575cdec5ec572696409ac574102442af3e`（tree `2b7240f11b1bcf934d34d95a286bdd49dbf021b5`，CI `33241732672` success）由第二次合法 merge `a5d9e9b0aeea5f2a9990d976258ddd34b9b8375e` 精确集成，post-merge CI `33243508362` success，并由 canonical append-only lifecycle chain 关闭；首次失败 merge `f4ceabe3e3a3e7bea31481bd91681a1b87f27d56` 仍是不可变 failure 且没有生命周期记录。关闭交付实现 game-neutral Deterministic Run Core 的 action transaction、authoritative state、versioned/domain-separated RNG、seed commitment、invariants、derived projection、PostgreSQL ledger atomicity 与 fail-closed replay。

`AIPT-MVP-B003 = MERGED_CLOSED`：唯一授权 Candidate `4f2979f4495e3d78393e9f9ec1978308a7fb10b9`（tree `bbdb35861bb6cf47a9e6ec4e943720c0126cbc50`，CI `33247140362` success）由合法 no-ff merge `beb7c70738b1f876845d68bec8e20166ab3eac10` 精确集成，post-merge CI `33264083089` success，并由 canonical append-only lifecycle chain 关闭。交付范围只包含 provider-neutral Deterministic Agent Orchestrator，B002/B003 business semantics、迁移和关闭生命周期继续冻结。

`AIPT-MVP-B004 = MERGED_CLOSED`；MODEL/HARNESS minimum certification 的历史受控真实调用累计为 remote 3 次、local 2 次。`INT-AIPT-UNREGISTERED-MVP-001` 已按 read-only closeout 正式关闭，不声称 Git merge、不会重跑旧集成。

2026-10-06 当前唯一施工批次是 `AIPT-MVP-B005 R1`，GLOBAL_WIP=1。远端证明治理已在接受的 main closeout `fdbf9637b38a773fbc7ea57a21e6f75dd89b235f` 关闭；R1 固定匿名 GitHub Commit/Tree 核验及安全修复正在等待独立实现验收。原 `c07e1aae94f681733ad73c1800423248bcc72376` merge 的 post-merge security FAIL 保留，不能作为合格 B005 关闭依据。B006 尚未启动。

按权威串行批次等权计算，M0=9/9（100%）、MVP=7/13（53.8%）、总体=16/22（72.7%）。这表示工程批次进度；真实桌测和 qualification Run 均为 0/8。M0 Development Pass=GRANTED，MVP Development Pass、production/release qualification 仍为 NOT_GRANTED；runtime_ready=false，首个阻塞 gate=IPC。后续依次为 B006 运行控制/IPC、B007 real pilot、B008 five Clean、B009 three Mutant 与 B010 GPT audit。

## 真实 MVP：使用《未登记》任务 0

- 真实 MVP 直接与已进入原型桌测阶段的**《未登记》**共同建设，使用其当前游戏仓库（`R12-Q001`、`R12-Q003`）。
- 直接使用《未登记》的世界观与叙事（`R12-Q013`）；具体内容为任务 0 的短篇完整单次游戏（`R12-Q009`）。
- AIPT 自带内容只保留**最小非叙事协议夹具**，不另造完整合成游戏（`DCA-Q001`）。

## 阵容

- 基准桌：**1 GM + 4 玩家**（`R12-Q008`），固定四名 Sentinel 角色，另两名用于后续变体（`R13-Q009`）。

## 运行场次：五场 Clean + 三 Mutant 检出

- 默认六场 Campaign；MVP 资格**另加两场 Mutant Run**，总计八场（`R14-F001`）。
- MVP 门禁（`R12-Q006`、`R15-Q019`、`R14-Q021`、`R14-Q024`、`R15-Q020`、`R15-Q022`、`R15-Q024`）：

```text
五场 Clean Run 完成
三个 Mutant 成功检出（隐藏信息泄漏 / Prose-Machine 分歧 / 状态重放不一致）
无隐藏信息泄漏
状态可重放
关键路径 / 结局 / 恢复可达
GPT 审计 PASS
```

## 模型分配

- **deepseek-v4-pro** 完成完整 Campaign（GM、玩家与 Observer）（`R14-Q023`、`R12-Q004`）。
- **llama.cpp** 只做启动、认证与最小角色调用（`R12-Q004`）；本地 GGUF 选型与性能阈值延期（`DEFER-002`、`DEFER-003`）。

## 开发/生产限制

- 叙事降级 Run 失去 Game Gate 资格但保留诊断证据（`R14-Q018`）。
- 第二审计者（Claude）未配置时允许开发态真实桌测；**生产/发行 Gate 阻塞**（`R13-Q024`）。
- MVP Development Pass 以 GPT 审计为硬门禁；Claude 经管理员批准后用于生产/高风险（`R14-Q024`）。
- 证据等级：`SYNTHETIC_PLAYTEST_EVIDENCE`（`R14-Q001`）。

## 当前不声称真人等价

- 发布前必须完成至少一场可审计**真人盲测**，并经过真人校准（`R3-Q021`、`R1-Q013`）。
- 校准样本数尚未基准化（`DEFER-008`）：在完成前，MVP 结果**不得**表述为真人等价证明。
- AI 只验证安全协议执行正确，不能证明真人心理安全（`R14-Q006`）。

## 相邻文档

- [../authority/README.md](../authority/README.md) · [../authority/BATCH_DEPENDENCY_GRAPH.md](../authority/BATCH_DEPENDENCY_GRAPH.md) · [../test-model/README.md](../test-model/README.md) · [../evidence/README.md](../evidence/README.md) · [../integration/README.md](../integration/README.md) · [M0.md](M0.md)
- [返回仓库首页](../../README.md)

2026-10-06 R6 repair：PR #23 已由 Owner 合并，但本地独立 Codex 审查发现 LOCAL-B005-R1-001 收据字段缺口，总体 FAIL；CI 成功不覆盖此结论。Owner 授权在 exact failed merge 08f8b2ecf721759940f4e4fef862b1a4da9c1834 上追加公开 R6 PR，保留失败历史并复审。R6 enforce 完整 canonical receipt bytes；最终独立审查、精确 final merge 5/5 CI、online source verification 与 immutable catalogue 全部通过才关闭 B005。当前进度仍为 M0 9/9、MVP 7/13、总体 16/22；B006 未启动。

R6 第一个候选与 PR #24 未合并，保留 independent review FAIL（LOCAL-B005-R6-001）及 successful 5/5 CI。后续候选继续同一 R6 授权和 exact 08f8 repair base，补全 accepted main/checkout 两侧的 frozen artifact 与 rewrite/restore history 校验，并禁止已接受记录的失败被降级为 proposal。B005 仍 IN_PROGRESS，B006 未启动，工程进度保持 7/13 MVP。

B006 后继修复授权已接受（2026-10-06）：Owner 批准 `B006-B002-ZERO-RNG-REPAIR-Q001=A`，仅修复 `cloneProposal` 将合法 `rng_requests=[]` 复制为 `null` 的问题，增加 nil/empty 回放回归与明确的后继验收规则。原 B002 关闭快照及失败证据保留；公开 PR、同一独立只读 Codex 子代理复审、精确合并 SHA 的 5/5 CI 与不可变证据目录通过前不关闭 B006。当前补丁已应用；M0 100%，MVP 8/13（61.5%），总体 17/22（77.3%），真实模型和资格 Run 仍为 0。
