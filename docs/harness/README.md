# Harness Adapter（AIPT-M0-B005）

本目录描述正在施工的 **AIPT Harness Adapter**。它是 AIPT 产品运行时对象；
`$codex-harness` 则是 Codex↔DeepSeek 的施工 worker，两者不得混同。本批次的
计价路由为 `CODEX_ONLY`，没有调用后者执行 implementation 或 test leaf。

## 边界

Adapter 是 `@aipt/adapter-sdk` 上的一方薄层。生产 host 显式提供
`HarnessBackend`，再调用 `runProcessHarnessAdapter`。Adapter 不构造 prompt、
不选择模型、不读取 endpoint、不发现凭据、不转发 ambient environment，也不
打开 socket 或 Web listener。

stdin 使用 UTF-8、每个 LF 结束一条 JSON-RPC 信封，单帧正文上限 1 MiB。
clean EOF 正常结束；非法 UTF-8、非法 JSON/请求、超限帧和 EOF partial frame
全部失败关闭。backend 的完整响应批次先通过 SDK 编码和身份/transition 绑定，
然后按“response → notifications”顺序写出。stdout 只承载协议帧；stderr 只
输出固定 schema、稳定错误码和 `FAIL_CLOSED` disposition，绝不回显 payload、
异常正文或环境。

## 确定性 fixture runtime

生产目录 `src/` 不包含 B002 最小夹具的游戏字段或文件 I/O。测试专用 backend
位于 `packages/harness-adapter/test/fixture-backend.ts`，运行时读取既有权威资产：

- ACCEPT：精确输出 canonical result response，再输出 canonical state-event notification；
- REJECT：只输出 canonical protocol error response；
- 非 canonical 请求、输出身份漂移和 backend 故障均在 stdout 写入前失败关闭。

`pnpm run test:harness-adapter` 启动真实 Node 子进程，覆盖分帧、顺序、重复哈希、
1 MiB 上限、malformed UTF-8/JSON、partial EOF、clean EOF、背压、环境白名单、
诊断脱敏、有界 SIGTERM 取消及进程回收。测试不联网、不调用模型。

## DeepSeek Harness 兼容资格

Owner 于 2026-08-22 明确授权升级，当前兼容目标固定为
`dsh-v0.1.0-rc.8` / `141eb6fef83422698aef7a981029e843e8161534`；
此前冻结的 `47f943859bef60e4160492346772ded9b24f765a` 仅保留为历史 provenance。
机器记录见 [compatibility.json](compatibility.json)。

源码资格检查确认 DSH 当前版本仍提供显式 command/args 的受管 subprocess、pipe
stdio、协议 stdout/诊断 stderr 分离，以及 shutdown→EOF→SIGTERM→SIGKILL 的
有界清理能力。B005 只依赖这个**进程边界 seam**；AIPT wire vocabulary 仍完全
由 B002 Schema/SDK 决定，不复制 DSH SDK 的 session/prompt 方法，也不声称两套
JSON-RPC vocabulary 相同。CI 的确定性 smoke 只运行 AIPT fixture child，不需要
DSH checkout、远端 API 或模型凭据。

## 批次边界

`AIPT-M0-B005` 为 `IN_PROGRESS`，`GLOBAL_WIP = 1`。`AIPT-M0-B006` 为
`NOT_AUTHORIZED`，`next_batch_authorized = false`、`next_batch_started = false`；
本目录不定义 Evidence/Audit Schema、audit export 或其运行时。
