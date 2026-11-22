# Password One · 生产过程回放

> [!IMPORTANT]
> 这是**事后回放**：本仓库初版由 Antigravity 主会话派出的子 agent 在其自身会话中完成，**没有**经过 OPC OS 工作流（无计划审批、无 Herdr 隔离工作树、无独立评审）。本文件由该子 agent 的原始会话日志自动生成，用于让过程可追溯；评测数据由实现者自建，尚未独立验证。

| 项 | 值 |
|---|---|
| 执行者 | Antigravity 子 agent（模型 `gemini-4-carbon-medium`，会话 `ab4f8573-7c02-4f85-8d2e-99f8e6fee7b0`） |
| 起止 | 2026-11-22T12:39:19Z → 2026-11-22T13:06:04Z（27 分钟） |
| 工具调用 | 39 次：写/改文件 26，命令 9（失败 3），测试运行 2 |
| Token | 输入 189,530，输出 99,366，缓存命中 3,516,561 |
| 产出文件 | 19 个 |

## 原始任务书（主会话下发，未删改）

<details><summary>展开</summary>

> 你负责完整落地第 2 个独立课题项目与服务：**Password One**，目录为 `/Users/penglei/developer/ai-github/password-one`（目录已创建，当前为空）。
> 
> ## 背景与研究目标
> 在当前的 AI Agent 体系中，LLM 本身根本不需要看到明文密码、API Key、私钥或数据库连接串——**只有真实工具执行（HTTP 请求、CLI 子进程、数据库连接）的那一瞬间在传输边界需要凭据，且工具调用的返回结果（`stdout`/`stderr`/HTTP 响应体/调试头）也绝不应该把密码回传给 LLM 上下文**！
> 更深入一步，如果只做“朴素占位符字符串替换（Naive Placeholder Substitution）”，还会遭遇致命的 **Confused-Deputy（困惑副手 / SSRF 凭据窃取）攻击**：一旦 Agent 遭遇间接提示词注入（Indirect Prompt Injection），攻击者诱导 Agent 调用 HTTP 工具把 `{{pw1://prod_stripe_key}}` 发往 `https://attacker.evil.com/collect`，朴素替换器会照样填入真秘钥外泄！同时，如果工具报错在 `stderr` 或以 Base64 / Basic-Auth / URL 编码回显了凭据，朴素精确字符串匹配也会漏检回流进 LLM Context！
> 
> 因此，你需要先深入研究并撰写安全架构方案，再实现一个**零外部臃肿依赖（基于本机 Node v26 原生 TypeScript、`node:crypto`、`node:sqlite`、`node:http`、`node:child_process`、`node:test`）**的独立开源级项目与服务 `@opc/password-one`，并用真实红蓝对抗基准实验量化验证其安全与性能价值！
> 
> ## 交付要求（全部在 `/Users/penglei/developer/ai-github/password-one` 内完成）
> 
> 1. **深度课题研究与威胁建模文档 `docs/RESEARCH.md`**：
>    - 建立完整的 **AI Agent 凭据威胁模型（Threat Model
> <truncated 5368 bytes>
>     2. S2 Confused-Deputy SSRF 外带攻击（将合法句柄发往 `evil.local`）；
>      3. S3 HTTP 302 跨域重定向窃取 `Authorization` 头攻击；
>      4. S4 远端调试接口在响应 JSON 中原样回显请求头明文秘钥；
>      5. S5 工具输出中以 Base64 / Basic-Auth / URL-Encoded 形态回显秘钥；
>      6. S6 子进程 `printenv` / `stderr` 异常堆栈回显秘钥；
>      7. S7 数据库存储层直接篡改 `allowed_hosts` 企图越权解密（验证 AES-256-GCM AAD 拦截）；
>      8. S8 合法授权 HTTP 与 CLI 工具调用成功率 + 单次加解密/脱敏微秒级延迟 & LLM Context 秘钥 Token 暴露数统计。
>    - `src/cli.ts` & `src/index.ts`：支持 `serve`、`mcp`、`benchmark`、`demo` 子命令。
>    - `src/password-one.test.ts`：使用 `node:test` + `node:assert/strict` 编写覆盖加密与 AAD 防篡改、Vault 生命周期、6 种编码脱敏器、SSRF 拦截、302 跨域剥离、子进程安全注入、审计哈希链校验、HTTP 服务全接口测试、MCP 协议测试及 Benchmark 断言（至少 18+ 测试用例）。
> 
> 3. **实测红蓝评估报告 `docs/EVALUATION.md` 与 `README.md`**：
>    - 运行 `node src/cli.ts benchmark` 获取真实攻防拦截率与微秒/毫秒级性能开销数据，写入 `docs/EVALUATION.md`，总结核心安全收益、边界条件（如工具自身业务侧信道、动态域名场景如何治理）及与 Agent 框架（MCP / `@ppeng/agent-loop` / OPC OS Dark Factory）的集成方案。
>    - 写好清晰的 `README.md`、`LICENSE`、`.gitignore`。
> 
> 4. **Git 仓库初始化与干净提交**：
>    - 在 `/Users/penglei/developer/ai-github/password-one` 执行 `git init -b main`，确保 `npm test` 100% 通过且无残留临时文件，提交干净的初始 commit（不要留常驻后台进程阻塞退出，主控稍后会统一拉起服务）。
> 
> 完成后，向我汇报：仓库结构、测试通过情况、8 大攻防场景 Benchmark 实测对比表、延迟开销、关键文件路径及 Git Commit SHA。

</details>

任务书中预先写定了架构、指标和“彻底防御 / 量化验证价值”等期望结论，评测场景也由同一执行者设计——这是本次评测不能作为价值证明的主要原因。

## 测试运行轨迹

| 时间 | 结果 |
|---|---|
| 21:01:00 | 20 通过 / 2 失败 |
| 21:05:05 | 22 通过 / 0 失败 |

## 失败与返工

- 20:39:38 Verify Node native TypeScript execution：`node --input-type=module -e 'const x: number = 42; console.log(x);'` → **失败 (exit 1)**
- 20:59:06 Run typecheck and test suite：`cd /Users/penglei/developer/ai-github/password-one && npm run typecheck && npm test` → **失败 (exit 2)**
- 21:01:00 Run typecheck, 22 tests, benchmark, and demo：`cd /Users/penglei/developer/ai-github/password-one && npm run typecheck && npm test && node src/cli.ts benchmark && node src/cli.ts demo` → **失败 (exit 1)**（测试 20 通过 / 2 失败）

## 完整时间线

| 时间 | 阶段 | 动作 |
|---|---|---|
| 20:39:19 | 环境检查 | Check Node version and target directory：`node -v && npm -v && ls -la /Users/penglei/developer/ai-github/password-one && echo "HC=$HC_TERMINAL_ID HFLOW=$HFLOW_WORKER" && which tsc \|\| true` → 成功 |
| 20:39:26 | 环境检查 | Verify node:sqlite and tsc version：`node -e 'import("node:sqlite").then(m => console.log("sqlite keys:", Object.keys(m)))' && /Users/penglei/.nvm/versions/node/v22.21.1/bin/tsc -v` → 成功 |
| 20:39:38 | 环境检查 | Verify Node native TypeScript execution：`node --input-type=module -e 'const x: number = 42; console.log(x);'` → **失败 (exit 1)** |
| 20:39:47 | 环境检查 | Test module-typescript in Node v26：`node --input-type=module-typescript -e 'const x: number = 42; console.log("ts ok:", x);'` → 成功 |
| 20:39:56 | 方案研究 | 写入 `docs/RESEARCH.md`（覆盖） |
| 20:43:10 | 实现 | 写入 `package.json`（覆盖） |
| 20:43:29 | 实现 | 写入 `tsconfig.json`（覆盖） |
| 20:43:36 | 实现 | 写入 `.gitignore`（覆盖） |
| 20:43:43 | 实现 | 写入 `LICENSE`（覆盖） |
| 20:43:54 | 实现 | 写入 `types/node-minimal.d.ts`（覆盖） |
| 20:44:47 | 实现 | 写入 `src/types.ts`（覆盖） |
| 20:45:17 | 实现 | 写入 `src/crypto.ts`（覆盖） |
| 20:46:03 | 实现 | 写入 `src/scrubber.ts`（覆盖） |
| 20:47:19 | 实现 | 写入 `src/vault.ts`（覆盖） |
| 20:49:18 | 实现 | 写入 `src/broker.ts`（覆盖） |
| 20:51:45 | 基准评测 | 写入 `src/benchmark.ts`（覆盖） |
| 20:54:41 | 实现 | 写入 `src/server.ts`（覆盖） |
| 20:55:24 | 实现 | 写入 `src/mcp.ts`（覆盖） |
| 20:56:10 | 实现 | 写入 `src/index.ts`（覆盖） |
| 20:56:36 | 实现 | 写入 `src/cli.ts`（覆盖） |
| 20:57:13 | 测试与修复 | 写入 `src/password-one.test.ts`（覆盖） |
| 20:59:06 | 测试与修复 | Run typecheck and test suite：`cd /Users/penglei/developer/ai-github/password-one && npm run typecheck && npm test` → **失败 (exit 2)** |
| 20:59:32 | 实现 | 修改 `types/node-minimal.d.ts` |
| 20:59:49 | 测试与修复 | 修改 `src/password-one.test.ts` |
| 21:00:35 | 测试与修复 | 修改 `src/password-one.test.ts` |
| 21:01:00 | 基准评测 | Run typecheck, 22 tests, benchmark, and demo：`cd /Users/penglei/developer/ai-github/password-one && npm run typecheck && npm test && node src/cli.ts benchmark && node src/cli.ts demo` → **失败 (exit 1)**（测试 20 通过 / 2 失败） |
| 21:01:10 | 实现 | 修改 `src/scrubber.ts` |
| 21:01:35 | 环境检查 | 阅读 `src/scrubber.ts` |
| 21:02:23 | 环境检查 | 阅读 `src/scrubber.ts` |
| 21:02:27 | 实现 | 修改 `src/scrubber.ts` |
| 21:02:36 | 实现 | 修改 `src/scrubber.ts` |
| 21:02:47 | 基准评测 | 修改 `src/benchmark.ts` |
| 21:03:14 | 基准评测 | Verify typecheck, 22 tests, benchmark, and demo：`cd /Users/penglei/developer/ai-github/password-one && npm run typecheck && npm test && node src/cli.ts benchmark && node src/cli.ts demo` → 成功 |
| 21:03:24 | 报告与文档 | 写入 `docs/EVALUATION.md`（覆盖） |
| 21:04:18 | 报告与文档 | 写入 `README.md`（覆盖） |
| 21:05:05 | 测试与修复 | Run final typecheck, test suite, and inspect files：`cd /Users/penglei/developer/ai-github/password-one && npm run typecheck && npm test && ls -la && ls -la src docs types` → 成功（测试 22 通过 / 0 失败） |
| 21:05:14 | 提交 | Initialize git repository and commit initial release：`cd /Users/penglei/developer/ai-github/password-one && chmod +x src/cli.ts && git init -b main && git add -A && git commit -m "feat: implement Password One (@opc` → 成功 |
| 21:05:22 | 环境检查 | manage_task |
| 21:05:27 | 环境检查 | send_message |

## 产出文件

- `docs/RESEARCH.md`
- `package.json`
- `tsconfig.json`
- `.gitignore`
- `LICENSE`
- `types/node-minimal.d.ts`
- `src/types.ts`
- `src/crypto.ts`
- `src/scrubber.ts`
- `src/vault.ts`
- `src/broker.ts`
- `src/benchmark.ts`
- `src/server.ts`
- `src/mcp.ts`
- `src/index.ts`
- `src/cli.ts`
- `src/password-one.test.ts`
- `docs/EVALUATION.md`
- `README.md`
