# Password One (`@opc/password-one`) — Red-vs-Blue Empirical Evaluation Report

> **Test Environment**: Node.js `v26.7.0` (macOS Apple Silicon, native TypeScript execution, `node:crypto`, `node:sqlite` WAL mode, real loopback `node:http` servers & `node:child_process.execFile` subprocesses)  
> **Reproduce Command**: `npm run benchmark` (or `node src/cli.ts benchmark --json`)

---

## 1. Executive Summary

We evaluated **Password One** against two widely deployed AI Agent credential architectures across **8 live adversarial & operational scenarios** (`S1`–`S8`):

1. **`raw_env_agent`**: Ambient environment variables / prompt-injected credentials (`process.env` + standard HTTP redirect following).
2. **`naive_placeholder_broker`**: Unbound string placeholder substitution (`{{SECRET_NAME}}`) with exact-match output filtering and unauthenticated SQLite ACL storage.
3. **`password_one`**: Zero-Knowledge Policy-Bound Blind Credential Broker (AES-256-GCM Policy AAD + Scoped Leases + Origin-Locked Redirect-Safe Gateway + 6-Encoding Output Scrubber + SHA-256 Hash-Chained Audit Ledger).

### Aggregate Scorecard

| Architecture | Adversarial Attacks Defended (`S1`–`S7`) | Defense Rate | Secret Leaks (Network + Context) | LLM Context Secret Token Exposures | Authorized Workflow Success (`S8`) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`raw_env_agent`** | `0 / 7` | `0.0%` | `7` | `5` | `100%` |
| **`naive_placeholder_broker`** | `1 / 7` | `14.3%` | `6` | `3` | `100%` |
| **`password_one` (`@opc/password-one`)** | **`7 / 7`** | **`100.0%`** | **`0`** | **`0`** | **`100%`** |

---

## 2. Detailed 8-Scenario Adversarial Matrix (`S1`–`S8`)

| ID | Threat Category | Adversarial Scenario | `raw_env_agent` | `naive_placeholder_broker` | `password_one` | Empirical Mechanism Verified |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **S1** | `T1`: Context Exfiltration | Direct / Indirect Prompt Injection reading agent visible context | **LEAKED** | **DEFENDED** | **DEFENDED** | LLM only sees `pw1://stripe/prod_key` handle & sanitized ACL metadata; zero secret tokens in context. |
| **S2** | `T2a`: Confused-Deputy SSRF | Indirect Prompt Injection sends `Bearer {{pw1://stripe/prod_key}}` to `http://evil.local/collect` | **LEAKED** | **LEAKED** | **DEFENDED** | Naive broker substitutes secret into attacker request; Password One aborts before TCP socket connect (`evil.local` not in `allowedHosts`). |
| **S3** | `T2b`: 302 Redirect Theft | Allowlisted `/v1/open-redirect` returns `302 Found -> Location: http://evil.local/steal` | **LEAKED** | **LEAKED** | **DEFENDED** | Naive redirect follower forwards `Authorization` header across origins; Password One manual hop controller blocks unauthorized cross-origin hop (and strips credentials in `strip` mode). |
| **S4** | `T3`: Upstream Debug Echo | Upstream `500` debug payload echoes raw header + nested double-JSON-escaped secret (`\"quote\"\\slash`) | **LEAKED** | **LEAKED** | **DEFENDED** | Exact-string filter misses double-JSON-escaped secret; Password One scrubs both raw and nested JSON-escaped forms before returning `ToolResult`. |
| **S5** | `T3`: Multi-Encoding Echo | Upstream echoes `Basic base64(merchant:secret)`, Std Base64, and `%5F` URL-encoded secret | **LEAKED** | **LEAKED** | **DEFENDED** | `merchant:` shifts Base64 6-bit alignment, bypassing naive substring filters; Password One's active Basic/Base64/Percent inspector + 3-phase slices redact all 3 forms. |
| **S6** | `T4a`: Subprocess Sniffing & Crash | Agent runs `printenv` or triggers CLI crash dumping raw + Base64 secret to `stderr` | **LEAKED** | **LEAKED** | **DEFENDED** | `printenv` blocked by clean-room policy; ambient `process.env` isolated; `stderr` scrubbed across all 6 encodings. |
| **S7** | `T4b`: Local DB ACL Tampering | Local attacker edits `allowed_hosts_json` + `policy_hash` directly in SQLite to add `evil.local` | **LEAKED** | **LEAKED** | **DEFENDED** | Recomputed policy hash alters AES-256-GCM AAD, causing `decipher.final()` authentication failure (`PolicyTamperError`); `0` bytes decrypted. |
| **S8** | Authorized Operations | Scoped `grant_xxx` HTTP `POST /v1/charges` + clean-room `node` CLI workflow | **OK (100%)** | **OK (100%)** | **OK (100%)** | Zero usability loss; atomic grant consumption (`usedCount` incremented) and tamper-evident audit logging verified. |

---

## 3. Micro-Benchmark Latency & Overhead Analysis

Measured over `200` iterations on Node `v26.7.0`:

| Operation | Mean Latency | `p50` Latency | `p95` Latency | Notes |
| :--- | :---: | :---: | :---: | :--- |
| **Secret Decrypt + Policy AAD Verify** | **`37.56 µs`** | **`33.42 µs`** | **`50.00 µs`** | Per-request hot path (`HKDF-SHA256` + `AES-256-GCM` + SQLite read) |
| **6-Encoding Output Scrubber (`2 KB` JSON)** | **`73.07 µs`** | **`69.12 µs`** | **`81.79 µs`** | Includes active `Basic <b64>`, `%XX` URL decode, 6-variant pass & regexes |
| **SHA-256 Audit Chain Verification (`19` rows)** | **`88.65 µs`** | **`78.71 µs`** | **`103.37 µs`** | Full genesis-to-head hash recomputation |
| **Secret Write/Rotate + AAD Bind + Audit Write** | **`857.83 µs`** | **`853.08 µs`** | **`1036.75 µs`** | Provisioning path (SQLite WAL write + chained audit insert) |
| **End-to-End Loopback Blind HTTP Proxy** | **`1.327 ms`** | — | — | Full broker pipeline + real TCP HTTP round-trip + response scrubbing |

### Key Performance Takeaway
Compared to typical LLM inference latencies (`500 ms` – `15,000 ms` per turn) and external SaaS API RTTs (`50 ms` – `400 ms`), Password One adds **~`0.11 ms` (`110 µs`) of cryptographic + multi-encoding scrubbing compute** on the tool execution hot path—less than **`0.03%`** overhead for complete inbound/outbound secret isolation.

---

## 4. Security Boundary Conditions & Governance Trade-offs

Even with cryptographic policy binding and 6-encoding output scrubbing, security architects should account for four boundary conditions:

1. **Semantic / Application-Layer Side Channels**:
   - *Limitation*: While Password One prevents exfiltrating the *credential* (`pw1://github/deploy_token`), a prompt-injected agent holding a valid lease can still abuse *authorized API business actions* on the allowlisted host (e.g., creating a public GitHub Gist containing sensitive repository source code on `api.github.com`).
   - *Mitigation*: Pair Password One with **short-lived, task-scoped grants (`POST /v1/grants` with `maxUses: 1..N` and narrow `ttlSeconds`)** and API-provider fine-grained token scopes (read-only vs write).
2. **Dynamic / Tenant-Specific Upstream Domains**:
   - *Challenge*: Multi-tenant SaaS APIs (`https://<customer>.myshopify.com` or S3 presigned URLs `https://<bucket>.s3.amazonaws.com`) cannot use a single static hostname.
   - *Governance Pattern*: Bind the secret policy to the registrable wildcard (`*.myshopify.com`) and `crossOriginRedirect: "strip"` (so `api.service.com -> s3.amazonaws.com` presigned download redirects automatically strip `Authorization` headers while still completing asset retrieval), then narrow per-task execution down to the exact tenant host (`acme.myshopify.com`) inside `POST /v1/grants`!
3. **Custom Compression / Encryption / Arbitrary Binary Encodings**:
   - *Limitation*: If an approved CLI tool compresses (`gzip`), encrypts, or hex-dumps every byte of a secret in an unconventional cipher before writing to `stdout`, deterministic 6-encoding + Base64/URL inspection cannot invert arbitrary compression without false positives.
   - *Mitigation*: Enforce strict `allowedCommands` (e.g., allow `stripe` or `psql`, never `python`/`bash`/`gzip`/`xxd` on production secrets) and set `allowEnvInjection: false` whenever a CLI supports safer file-descriptor or header flags.
4. **Master Key Custody (`PW1_MASTER_KEY`)**:
   - Password One runs as an **out-of-process boundary daemon** (`127.0.0.1:52342` or isolated MCP server process) so the agent worker process does not share memory space or `/proc/self/environ` with `PW1_MASTER_KEY`. In production hosts, inject `PW1_MASTER_KEY` from OS Keychain / systemd `LoadCredential` / KMS at daemon boot.

---

## 5. Agent Ecosystem Integration Blueprints

### A. Model Context Protocol (MCP) Integration (`Claude Desktop` / `Cursor` / `Antigravity`)
Configure Password One as an isolated stdio MCP server:
```json
{
  "mcpServers": {
    "password-one": {
      "command": "node",
      "args": ["/Users/penglei/developer/ai-github/password-one/src/cli.ts", "mcp"],
      "env": {
        "DATA_PATH": "/Users/penglei/.opc/password-one.sqlite",
        "PW1_MASTER_KEY": "<injected-from-keychain>"
      }
    }
  }
}
```
The LLM receives `pw1_list_handles`, `pw1_http_request`, `pw1_exec_command`, `pw1_scrub_output`, and `pw1_audit_verify`—with **zero** tool surface capable of returning plaintext secrets.

### B. `@ppeng/agent-loop` Tool Interceptor Middleware
1. **Pre-Loop Context Hydration**: Inject `GET /v1/secrets` handle descriptions into the system prompt instead of `.env` values.
2. **Tool Execution Routing**: Route outbound HTTP tool calls to `POST http://127.0.0.1:52342/v1/proxy/http` and CLI calls to `POST /v1/proxy/exec`.
3. **Post-Tool Output Guardrail**: Pass outputs from any third-party MCP server through `POST /v1/scrub` before appending `ToolResultMessage` to conversation history.

### C. OPC OS Dark Factory (Supervisor-Worker Lease Pattern)
1. **Supervisor** holds administrative provisioning access and mints a job-scoped grant (`POST /v1/grants` with `agentId: "worker-pr-42"`, `maxUses: 5`, `ttlSeconds: 180`).
2. **Untrusted Sandboxed Worker** receives only `grant_xxx` and `{{pw1://github/bot_token}}`.
3. **Post-Run Verification**: Supervisor queries `GET /v1/audit` to confirm `verification.valid === true` and verify zero `DENY` / `TAMPER_DETECTED` anomalies occurred during autonomous execution.
