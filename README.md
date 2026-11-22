# Password One (`@opc/password-one`)

**Zero-Knowledge Policy-Bound Blind Credential Broker & 6-Encoding Output Scrubber for AI Agents.**

> LLMs never need to see plaintext passwords, API keys, private keys, or database DSNs—credentials belong strictly to the **outbound transport boundary** for milliseconds, and tool outputs (`stdout`, `stderr`, HTTP bodies, debug headers) must never echo secrets back into the LLM context window.

Built with **zero external runtime dependencies** on Node.js native TypeScript (`node:crypto`, `node:sqlite`, `node:http`, `node:child_process`, `node:test`).

---

## Why Naive `{{SECRET}}` Placeholders Are Not Enough

Simple placeholder wrappers (`{{STRIPE_KEY}}` -> `sk_live_...`) fail against real-world agent attacks:
1. **Confused-Deputy / SSRF Exfiltration**: Under Indirect Prompt Injection, an attacker tricks the agent into sending `Authorization: Bearer {{pw1://stripe/prod_key}}` to `https://evil.attacker.com/collect`—and a naive substituent injects the real production key.
2. **HTTP 302 Cross-Origin Redirect Theft**: Calling an allowlisted endpoint that returns `302 Found -> Location: https://evil.com/steal` causes standard HTTP clients to forward `Authorization` headers across origins.
3. **Multi-Encoding Tool Output Echo**: Verbose errors (`curl -v`, HTTP `500` traces) echo secrets in `Basic base64(user:pass)` (shifted 6-bit Base64 alignment!), URL `%XX` encoding, or nested JSON escaping, bypassing exact-string filters.
4. **Local SQLite Policy Tampering**: Modifying `allowed_hosts` directly in an unauthenticated local database bypasses ACL checks without knowing the master key.

---

## Four-Layer Architecture

1. **AAD-Bound Envelope Vault (`src/crypto.ts`, `src/vault.ts`)**
   - `scrypt` Master Key KDF -> `HKDF-SHA256` per-secret/per-version DEK -> `AES-256-GCM` authenticated encryption.
   - Binds `secretId | alias | version | sha256(canonicalPolicy)` into **AES-256-GCM AAD**. Tampering with `allowed_hosts` or `allowed_tools` in SQLite triggers immediate cryptographic authentication failure (`PolicyTamperError`).
2. **Opaque Handles & Short-Lived Scoped Leases (`src/vault.ts`)**
   - Agents only ever see handles (`pw1://stripe/prod_key` / `{{pw1://stripe/prod_key}}`) and sanitized policy metadata—never plaintext or ciphertext.
   - Supports issuing task-scoped leases (`grant_xxx`) bound to `agentId`, narrowed `allowedHosts`/`allowedTools`, atomic `maxUses`, and `ttlSeconds`.
3. **Policy-Bound Blind HTTP & Subprocess Gateway (`src/broker.ts`)**
   - **`executeHttp`**: Validates strict domain/subdomain allowlists (`api.stripe.com`, `*.stripe.com`), blocks URL userinfo/Host-header spoofing/DNS handle exfiltration, manually intercepts `301/302/303/307/308` redirects (blocking unauthorized cross-origin hops or stripping all credentials), injects plaintext at socket write time, and scrubs responses.
   - **`executeCommand`**: Uses shell-free `execFile` (`shell: false`), builds a sterile clean-room environment (never inheriting ambient host `process.env` secrets), blocks `env`/`printenv`/`set` sniffing & `LD_PRELOAD`/`NODE_OPTIONS` hijacking, and scrubs both `stdout` and `stderr`.
4. **6-Encoding Output Scrubber + SHA-256 Hash-Chained Audit Ledger (`src/scrubber.ts`, `src/vault.ts`)**
   - Redacts registered secrets across **raw**, **URL-encoded (RFC 3986 & `%XX` symbol runs)**, **Standard Base64**, **URL-Safe Base64**, **single/double JSON-escaped**, and **HTTP `Basic base64(user:secret)` (all 3 Base64 byte-alignment phases)** + heuristic patterns (`sk-...`, `ghp_...`, `AKIA...`, JWT, PEM private keys) -> `[REDACTED:pw1://<alias>]`.
   - Logs every mutation, allow, deny, tamper alert, and redaction hit into a tamper-evident **SHA-256 hash-chained SQLite ledger** verified via `verifyAuditChain()`.

---

## Quick Start (Zero Dependencies, Node >= 23.6 / v26)

```bash
# Run 22 unit, cryptographic, HTTP, MCP & adversarial benchmark tests
npm test

# Type-check strict TypeScript (zero external dependencies)
npm run typecheck

# Run interactive end-to-end live demo
npm run demo

# Run 8-scenario Red-vs-Blue adversarial & latency benchmark
npm run benchmark

# Start HTTP REST Broker (defaults to 127.0.0.1:52342)
PW1_MASTER_KEY="your-strong-master-passphrase" npm start

# Start JSON-RPC 2.0 stdio MCP Server
PW1_MASTER_KEY="your-strong-master-passphrase" npm run mcp
```

---

## HTTP REST API (`127.0.0.1:52342`)

| Method & Path | Description |
| :--- | :--- |
| `GET /health` | Health status, secret/grant counts, and live `auditChainValid` check |
| `GET /v1/secrets` | List opaque secret handles & bound policies (never returns plaintext or ciphertext) |
| `POST /v1/secrets` | Create or rotate (`version + 1`) an AAD-bound secret and access policy |
| `DELETE /v1/secrets/:alias` | Delete secret and revoke all associated grants |
| `POST /v1/grants` | Mint a short-lived scoped lease (`grant_xxx`) for a worker agent |
| `POST /v1/proxy/http` | Execute blind-injected HTTP call with SSRF & 302 cross-origin guards |
| `POST /v1/proxy/exec` | Execute blind-injected clean-room subprocess (`execFile`) |
| `POST /v1/scrub` | Scrub arbitrary text / third-party tool output across 6 encodings |
| `GET /v1/audit` | Query SHA-256 hash-chained audit records and chain integrity verification |
| `POST /v1/benchmark` | Run empirical 8-scenario Red-vs-Blue benchmark suite and return JSON report |

### Example: Provision Secret -> Mint Lease -> Blind Proxy Call

```bash
# 1. Provision secret bound strictly to api.stripe.com
curl -s http://127.0.0.1:52342/v1/secrets \
  -H "Content-Type: application/json" \
  -d '{
    "alias": "stripe/prod_key",
    "value": "<your-stripe-secret-key>",
    "description": "Production Stripe billing key",
    "policy": {
      "allowedHosts": ["api.stripe.com"],
      "allowedTools": ["http"],
      "requireGrant": true
    }
  }'

# 2. Issue a 2-use, 120-second lease for worker agent
curl -s http://127.0.0.1:52342/v1/grants \
  -H "Content-Type: application/json" \
  -d '{
    "alias": "stripe/prod_key",
    "agentId": "worker-billing-01",
    "maxUses": 2,
    "ttlSeconds": 120
  }'

# 3. Worker agent invokes blind HTTP proxy using only handle + grantId
curl -s http://127.0.0.1:52342/v1/proxy/http \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://api.stripe.com/v1/Balance",
    "auth": { "type": "bearer", "secret": "pw1://stripe/prod_key" },
    "agentId": "worker-billing-01",
    "grantId": "grant_..."
  }'
```

---

## MCP Server Tools (`src/mcp.ts`)

Exposes 5 tools over JSON-RPC 2.0 `stdio` (**intentionally zero tools to read plaintext**):
- `pw1_list_handles`
- `pw1_http_request`
- `pw1_exec_command`
- `pw1_scrub_output`
- `pw1_audit_verify`

---

## Red-vs-Blue Benchmark Summary (Node `v26.7.0`)

| Metric | `raw_env_agent` | `naive_placeholder_broker` | `password_one` (`@opc/password-one`) |
| :--- | :---: | :---: | :---: |
| **Attack Scenarios Defended (`S1`–`S7`)** | `0 / 7 (0%)` | `1 / 7 (14.3%)` | **`7 / 7 (100%)`** |
| **LLM Context Secret Token Exposures** | `5` | `3` | **`0`** |
| **Authorized Workflow Success (`S8`)** | `100%` | `100%` | **`100%`** |
| **Hot-Path Decrypt + Policy AAD Verify** | — | — | **`37.6 µs` mean (`33.4 µs` p50)** |
| **6-Encoding Scrubber (`2 KB` JSON)** | — | — | **`73.1 µs` mean (`69.1 µs` p50)** |

See [docs/RESEARCH.md](./docs/RESEARCH.md) for the formal threat model and cryptographic design, and [docs/EVALUATION.md](./docs/EVALUATION.md) for the full empirical evaluation report.

---

## Repository Structure

```text
password-one/
├── docs/
│   ├── RESEARCH.md          # Threat model (T1-T4) & 4-layer cryptographic specification
│   └── EVALUATION.md        # Empirical S1-S8 red-blue benchmark & integration guide
├── src/
│   ├── types.ts             # Domain types, policies, grants, audit & error classes
│   ├── crypto.ts            # scrypt + HKDF-SHA256 + AES-256-GCM Policy AAD envelope
│   ├── vault.ts             # node:sqlite vault, scoped leases & SHA-256 audit ledger
│   ├── scrubber.ts          # 6-encoding + 3-phase Base64 + regex bidirectional scrubber
│   ├── broker.ts            # Origin-locked HTTP hop controller & clean-room execFile gateway
│   ├── server.ts            # Loopback HTTP REST microservice (default 127.0.0.1:52342)
│   ├── mcp.ts               # JSON-RPC 2.0 over stdio MCP server (zero plaintext-read tools)
│   ├── benchmark.ts         # Live 8-scenario Red-vs-Blue adversarial & latency benchmark
│   ├── cli.ts               # CLI entrypoint (serve | mcp | benchmark | demo)
│   ├── index.ts             # Programmatic SDK exports
│   └── password-one.test.ts # 22 unit, tamper, SSRF, redirect, scrubber, HTTP & MCP tests
├── types/
│   └── node-minimal.d.ts    # Zero-dependency Node v26 built-in TypeScript declarations
├── package.json
├── tsconfig.json
├── .gitignore
└── LICENSE
```
