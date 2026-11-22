import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { runRedBlueBenchmark } from './benchmark.ts';
import { PasswordOneBroker, type BrokerOptions } from './broker.ts';
import {
  PasswordOneError,
  type CreateGrantInput,
  type ProxyExecRequest,
  type ProxyHttpRequest,
  type UpsertSecretInput,
} from './types.ts';
import { PasswordOneVault } from './vault.ts';

export const SERVICE_VERSION = '0.1.0';
export const DEFAULT_PORT = 52342;
export const DEFAULT_HOST = '127.0.0.1';

export interface PasswordOneServerOptions {
  port?: number;
  host?: string;
  dataPath?: string;
  masterKey?: string;
  scryptN?: number;
  brokerOptions?: BrokerOptions;
}

export interface RunningPasswordOneServer {
  server: Server;
  vault: PasswordOneVault;
  broker: PasswordOneBroker;
  host: string;
  port: number;
  baseUrl: string;
  close: () => Promise<void>;
}

const MAX_BODY_BYTES = 2 * 1024 * 1024;

function sendJson(res: ServerResponse, statusCode: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body, 'utf8'),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(body);
}

async function readJsonBody<T>(req: IncomingMessage): Promise<T> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer | string) => {
      const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
      total += buf.length;
      if (total > MAX_BODY_BYTES) {
        req.destroy();
        reject(new PasswordOneError('INVALID_INPUT', 'Request JSON body exceeds 2MB limit', 413));
        return;
      }
      chunks.push(buf);
    });
    req.on('end', () => {
      if (chunks.length === 0) {
        resolve({} as T);
        return;
      }
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) {
        resolve({} as T);
        return;
      }
      try {
        resolve(JSON.parse(raw) as T);
      } catch {
        reject(new PasswordOneError('INVALID_INPUT', 'Malformed JSON request body', 400));
      }
    });
    req.on('error', (err: Error) => {
      reject(new PasswordOneError('INVALID_INPUT', `Request stream error: ${err.message}`, 400));
    });
  });
}

export async function startPasswordOneServer(
  options?: PasswordOneServerOptions
): Promise<RunningPasswordOneServer> {
  const port = options?.port ?? (process.env.PORT ? Number(process.env.PORT) : DEFAULT_PORT);
  const host = options?.host ?? process.env.HOST ?? DEFAULT_HOST;
  const dataPath = options?.dataPath ?? process.env.DATA_PATH ?? join(process.cwd(), 'data', 'password-one.sqlite');
  const masterKey =
    options?.masterKey ?? process.env.PW1_MASTER_KEY ?? 'pw1-local-dev-master-key-change-in-prod';

  const vault = new PasswordOneVault({
    dbPath: dataPath,
    masterKey,
    scryptN: options?.scryptN,
  });
  const broker = new PasswordOneBroker(vault, options?.brokerOptions);
  const startedAt = Date.now();

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const method = (req.method ?? 'GET').toUpperCase();
      const parsedUrl = new URL(req.url ?? '/', `http://${host}:${port}`);
      const pathname = parsedUrl.pathname;

      if (method === 'GET' && pathname === '/health') {
        const stats = vault.getStats();
        sendJson(res, 200, {
          ok: true,
          service: 'password-one',
          version: SERVICE_VERSION,
          secretsCount: stats.secretsCount,
          activeGrantsCount: stats.activeGrantsCount,
          auditEntriesCount: stats.auditEntriesCount,
          auditChainValid: stats.auditVerification.valid,
          auditHeadHash: stats.auditVerification.headHash,
          uptimeMs: Date.now() - startedAt,
        });
        return;
      }

      if (method === 'GET' && pathname === '/v1/secrets') {
        const secrets = vault.listSecrets();
        sendJson(res, 200, { ok: true, secrets });
        return;
      }

      if (method === 'POST' && pathname === '/v1/secrets') {
        const body = await readJsonBody<UpsertSecretInput>(req);
        const secret = vault.upsertSecret(body);
        sendJson(res, 201, { ok: true, secret });
        return;
      }

      if (method === 'DELETE' && pathname.startsWith('/v1/secrets/')) {
        const rawSuffix = pathname.slice('/v1/secrets/'.length);
        const alias = decodeURIComponent(rawSuffix);
        if (!alias) {
          throw new PasswordOneError('INVALID_INPUT', 'Missing secret alias in DELETE path', 400);
        }
        const deleted = vault.deleteSecret(alias);
        if (!deleted) {
          sendJson(res, 404, {
            ok: false,
            error: { code: 'SECRET_NOT_FOUND', message: `Secret "${alias}" not found` },
          });
          return;
        }
        sendJson(res, 200, { ok: true, deleted: true, alias });
        return;
      }

      if (method === 'POST' && pathname === '/v1/grants') {
        const body = await readJsonBody<CreateGrantInput>(req);
        const grant = vault.createGrant(body);
        sendJson(res, 201, { ok: true, grant });
        return;
      }

      if (method === 'POST' && pathname === '/v1/proxy/http') {
        const body = await readJsonBody<ProxyHttpRequest>(req);
        const result = await broker.executeHttp(body);
        sendJson(res, 200, { ok: true, result });
        return;
      }

      if (method === 'POST' && pathname === '/v1/proxy/exec') {
        const body = await readJsonBody<ProxyExecRequest>(req);
        const result = await broker.executeCommand(body);
        sendJson(res, 200, { ok: true, result });
        return;
      }

      if (method === 'POST' && pathname === '/v1/scrub') {
        const body = await readJsonBody<{ text?: string; source?: string }>(req);
        if (typeof body.text !== 'string') {
          throw new PasswordOneError('INVALID_INPUT', 'Field "text" (string) is required for /v1/scrub', 400);
        }
        const result = broker.scrubText(body.text, body.source ?? 'http_api_scrub');
        sendJson(res, 200, { ok: true, result });
        return;
      }

      if (method === 'GET' && pathname === '/v1/audit') {
        const limitParam = parsedUrl.searchParams.get('limit');
        const limit = limitParam ? Number(limitParam) : 100;
        const verification = vault.verifyAuditChain();
        const entries = vault.listAuditLogs(Number.isFinite(limit) ? limit : 100);
        sendJson(res, 200, {
          ok: true,
          verification,
          entries,
        });
        return;
      }

      if (method === 'POST' && pathname === '/v1/benchmark') {
        const body = await readJsonBody<{ microIterations?: number }>(req);
        const report = await runRedBlueBenchmark({
          microIterations: body.microIterations ?? 100,
        });
        sendJson(res, 200, { ok: true, report });
        return;
      }

      sendJson(res, 404, {
        ok: false,
        error: { code: 'NOT_FOUND', message: `Route ${method} ${pathname} not found` },
      });
    } catch (err) {
      if (err instanceof PasswordOneError) {
        const scrubbedMsg = broker.scrubText(err.message, 'error_handler').scrubbedText;
        sendJson(res, err.statusCode, {
          ok: false,
          error: {
            code: err.code,
            message: scrubbedMsg,
          },
        });
        return;
      }
      const fallbackMsg = err instanceof Error ? broker.scrubText(err.message, 'error_handler').scrubbedText : 'Internal server error';
      sendJson(res, 500, {
        ok: false,
        error: {
          code: 'INTERNAL_ERROR',
          message: fallbackMsg,
        },
      });
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });

  const addr = server.address() as AddressInfo;
  const boundPort = addr.port;
  const baseUrl = `http://${host}:${boundPort}`;

  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    vault.close();
  };

  return {
    server,
    vault,
    broker,
    host,
    port: boundPort,
    baseUrl,
    close,
  };
}
