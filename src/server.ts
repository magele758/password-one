import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { runRedBlueBenchmark } from './benchmark.ts';
import { PasswordOneBroker, type BrokerOptions } from './broker.ts';
import { PasswordOneMcpDispatcher, type JsonRpcRequest, type JsonRpcResponse } from './mcp.ts';
import {
  DEFAULT_DEV_MASTER_KEY,
  PasswordOneError,
  SERVICE_VERSION,
  type CreateGrantInput,
  type ProxyExecRequest,
  type ProxyHttpRequest,
  type UpsertSecretInput,
} from './types.ts';
import { PasswordOneVault } from './vault.ts';

export { DEFAULT_DEV_MASTER_KEY, SERVICE_VERSION } from './types.ts';
export const DEFAULT_PORT = 52342;
export const DEFAULT_HOST = '127.0.0.1';
export const MIN_AUTH_TOKEN_LENGTH = 16;

export interface PasswordOneServerOptions {
  port?: number;
  host?: string;
  dataPath?: string;
  masterKey?: string;
  authToken?: string;
  brokerToken?: string;
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
  authEnabled: boolean;
  brokerAuthEnabled: boolean;
  close: () => Promise<void>;
}

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const MAX_MCP_SESSIONS = 1024;

export function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  return normalized === '127.0.0.1' || normalized === '::1' || normalized === 'localhost';
}

function formatHostForUrl(host: string): string {
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
}

function sha256Digest(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

function extractBearerToken(req: IncomingMessage): string | null {
  const raw = req.headers['authorization'];
  if (typeof raw !== 'string') {
    return null;
  }
  const match = /^Bearer[ \t]+(.+)$/i.exec(raw.trim());
  return match ? match[1] : null;
}

type AuthRole = 'admin' | 'broker' | 'none';

function resolveAuthRole(
  req: IncomingMessage,
  expectedAdminDigest: Buffer | null,
  expectedBrokerDigest: Buffer | null
): AuthRole {
  const presented = extractBearerToken(req);
  if (!presented) {
    return 'none';
  }
  const presentedDigest = sha256Digest(presented);
  const isAdmin = expectedAdminDigest !== null && timingSafeEqual(presentedDigest, expectedAdminDigest);
  const isBroker = expectedBrokerDigest !== null && timingSafeEqual(presentedDigest, expectedBrokerDigest);
  if (isAdmin) return 'admin';
  if (isBroker) return 'broker';
  return 'none';
}

function isAdminOnlyRoute(method: string, pathname: string): boolean {
  if (method === 'POST' && pathname === '/v1/secrets') return true;
  if (method === 'DELETE' && pathname.startsWith('/v1/secrets/')) return true;
  if (method === 'POST' && pathname === '/v1/grants') return true;
  if (method === 'POST' && pathname === '/v1/benchmark') return true;
  return false;
}

function sendJson(
  res: ServerResponse,
  statusCode: number,
  payload: unknown,
  extraHeaders?: Record<string, string>
): void {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body, 'utf8'),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...extraHeaders,
  });
  res.end(body);
}

function sendAccepted(res: ServerResponse, extraHeaders?: Record<string, string>): void {
  res.writeHead(202, {
    'content-length': 0,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...extraHeaders,
  });
  res.end();
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
  const rawEnvPort = process.env.PORT?.trim();
  const port = options?.port ?? (rawEnvPort ? Number(rawEnvPort) : DEFAULT_PORT);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new PasswordOneError('INVALID_INPUT', 'Invalid PORT configuration (expected integer 0-65535)', 400);
  }

  const host = (options?.host ?? (process.env.HOST?.trim() || undefined) ?? DEFAULT_HOST).trim();
  const dataPath =
    options?.dataPath ??
    (process.env.DATA_PATH?.trim() || undefined) ??
    join(process.cwd(), 'data', 'password-one.sqlite');
  const authToken =
    options?.authToken !== undefined
      ? options.authToken.trim() || undefined
      : process.env.PW1_AUTH_TOKEN?.trim() || undefined;
  const brokerToken =
    options?.brokerToken !== undefined
      ? options.brokerToken.trim() || undefined
      : process.env.PW1_BROKER_TOKEN?.trim() || undefined;
  const rawMasterKey = options?.masterKey !== undefined ? options.masterKey : process.env.PW1_MASTER_KEY;
  const trimmedMasterKey = rawMasterKey?.trim() ?? '';

  if (authToken && /[\r\n]/.test(authToken)) {
    throw new PasswordOneError('INVALID_INPUT', 'PW1_AUTH_TOKEN must not contain CR/LF characters', 400);
  }
  if (brokerToken && /[\r\n]/.test(brokerToken)) {
    throw new PasswordOneError('INVALID_INPUT', 'PW1_BROKER_TOKEN must not contain CR/LF characters', 400);
  }

  const expectedAdminDigest = authToken ? sha256Digest(authToken) : null;
  const expectedBrokerDigest = brokerToken ? sha256Digest(brokerToken) : null;

  if (expectedAdminDigest && expectedBrokerDigest && timingSafeEqual(expectedAdminDigest, expectedBrokerDigest)) {
    throw new PasswordOneError(
      'INVALID_INPUT',
      'PW1_AUTH_TOKEN and PW1_BROKER_TOKEN must be distinct tokens',
      400
    );
  }

  if (!isLoopbackHost(host)) {
    if (!authToken || authToken.length < MIN_AUTH_TOKEN_LENGTH) {
      throw new PasswordOneError(
        'INVALID_INPUT',
        `Refusing to bind non-loopback host "${host}" without PW1_AUTH_TOKEN (minimum ${MIN_AUTH_TOKEN_LENGTH} characters)`,
        400
      );
    }
    if (brokerToken !== undefined && brokerToken.length < MIN_AUTH_TOKEN_LENGTH) {
      throw new PasswordOneError(
        'INVALID_INPUT',
        `Refusing to bind non-loopback host "${host}" with weak PW1_BROKER_TOKEN (minimum ${MIN_AUTH_TOKEN_LENGTH} characters)`,
        400
      );
    }
    if (!trimmedMasterKey || trimmedMasterKey === DEFAULT_DEV_MASTER_KEY) {
      throw new PasswordOneError(
        'INVALID_INPUT',
        `Refusing to bind non-loopback host "${host}" without an explicit non-default PW1_MASTER_KEY`,
        400
      );
    }
  }

  const masterKey =
    rawMasterKey !== undefined && trimmedMasterKey.length > 0 ? rawMasterKey : DEFAULT_DEV_MASTER_KEY;
  const authRequired = expectedAdminDigest !== null || expectedBrokerDigest !== null;

  const vault = new PasswordOneVault({
    dbPath: dataPath,
    masterKey,
    scryptN: options?.scryptN,
  });
  const broker = new PasswordOneBroker(vault, options?.brokerOptions);
  const mcpDispatcher = new PasswordOneMcpDispatcher(vault, broker);
  const mcpSessions = new Set<string>();
  const createMcpSession = (): string => {
    if (mcpSessions.size >= MAX_MCP_SESSIONS) {
      const oldest = mcpSessions.values().next().value;
      if (oldest) {
        mcpSessions.delete(oldest);
      }
    }
    const id = randomUUID();
    mcpSessions.add(id);
    return id;
  };
  const startedAt = Date.now();
  const urlHost = formatHostForUrl(host);

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const method = (req.method ?? 'GET').toUpperCase();
      const parsedUrl = new URL(req.url ?? '/', `http://${urlHost}:${port}`);
      const pathname = parsedUrl.pathname;

      const authRole = authRequired ? resolveAuthRole(req, expectedAdminDigest, expectedBrokerDigest) : 'admin';

      if (method === 'GET' && pathname === '/health') {
        if (authRequired && authRole === 'none') {
          sendJson(res, 200, {
            ok: true,
            service: 'password-one',
            version: SERVICE_VERSION,
          });
          return;
        }
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

      if (authRequired && authRole === 'none') {
        sendJson(
          res,
          401,
          {
            ok: false,
            error: {
              code: 'UNAUTHORIZED',
              message: 'Valid Bearer token required',
            },
          },
          { 'www-authenticate': 'Bearer realm="password-one"' }
        );
        return;
      }

      if (authRequired && isAdminOnlyRoute(method, pathname) && authRole !== 'admin') {
        sendJson(res, 403, {
          ok: false,
          error: {
            code: 'FORBIDDEN',
            message: 'Admin token required for this endpoint',
          },
        });
        return;
      }

      if (pathname === '/mcp') {
        if (method === 'GET') {
          sendJson(
            res,
            405,
            {
              ok: false,
              error: {
                code: 'METHOD_NOT_ALLOWED',
                message: 'GET /mcp is not supported; use POST or DELETE',
              },
            },
            { allow: 'POST, DELETE' }
          );
          return;
        }

        if (method === 'DELETE') {
          const reqSessionId = req.headers['mcp-session-id'];
          if (typeof reqSessionId === 'string' && reqSessionId.trim()) {
            mcpSessions.delete(reqSessionId.trim());
          }
          sendJson(res, 200, { ok: true });
          return;
        }

        if (method !== 'POST') {
          sendJson(
            res,
            405,
            {
              ok: false,
              error: {
                code: 'METHOD_NOT_ALLOWED',
                message: `Method ${method} is not allowed on /mcp; use POST or DELETE`,
              },
            },
            { allow: 'POST, DELETE' }
          );
          return;
        }

        let parsedPayload: unknown;
        try {
          parsedPayload = await readJsonBody<unknown>(req);
        } catch (err) {
          if (err instanceof PasswordOneError && err.statusCode === 400) {
            sendJson(res, 400, {
              jsonrpc: '2.0',
              id: null,
              error: { code: -32700, message: 'Parse error' },
            });
            return;
          }
          throw err;
        }

        if (Array.isArray(parsedPayload)) {
          if (parsedPayload.length === 0) {
            sendJson(res, 400, {
              jsonrpc: '2.0',
              id: null,
              error: { code: -32600, message: 'Invalid Request: empty JSON-RPC batch' },
            });
            return;
          }

          const responses: JsonRpcResponse[] = [];
          let initializedSessionId: string | undefined;

          for (const item of parsedPayload) {
            const response = await mcpDispatcher.handleMessage(item as JsonRpcRequest);
            if (response) {
              responses.push(response);
              if (
                !initializedSessionId &&
                item &&
                typeof item === 'object' &&
                !Array.isArray(item) &&
                (item as JsonRpcRequest).method === 'initialize' &&
                !response.error
              ) {
                initializedSessionId = createMcpSession();
              }
            }
          }

          const extraHeaders = initializedSessionId ? { 'mcp-session-id': initializedSessionId } : undefined;
          if (responses.length === 0) {
            sendAccepted(res, extraHeaders);
            return;
          }

          sendJson(res, 200, responses, extraHeaders);
          return;
        }

        const singleReq = parsedPayload as JsonRpcRequest;
        const response = await mcpDispatcher.handleMessage(singleReq);
        if (!response) {
          sendAccepted(res);
          return;
        }

        let extraHeaders: Record<string, string> | undefined;
        if (
          singleReq &&
          typeof singleReq === 'object' &&
          !Array.isArray(singleReq) &&
          singleReq.method === 'initialize' &&
          !response.error
        ) {
          extraHeaders = { 'mcp-session-id': createMcpSession() };
        }

        sendJson(res, 200, response, extraHeaders);
        return;
      }

      if (method === 'GET' && pathname === '/v1/handles') {
        const handles = vault.listSecrets();
        sendJson(res, 200, { ok: true, handles });
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

  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => {
        server.off('error', reject);
        resolve();
      });
    });
  } catch (err) {
    vault.close();
    throw err;
  }

  const addr = server.address() as AddressInfo;
  const boundPort = addr.port;
  const baseUrl = `http://${urlHost}:${boundPort}`;

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
    authEnabled: authRequired,
    brokerAuthEnabled: expectedBrokerDigest !== null,
    close,
  };
}
