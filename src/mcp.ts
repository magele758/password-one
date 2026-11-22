import { join } from 'node:path';
import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';
import { PasswordOneBroker, type BrokerOptions } from './broker.ts';
import { SERVICE_VERSION } from './server.ts';
import {
  PasswordOneError,
  type HttpAuthBinding,
  type ProxyExecRequest,
  type ProxyHttpRequest,
} from './types.ts';
import { PasswordOneVault } from './vault.ts';

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export const MCP_TOOLS_DEFINITION = [
  {
    name: 'pw1_list_handles',
    description:
      'List available opaque credential handles (pw1://<alias>) and their bound host/tool policies. Never exposes secret plaintext.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: 'pw1_http_request',
    description:
      'Execute an outbound HTTP request using blind credential handles ({{pw1://alias}}). Enforces host allowlists, blocks cross-origin 302 credential theft, and scrubs echoed secrets.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'Target HTTPS (or policy-permitted HTTP) URL' },
        method: { type: 'string', description: 'HTTP method (GET, POST, PUT, PATCH, DELETE)' },
        headers: {
          type: 'object',
          additionalProperties: { type: 'string' },
          description: 'Request headers; may contain {{pw1://alias}} placeholders',
        },
        query: {
          type: 'object',
          additionalProperties: { type: 'string' },
          description: 'Query parameters; may contain {{pw1://alias}} placeholders',
        },
        body: { type: 'string', description: 'Optional request body; may contain {{pw1://alias}} placeholders' },
        auth: {
          type: 'object',
          description: 'Structured auth binding ({ type: "bearer"|"basic"|"header"|"query", secret: "pw1://alias", ... })',
        },
        agentId: { type: 'string' },
        grantId: { type: 'string', description: 'Optional scoped lease ID (grant_xxx)' },
      },
      required: ['url'],
      additionalProperties: false,
    },
  },
  {
    name: 'pw1_exec_command',
    description:
      'Execute an allowlisted CLI binary via shell-free execFile with clean-room environment secret injection and 6-encoding stdout/stderr scrubbing.',
    inputSchema: {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'Executable binary name or path (shell=false)' },
        args: { type: 'array', items: { type: 'string' } },
        env: { type: 'object', additionalProperties: { type: 'string' } },
        secretEnv: {
          type: 'object',
          additionalProperties: { type: 'string' },
          description: 'Map of ENV_VAR -> pw1://alias',
        },
        cwd: { type: 'string' },
        timeoutMs: { type: 'number' },
        agentId: { type: 'string' },
        grantId: { type: 'string' },
      },
      required: ['command'],
      additionalProperties: false,
    },
  },
  {
    name: 'pw1_scrub_output',
    description:
      'Scrub arbitrary text or tool outputs against all active secrets across 6 encodings (raw, URL, Base64, Base64URL, JSON-escaped, Basic-Auth) plus high-risk credential patterns.',
    inputSchema: {
      type: 'object',
      properties: {
        text: { type: 'string', description: 'Text to sanitize' },
      },
      required: ['text'],
      additionalProperties: false,
    },
  },
  {
    name: 'pw1_audit_verify',
    description:
      'Verify cryptographic integrity of the SHA-256 hash-chained audit ledger and return recent sanitized audit records.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Number of recent audit entries to return (default 20)' },
      },
      additionalProperties: false,
    },
  },
] as const;

export class PasswordOneMcpDispatcher {
  readonly #vault: PasswordOneVault;
  readonly #broker: PasswordOneBroker;

  constructor(vault: PasswordOneVault, broker: PasswordOneBroker) {
    this.#vault = vault;
    this.#broker = broker;
  }

  async handleMessage(msg: JsonRpcRequest): Promise<JsonRpcResponse | null> {
    if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
      return {
        jsonrpc: '2.0',
        id: msg?.id ?? null,
        error: { code: -32600, message: 'Invalid JSON-RPC 2.0 request' },
      };
    }

    // Notifications (no `id`) require no response frame
    if (msg.id === undefined) {
      return null;
    }

    try {
      switch (msg.method) {
        case 'initialize': {
          return {
            jsonrpc: '2.0',
            id: msg.id,
            result: {
              protocolVersion: '2024-11-05',
              capabilities: {
                tools: {},
              },
              serverInfo: {
                name: '@opc/password-one',
                version: SERVICE_VERSION,
              },
            },
          };
        }

        case 'ping': {
          return {
            jsonrpc: '2.0',
            id: msg.id,
            result: {},
          };
        }

        case 'tools/list': {
          return {
            jsonrpc: '2.0',
            id: msg.id,
            result: {
              tools: MCP_TOOLS_DEFINITION,
            },
          };
        }

        case 'tools/call': {
          const toolName = String(msg.params?.name ?? '');
          const args = (msg.params?.arguments ?? {}) as Record<string, unknown>;
          const toolResult = await this.#callTool(toolName, args);
          return {
            jsonrpc: '2.0',
            id: msg.id,
            result: toolResult,
          };
        }

        default: {
          return {
            jsonrpc: '2.0',
            id: msg.id,
            error: {
              code: -32601,
              message: `Method not found: ${msg.method}`,
            },
          };
        }
      }
    } catch (err) {
      const safeMessage =
        err instanceof Error
          ? this.#broker.scrubText(err.message, 'mcp_error').scrubbedText
          : 'Internal MCP tool error';
      return {
        jsonrpc: '2.0',
        id: msg.id,
        error: {
          code: -32000,
          message: safeMessage,
        },
      };
    }
  }

  async #callTool(
    name: string,
    args: Record<string, unknown>
  ): Promise<{ content: { type: 'text'; text: string }[]; isError?: boolean }> {
    try {
      if (name === 'pw1_list_handles') {
        const handles = this.#vault.listSecrets();
        return {
          content: [{ type: 'text', text: JSON.stringify({ handles }, null, 2) }],
        };
      }

      if (name === 'pw1_http_request') {
        const req: ProxyHttpRequest = {
          url: String(args.url ?? ''),
          method: typeof args.method === 'string' ? args.method : undefined,
          headers: (args.headers as Record<string, string> | undefined) ?? undefined,
          query: (args.query as Record<string, string> | undefined) ?? undefined,
          body: typeof args.body === 'string' ? args.body : undefined,
          auth: (args.auth as HttpAuthBinding | undefined) ?? undefined,
          agentId: typeof args.agentId === 'string' ? args.agentId : undefined,
          grantId: typeof args.grantId === 'string' ? args.grantId : undefined,
        };
        const res = await this.#broker.executeHttp(req);
        return {
          content: [{ type: 'text', text: JSON.stringify(res, null, 2) }],
        };
      }

      if (name === 'pw1_exec_command') {
        const req: ProxyExecRequest = {
          command: String(args.command ?? ''),
          args: Array.isArray(args.args) ? args.args.map(String) : undefined,
          env: (args.env as Record<string, string> | undefined) ?? undefined,
          secretEnv: (args.secretEnv as Record<string, string> | undefined) ?? undefined,
          cwd: typeof args.cwd === 'string' ? args.cwd : undefined,
          timeoutMs: typeof args.timeoutMs === 'number' ? args.timeoutMs : undefined,
          agentId: typeof args.agentId === 'string' ? args.agentId : undefined,
          grantId: typeof args.grantId === 'string' ? args.grantId : undefined,
        };
        const res = await this.#broker.executeCommand(req);
        return {
          content: [{ type: 'text', text: JSON.stringify(res, null, 2) }],
        };
      }

      if (name === 'pw1_scrub_output') {
        const text = String(args.text ?? '');
        const res = this.#broker.scrubText(text, 'mcp_scrub_tool');
        return {
          content: [{ type: 'text', text: JSON.stringify(res, null, 2) }],
        };
      }

      if (name === 'pw1_audit_verify') {
        const limit = typeof args.limit === 'number' ? args.limit : 20;
        const verification = this.#vault.verifyAuditChain();
        const entries = this.#vault.listAuditLogs(limit);
        return {
          content: [{ type: 'text', text: JSON.stringify({ verification, entries }, null, 2) }],
        };
      }

      throw new PasswordOneError(
        'INVALID_INPUT',
        `Unknown tool "${name}". Note: Password One intentionally exposes no plaintext secret-reading tool.`
      );
    } catch (err) {
      const safeErr =
        err instanceof Error
          ? this.#broker.scrubText(err.message, 'mcp_tool_error').scrubbedText
          : 'Execution error';
      const code = err instanceof PasswordOneError ? err.code : 'EXECUTION_ERROR';
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: JSON.stringify({ error: { code, message: safeErr } }),
          },
        ],
      };
    }
  }
}

export interface McpStdioOptions {
  input?: Readable;
  output?: Writable;
  vault?: PasswordOneVault;
  broker?: PasswordOneBroker;
  dataPath?: string;
  masterKey?: string;
  brokerOptions?: BrokerOptions;
}

export async function runMcpServer(options?: McpStdioOptions): Promise<{ close: () => void }> {
  const input = options?.input ?? process.stdin;
  const output = options?.output ?? process.stdout;
  const ownsVault = !options?.vault;
  const vault =
    options?.vault ??
    new PasswordOneVault({
      dbPath: options?.dataPath ?? process.env.DATA_PATH ?? join(process.cwd(), 'data', 'password-one.sqlite'),
      masterKey: options?.masterKey ?? process.env.PW1_MASTER_KEY ?? 'pw1-local-dev-master-key-change-in-prod',
    });
  const broker = options?.broker ?? new PasswordOneBroker(vault, options?.brokerOptions);
  const dispatcher = new PasswordOneMcpDispatcher(vault, broker);

  const rl = createInterface({ input, crlfDelay: Infinity });

  const loopPromise = (async () => {
    for await (const rawLine of rl) {
      const line = rawLine.trim();
      if (!line || line.toLowerCase().startsWith('content-length:')) continue;
      let parsed: JsonRpcRequest;
      try {
        parsed = JSON.parse(line) as JsonRpcRequest;
      } catch {
        const parseErr: JsonRpcResponse = {
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Parse error' },
        };
        output.write(`${JSON.stringify(parseErr)}\n`);
        continue;
      }
      const response = await dispatcher.handleMessage(parsed);
      if (response) {
        output.write(`${JSON.stringify(response)}\n`);
      }
    }
  })();

  void loopPromise;

  return {
    close: () => {
      rl.close();
      if (ownsVault) {
        vault.close();
      }
    },
  };
}
