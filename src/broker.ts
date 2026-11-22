import { execFile } from 'node:child_process';
import { request as httpRequest, type IncomingMessage, type OutgoingHttpHeaders } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { basename } from 'node:path';
import { performance } from 'node:perf_hooks';
import { OutputScrubber } from './scrubber.ts';
import {
  LeaseError,
  PasswordOneError,
  PolicyViolationError,
  type ProxyExecRequest,
  type ProxyExecResponse,
  type ProxyHttpRequest,
  type ProxyHttpResponse,
  type RedirectHopRecord,
  type ScrubResult,
} from './types.ts';
import { hostMatchesAny, PasswordOneVault, type ResolvedSecretRecord } from './vault.ts';

const PLACEHOLDER_REGEX = /\{\{pw1:\/\/([a-zA-Z0-9][a-zA-Z0-9._/-]{0,126}[a-zA-Z0-9])\}\}/g;
const DIRECT_HANDLE_REGEX = /pw1:\/\/([a-zA-Z0-9][a-zA-Z0-9._/-]{0,126}[a-zA-Z0-9])/g;

const FORBIDDEN_SNIFF_COMMANDS = new Set([
  'env',
  'printenv',
  'set',
  'export',
  'declare',
  'typeset',
]);

const FORBIDDEN_INJECT_ENV_KEYS = new Set([
  'LD_PRELOAD',
  'LD_LIBRARY_PATH',
  'DYLD_INSERT_LIBRARIES',
  'DYLD_LIBRARY_PATH',
  'NODE_OPTIONS',
  'PYTHONSTARTUP',
  'BASH_ENV',
]);

const SAFE_OS_ENV_KEYS = ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'TZ', 'TERM', 'SystemRoot'];

export interface HostResolveOverride {
  address: string;
  port?: number;
}

export interface BrokerOptions {
  /**
   * Optional DNS/socket routing map (similar to `curl --resolve host:port:addr`)
   * for isolated integration testing without mutating /etc/hosts.
   * Policy and origin checks always run against the logical URL hostname.
   */
  resolveOverrides?: Record<string, HostResolveOverride>;
}

function extractSecretAliasesFromText(text: string): string[] {
  const found = new Set<string>();
  for (const m of text.matchAll(PLACEHOLDER_REGEX)) {
    if (m[1]) found.add(m[1]);
  }
  for (const m of text.matchAll(DIRECT_HANDLE_REGEX)) {
    if (m[1]) found.add(m[1]);
  }
  return Array.from(found);
}

function replaceHandlesInText(text: string, resolved: ReadonlyMap<string, string>): string {
  let out = text.replace(PLACEHOLDER_REGEX, (full, alias: string) => {
    const val = resolved.get(alias);
    return val !== undefined ? val : full;
  });
  out = out.replace(DIRECT_HANDLE_REGEX, (full, alias: string) => {
    const val = resolved.get(alias);
    return val !== undefined ? val : full;
  });
  return out;
}

interface RawHttpResult {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

export class PasswordOneBroker {
  readonly #vault: PasswordOneVault;
  readonly #scrubber: OutputScrubber;
  readonly #resolveOverrides: Record<string, HostResolveOverride>;

  constructor(vault: PasswordOneVault, options?: BrokerOptions) {
    this.#vault = vault;
    this.#scrubber = new OutputScrubber();
    this.#resolveOverrides = {};
    if (options?.resolveOverrides) {
      for (const [k, v] of Object.entries(options.resolveOverrides)) {
        this.#resolveOverrides[k.toLowerCase()] = v;
      }
    }
  }

  scrubText(text: string, source = 'manual_scrub'): ScrubResult {
    const secrets = this.#vault.collectActiveSecretsForScrubber();
    const res = this.#scrubber.scrub(text, secrets);
    if (res.redactionsCount > 0) {
      this.#vault.appendAudit({
        action: 'OUTPUT_SCRUB',
        alias: res.redactedAliases[0] ?? null,
        toolName: source,
        decision: 'SCRUB',
        reason: `Scrubbed ${res.redactionsCount} sensitive token occurrence(s)`,
        redactionsCount: res.redactionsCount,
        metadata: {
          redactedAliases: res.redactedAliases,
          matches: res.matches,
        },
      });
    }
    return res;
  }

  async executeHttp(req: ProxyHttpRequest): Promise<ProxyHttpResponse> {
    const t0 = performance.now();
    if (!req.url || typeof req.url !== 'string') {
      throw new PasswordOneError('INVALID_INPUT', 'HTTP proxy request requires a valid url string');
    }

    // Collect all referenced secret handles across url, query, headers, body, and structured auth
    const referencedAliases = new Set<string>();
    for (const a of extractSecretAliasesFromText(req.url)) referencedAliases.add(a);
    for (const v of Object.values(req.query ?? {})) {
      for (const a of extractSecretAliasesFromText(v)) referencedAliases.add(a);
    }
    for (const [hk, hv] of Object.entries(req.headers ?? {})) {
      if (extractSecretAliasesFromText(hk).length > 0) {
        throw new PolicyViolationError('Secret handles cannot be placed inside HTTP header names');
      }
      for (const a of extractSecretAliasesFromText(hv)) referencedAliases.add(a);
    }
    if (req.body) {
      for (const a of extractSecretAliasesFromText(req.body)) referencedAliases.add(a);
    }
    if (req.auth) {
      for (const a of extractSecretAliasesFromText(req.auth.secret)) referencedAliases.add(a);
    }

    // Parse initial URL before substitution to ensure hostname/protocol do not carry secret handles
    let preCheckUrl: URL;
    try {
      preCheckUrl = new URL(req.url);
    } catch {
      throw new PasswordOneError('INVALID_INPUT', `Malformed target URL: "${req.url}"`);
    }

    if (preCheckUrl.protocol !== 'https:' && preCheckUrl.protocol !== 'http:') {
      this.#vault.appendAudit({
        action: 'HTTP_DENY',
        agentId: req.agentId ?? null,
        grantId: req.grantId ?? null,
        toolName: 'http',
        target: req.url,
        decision: 'DENY',
        reason: `Disallowed URL protocol "${preCheckUrl.protocol}"`,
      });
      throw new PolicyViolationError(`Unsupported URL protocol "${preCheckUrl.protocol}"; only https: (or policy-enabled http:) is permitted`);
    }

    if (preCheckUrl.username || preCheckUrl.password) {
      this.#vault.appendAudit({
        action: 'HTTP_DENY',
        agentId: req.agentId ?? null,
        grantId: req.grantId ?? null,
        toolName: 'http',
        target: `${preCheckUrl.origin}${preCheckUrl.pathname}`,
        decision: 'DENY',
        reason: 'Embedded URL userinfo authority trick rejected',
      });
      throw new PolicyViolationError('URLs containing embedded username/password authority components are forbidden');
    }

    if (
      extractSecretAliasesFromText(preCheckUrl.hostname).length > 0 ||
      req.url.split('?')[0]?.split('/').slice(0, 3).join('/').includes('pw1://')
    ) {
      this.#vault.appendAudit({
        action: 'HTTP_DENY',
        agentId: req.agentId ?? null,
        toolName: 'http',
        target: preCheckUrl.hostname,
        decision: 'DENY',
        reason: 'Secret handle forbidden inside URL authority/hostname (DNS exfiltration guard)',
      });
      throw new PolicyViolationError('Secret handles are forbidden inside URL hostname/authority');
    }

    // Reject explicit Host header spoofing
    for (const [hk, hv] of Object.entries(req.headers ?? {})) {
      if (hk.toLowerCase() === 'host') {
        const normalizedHeaderHost = hv.trim().toLowerCase();
        if (
          normalizedHeaderHost !== preCheckUrl.host.toLowerCase() &&
          normalizedHeaderHost !== preCheckUrl.hostname.toLowerCase()
        ) {
          this.#vault.appendAudit({
            action: 'HTTP_DENY',
            agentId: req.agentId ?? null,
            toolName: 'http',
            target: preCheckUrl.href,
            decision: 'DENY',
            reason: `Host header spoofing blocked ("${hv}" != "${preCheckUrl.host}")`,
          });
          throw new PolicyViolationError(`Host header "${hv}" does not match target URL host "${preCheckUrl.host}"`);
        }
      }
    }

    // Resolve and verify policy + AAD + lease for every referenced secret
    const resolvedSecrets = new Map<string, ResolvedSecretRecord>();
    const plaintextMap = new Map<string, string>();

    for (const alias of referencedAliases) {
      const record = this.#vault.resolveSecretForBroker(alias);
      const { policy } = record.metadata;

      if (!policy.allowedTools.includes('http')) {
        this.#vault.appendAudit({
          action: 'HTTP_DENY',
          alias,
          agentId: req.agentId ?? null,
          grantId: req.grantId ?? null,
          toolName: 'http',
          target: preCheckUrl.origin,
          decision: 'DENY',
          reason: `Secret "${alias}" policy forbids "http" gateway`,
        });
        throw new PolicyViolationError(`Secret "${alias}" does not permit "http" execution`);
      }

      if (preCheckUrl.protocol === 'http:' && !policy.allowHttp) {
        this.#vault.appendAudit({
          action: 'HTTP_DENY',
          alias,
          agentId: req.agentId ?? null,
          grantId: req.grantId ?? null,
          toolName: 'http',
          target: preCheckUrl.origin,
          decision: 'DENY',
          reason: `Secret "${alias}" requires HTTPS; plain HTTP to "${preCheckUrl.hostname}" denied`,
        });
        throw new PolicyViolationError(`Secret "${alias}" requires HTTPS and forbids plain HTTP`);
      }

      if (!hostMatchesAny(preCheckUrl.hostname, policy.allowedHosts)) {
        this.#vault.appendAudit({
          action: 'HTTP_DENY',
          alias,
          agentId: req.agentId ?? null,
          grantId: req.grantId ?? null,
          toolName: 'http',
          target: preCheckUrl.href,
          decision: 'DENY',
          reason: `Confused-deputy/SSRF guard: host "${preCheckUrl.hostname}" is not in allowedHosts [${policy.allowedHosts.join(', ')}]`,
        });
        throw new PolicyViolationError(
          `Target host "${preCheckUrl.hostname}" is not authorized to receive secret "${alias}" (allowed: ${policy.allowedHosts.join(', ')})`
        );
      }

      if (policy.requireGrant && !req.grantId) {
        this.#vault.appendAudit({
          action: 'HTTP_DENY',
          alias,
          agentId: req.agentId ?? null,
          toolName: 'http',
          target: preCheckUrl.href,
          decision: 'DENY',
          reason: `Secret "${alias}" requires an active scoped grantId`,
        });
        throw new LeaseError(`Secret "${alias}" requires a scoped grantId`);
      }

      if (req.grantId) {
        try {
          this.#vault.consumeGrant({
            grantId: req.grantId,
            alias,
            agentId: req.agentId,
            tool: 'http',
            targetHost: preCheckUrl.hostname,
          });
        } catch (err) {
          this.#vault.appendAudit({
            action: 'HTTP_DENY',
            alias,
            agentId: req.agentId ?? null,
            grantId: req.grantId,
            toolName: 'http',
            target: preCheckUrl.href,
            decision: 'DENY',
            reason: err instanceof Error ? err.message : 'Grant validation failed',
          });
          throw err;
        }
      }

      resolvedSecrets.set(alias, record);
      plaintextMap.set(alias, record.plaintext);
    }

    // Build initial request with JIT secret injection
    const targetUrl = new URL(replaceHandlesInText(req.url, plaintextMap));
    const secretQueryKeys = new Set<string>();
    for (const [qk, qv] of Object.entries(req.query ?? {})) {
      if (extractSecretAliasesFromText(qv).length > 0) {
        secretQueryKeys.add(qk);
      }
      targetUrl.searchParams.set(qk, replaceHandlesInText(qv, plaintextMap));
    }

    const injectedHeaders: Record<string, string> = {};
    const secretHeaderNames = new Set<string>();

    for (const [hk, hv] of Object.entries(req.headers ?? {})) {
      if (extractSecretAliasesFromText(hv).length > 0) {
        secretHeaderNames.add(hk.toLowerCase());
      }
      injectedHeaders[hk] = replaceHandlesInText(hv, plaintextMap);
    }

    if (req.auth) {
      const resolvedAuthSecret = replaceHandlesInText(req.auth.secret, plaintextMap);
      if (req.auth.type === 'bearer') {
        injectedHeaders['Authorization'] = `Bearer ${resolvedAuthSecret}`;
        secretHeaderNames.add('authorization');
      } else if (req.auth.type === 'basic') {
        const b64 = Buffer.from(`${req.auth.username}:${resolvedAuthSecret}`, 'utf8').toString('base64');
        injectedHeaders['Authorization'] = `Basic ${b64}`;
        secretHeaderNames.add('authorization');
      } else if (req.auth.type === 'header') {
        const prefix = req.auth.prefix ?? '';
        injectedHeaders[req.auth.headerName] = `${prefix}${resolvedAuthSecret}`;
        secretHeaderNames.add(req.auth.headerName.toLowerCase());
      } else if (req.auth.type === 'query') {
        targetUrl.searchParams.set(req.auth.paramName, resolvedAuthSecret);
        secretQueryKeys.add(req.auth.paramName);
      }
    }

    const bodyHadSecrets = req.body ? extractSecretAliasesFromText(req.body).length > 0 : false;
    let currentBody: string | undefined = req.body ? replaceHandlesInText(req.body, plaintextMap) : undefined;
    let currentMethod = (req.method ?? 'GET').toUpperCase();
    let currentUrl = targetUrl;
    let currentHeaders = { ...injectedHeaders };

    const maxRedirects = Math.max(0, Math.min(10, req.maxRedirects ?? 5));
    const timeoutMs = req.timeoutMs ?? 10000;
    const redirects: RedirectHopRecord[] = [];

    try {
      let hop = 0;
      let rawRes: RawHttpResult;

      while (true) {
        rawRes = await this.#performSingleHttpHop({
          url: currentUrl,
          method: currentMethod,
          headers: currentHeaders,
          body: currentBody,
          timeoutMs,
        });

        const isRedirect =
          (rawRes.statusCode === 301 ||
            rawRes.statusCode === 302 ||
            rawRes.statusCode === 303 ||
            rawRes.statusCode === 307 ||
            rawRes.statusCode === 308) &&
          typeof rawRes.headers['location'] === 'string' &&
          rawRes.headers['location'].length > 0;

        if (!isRedirect || hop >= maxRedirects) {
          break;
        }

        const locationHeader = rawRes.headers['location']!;
        let nextUrl: URL;
        try {
          nextUrl = new URL(locationHeader, currentUrl);
        } catch {
          throw new PolicyViolationError(`Upstream returned malformed redirect Location "${locationHeader}"`);
        }

        if (nextUrl.protocol !== 'https:' && nextUrl.protocol !== 'http:') {
          throw new PolicyViolationError(`Redirect to disallowed protocol "${nextUrl.protocol}" blocked`);
        }
        if (nextUrl.username || nextUrl.password) {
          throw new PolicyViolationError('Redirect Location with embedded userinfo blocked');
        }

        const crossOrigin = nextUrl.origin !== currentUrl.origin;
        let strippedCredentials = false;

        if (crossOrigin && resolvedSecrets.size > 0) {
          for (const [alias, rec] of resolvedSecrets.entries()) {
            const hostAllowed = hostMatchesAny(nextUrl.hostname, rec.metadata.policy.allowedHosts);
            if (!hostAllowed && rec.metadata.policy.crossOriginRedirect === 'block') {
              this.#vault.appendAudit({
                action: 'REDIRECT_BLOCK',
                alias,
                agentId: req.agentId ?? null,
                grantId: req.grantId ?? null,
                toolName: 'http',
                target: `${currentUrl.origin} -> ${nextUrl.origin}`,
                decision: 'DENY',
                reason: `Blocked cross-origin ${rawRes.statusCode} redirect to unauthorized host "${nextUrl.hostname}"`,
              });
              throw new PolicyViolationError(
                `Cross-origin ${rawRes.statusCode} redirect from "${currentUrl.hostname}" to unauthorized host "${nextUrl.hostname}" blocked`
              );
            }
            if (nextUrl.protocol === 'http:' && !rec.metadata.policy.allowHttp && hostAllowed) {
              throw new PolicyViolationError(`HTTPS downgrade redirect to "${nextUrl.href}" blocked`);
            }
          }

          // Even when crossOriginRedirect === 'strip' (or between distinct allowlisted origins),
          // NEVER forward Authorization, Cookie, secret headers, secret query params, or secret bodies across origins!
          const sanitizedHeaders: Record<string, string> = {};
          for (const [hk, hv] of Object.entries(currentHeaders)) {
            const lower = hk.toLowerCase();
            if (
              lower === 'authorization' ||
              lower === 'proxy-authorization' ||
              lower === 'cookie' ||
              lower === 'host' ||
              secretHeaderNames.has(lower)
            ) {
              strippedCredentials = true;
              continue;
            }
            sanitizedHeaders[hk] = hv;
          }
          currentHeaders = sanitizedHeaders;

          for (const sqk of secretQueryKeys) {
            if (nextUrl.searchParams.has(sqk)) {
              nextUrl.searchParams.delete(sqk);
              strippedCredentials = true;
            }
          }

          if (bodyHadSecrets) {
            currentBody = undefined;
            strippedCredentials = true;
          }

          this.#vault.appendAudit({
            action: 'REDIRECT_STRIP',
            alias: Array.from(resolvedSecrets.keys())[0] ?? null,
            agentId: req.agentId ?? null,
            grantId: req.grantId ?? null,
            toolName: 'http',
            target: `${currentUrl.origin} -> ${nextUrl.origin}`,
            decision: 'ALLOW',
            reason: `Stripped all credentials before following cross-origin ${rawRes.statusCode} redirect`,
          });
        }

        if (rawRes.statusCode === 301 || rawRes.statusCode === 302 || rawRes.statusCode === 303) {
          if (currentMethod !== 'GET' && currentMethod !== 'HEAD') {
            currentMethod = 'GET';
            currentBody = undefined;
          }
        }

        redirects.push({
          fromUrl: `${currentUrl.origin}${currentUrl.pathname}`,
          toUrl: `${nextUrl.origin}${nextUrl.pathname}`,
          statusCode: rawRes.statusCode,
          crossOrigin,
          strippedCredentials,
        });

        currentUrl = nextUrl;
        hop += 1;
      }

      // Scrub response headers, finalUrl, and body before returning to caller / LLM context
      const activeSecrets = this.#vault.collectActiveSecretsForScrubber();
      const bodyScrub = this.#scrubber.scrub(rawRes.body, activeSecrets);
      const headerScrub = this.#scrubber.scrubHeaders(rawRes.headers, activeSecrets);
      const urlScrub = this.#scrubber.scrub(currentUrl.href, activeSecrets);

      const totalRedactions =
        bodyScrub.redactionsCount + headerScrub.redactionsCount + urlScrub.redactionsCount;
      const redactedAliases = Array.from(
        new Set([...bodyScrub.redactedAliases, ...headerScrub.redactedAliases, ...urlScrub.redactedAliases])
      ).sort();

      const primaryAlias = Array.from(resolvedSecrets.keys())[0] ?? null;
      this.#vault.appendAudit({
        action: 'HTTP_ALLOW',
        alias: primaryAlias,
        agentId: req.agentId ?? null,
        grantId: req.grantId ?? null,
        toolName: 'http',
        target: `${preCheckUrl.origin}${preCheckUrl.pathname}`,
        decision: 'ALLOW',
        reason: `Completed ${req.method ?? 'GET'} -> HTTP ${rawRes.statusCode}`,
        redactionsCount: totalRedactions,
        metadata: {
          referencedAliases: Array.from(resolvedSecrets.keys()),
          statusCode: rawRes.statusCode,
          redirectsCount: redirects.length,
          redactedAliases,
        },
      });

      if (totalRedactions > 0) {
        this.#vault.appendAudit({
          action: 'OUTPUT_SCRUB',
          alias: redactedAliases[0] ?? primaryAlias,
          agentId: req.agentId ?? null,
          toolName: 'http',
          target: `${preCheckUrl.origin}${preCheckUrl.pathname}`,
          decision: 'SCRUB',
          reason: `Redacted ${totalRedactions} echoed credential artifact(s) from HTTP response`,
          redactionsCount: totalRedactions,
          metadata: {
            redactedAliases,
            bodyMatches: bodyScrub.matches,
          },
        });
      }

      return {
        status: rawRes.statusCode,
        headers: headerScrub.headers,
        body: bodyScrub.scrubbedText,
        finalUrl: urlScrub.scrubbedText,
        redirects,
        redactionsCount: totalRedactions,
        redactedAliases,
        durationMs: Number((performance.now() - t0).toFixed(3)),
      };
    } finally {
      plaintextMap.clear();
    }
  }

  #performSingleHttpHop(params: {
    url: URL;
    method: string;
    headers: Record<string, string>;
    body?: string;
    timeoutMs: number;
  }): Promise<RawHttpResult> {
    return new Promise((resolve, reject) => {
      const logicalHostname = params.url.hostname.toLowerCase();
      const override = this.#resolveOverrides[logicalHostname];

      const connectHostname = override ? override.address : params.url.hostname;
      const connectPort = override?.port
        ? override.port
        : params.url.port
          ? Number(params.url.port)
          : params.url.protocol === 'https:'
            ? 443
            : 80;

      const outgoingHeaders: OutgoingHttpHeaders = { ...params.headers };
      const hasHost = Object.keys(outgoingHeaders).some((k) => k.toLowerCase() === 'host');
      if (!hasHost) {
        outgoingHeaders['Host'] = params.url.host;
      }
      if (params.body !== undefined) {
        const hasLen = Object.keys(outgoingHeaders).some((k) => k.toLowerCase() === 'content-length');
        if (!hasLen) {
          outgoingHeaders['Content-Length'] = Buffer.byteLength(params.body, 'utf8');
        }
      }

      const reqFn = params.url.protocol === 'https:' ? httpsRequest : httpRequest;
      const clientReq = reqFn(
        {
          protocol: params.url.protocol,
          hostname: connectHostname,
          port: connectPort,
          method: params.method,
          path: `${params.url.pathname}${params.url.search}`,
          headers: outgoingHeaders,
          timeout: params.timeoutMs,
        },
        (res: IncomingMessage) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer | string) => {
            chunks.push(typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk);
          });
          res.on('end', () => {
            const flatHeaders: Record<string, string> = {};
            for (const [k, v] of Object.entries(res.headers)) {
              if (Array.isArray(v)) {
                flatHeaders[k.toLowerCase()] = v.join(', ');
              } else if (typeof v === 'string') {
                flatHeaders[k.toLowerCase()] = v;
              }
            }
            resolve({
              statusCode: res.statusCode ?? 0,
              headers: flatHeaders,
              body: Buffer.concat(chunks).toString('utf8'),
            });
          });
          res.on('error', (err: Error) => {
            reject(new PasswordOneError('UPSTREAM_ERROR', `Upstream response error: ${err.message}`, 502));
          });
        }
      );

      clientReq.setTimeout(params.timeoutMs, () => {
        clientReq.destroy(new Error(`HTTP request timed out after ${params.timeoutMs}ms`));
      });

      clientReq.on('error', (err: Error) => {
        // Scrub any error message before bubbling up
        const safeMsg = this.#scrubber.scrub(err.message, this.#vault.collectActiveSecretsForScrubber()).scrubbedText;
        reject(new PasswordOneError('UPSTREAM_ERROR', `Upstream connection failed: ${safeMsg}`, 502));
      });

      if (params.body !== undefined) {
        clientReq.write(params.body, 'utf8');
      }
      clientReq.end();
    });
  }

  async executeCommand(req: ProxyExecRequest): Promise<ProxyExecResponse> {
    const t0 = performance.now();
    const rawCommand = (req.command ?? '').trim();
    if (!rawCommand) {
      throw new PasswordOneError('INVALID_INPUT', 'Command binary name or path is required');
    }

    const cmdBase = basename(rawCommand);
    if (FORBIDDEN_SNIFF_COMMANDS.has(cmdBase.toLowerCase())) {
      this.#vault.appendAudit({
        action: 'EXEC_DENY',
        agentId: req.agentId ?? null,
        grantId: req.grantId ?? null,
        toolName: 'exec',
        target: rawCommand,
        decision: 'DENY',
        reason: `Blocked environment harvesting command "${cmdBase}"`,
      });
      throw new PolicyViolationError(
        `Environment inspection command "${cmdBase}" is forbidden by Password One clean-room policy`
      );
    }

    if (extractSecretAliasesFromText(rawCommand).length > 0) {
      throw new PolicyViolationError('Secret handles cannot be used as the executable binary path');
    }

    const args = req.args ?? [];
    const envAliases = new Set<string>();
    const argAliases = new Set<string>();

    for (const a of args) {
      for (const alias of extractSecretAliasesFromText(a)) {
        argAliases.add(alias);
      }
    }

    for (const [envKey, envVal] of Object.entries(req.secretEnv ?? {})) {
      if (FORBIDDEN_INJECT_ENV_KEYS.has(envKey.toUpperCase())) {
        throw new PolicyViolationError(`Dynamic linker / runtime hijack variable "${envKey}" is forbidden`);
      }
      const extracted = extractSecretAliasesFromText(envVal);
      if (extracted.length === 0) {
        // Support bare alias string in secretEnv if passed without pw1:// prefix
        envAliases.add(envVal.trim());
      } else {
        for (const alias of extracted) envAliases.add(alias);
      }
    }

    for (const envKey of Object.keys(req.env ?? {})) {
      if (FORBIDDEN_INJECT_ENV_KEYS.has(envKey.toUpperCase())) {
        throw new PolicyViolationError(`Dynamic linker / runtime hijack variable "${envKey}" is forbidden`);
      }
    }

    const allAliases = new Set<string>([...envAliases, ...argAliases]);
    const plaintextMap = new Map<string, string>();

    for (const alias of allAliases) {
      const record = this.#vault.resolveSecretForBroker(alias);
      const { policy } = record.metadata;

      if (!policy.allowedTools.includes('exec')) {
        this.#vault.appendAudit({
          action: 'EXEC_DENY',
          alias,
          agentId: req.agentId ?? null,
          grantId: req.grantId ?? null,
          toolName: 'exec',
          target: cmdBase,
          decision: 'DENY',
          reason: `Secret "${alias}" policy forbids "exec" subprocess gateway`,
        });
        throw new PolicyViolationError(`Secret "${alias}" does not permit "exec" subprocess execution`);
      }

      if (policy.allowedCommands.length > 0 && !policy.allowedCommands.includes(cmdBase)) {
        this.#vault.appendAudit({
          action: 'EXEC_DENY',
          alias,
          agentId: req.agentId ?? null,
          grantId: req.grantId ?? null,
          toolName: 'exec',
          target: cmdBase,
          decision: 'DENY',
          reason: `Command "${cmdBase}" is not in allowedCommands [${policy.allowedCommands.join(', ')}]`,
        });
        throw new PolicyViolationError(
          `Command "${cmdBase}" is not authorized to access secret "${alias}" (allowed: ${policy.allowedCommands.join(', ')})`
        );
      }

      if (envAliases.has(alias) && !policy.allowEnvInjection) {
        this.#vault.appendAudit({
          action: 'EXEC_DENY',
          alias,
          agentId: req.agentId ?? null,
          grantId: req.grantId ?? null,
          toolName: 'exec',
          target: cmdBase,
          decision: 'DENY',
          reason: `Secret "${alias}" forbids environment variable injection (allowEnvInjection=false)`,
        });
        throw new PolicyViolationError(`Secret "${alias}" policy forbids environment variable injection`);
      }

      if (policy.requireGrant && !req.grantId) {
        this.#vault.appendAudit({
          action: 'EXEC_DENY',
          alias,
          agentId: req.agentId ?? null,
          toolName: 'exec',
          target: cmdBase,
          decision: 'DENY',
          reason: `Secret "${alias}" requires an active scoped grantId`,
        });
        throw new LeaseError(`Secret "${alias}" requires a scoped grantId`);
      }

      if (req.grantId) {
        try {
          this.#vault.consumeGrant({
            grantId: req.grantId,
            alias,
            agentId: req.agentId,
            tool: 'exec',
          });
        } catch (err) {
          this.#vault.appendAudit({
            action: 'EXEC_DENY',
            alias,
            agentId: req.agentId ?? null,
            grantId: req.grantId,
            toolName: 'exec',
            target: cmdBase,
            decision: 'DENY',
            reason: err instanceof Error ? err.message : 'Grant validation failed',
          });
          throw err;
        }
      }

      plaintextMap.set(alias, record.plaintext);
    }

    // Construct clean-room minimal environment (never inherit ambient host secrets!)
    const sterileEnv: Record<string, string> = {};
    for (const k of SAFE_OS_ENV_KEYS) {
      const val = process.env[k];
      if (val !== undefined) sterileEnv[k] = val;
    }
    for (const [k, v] of Object.entries(req.env ?? {})) {
      sterileEnv[k] = replaceHandlesInText(v, plaintextMap);
    }
    for (const [k, rawRef] of Object.entries(req.secretEnv ?? {})) {
      const extracted = extractSecretAliasesFromText(rawRef);
      if (extracted.length === 0) {
        const direct = plaintextMap.get(rawRef.trim());
        if (direct !== undefined) sterileEnv[k] = direct;
      } else {
        sterileEnv[k] = replaceHandlesInText(rawRef, plaintextMap);
      }
    }

    const resolvedArgs = args.map((a) => replaceHandlesInText(a, plaintextMap));
    const timeoutMs = req.timeoutMs ?? 10000;

    try {
      const rawExec = await new Promise<{ exitCode: number; stdout: string; stderr: string }>((resolve) => {
        execFile(
          rawCommand,
          resolvedArgs,
          {
            cwd: req.cwd,
            env: sterileEnv,
            timeout: timeoutMs,
            maxBuffer: 4 * 1024 * 1024,
            shell: false,
          },
          (error, stdout, stderr) => {
            if (!error) {
              resolve({ exitCode: 0, stdout, stderr });
              return;
            }
            const exitCode = typeof error.code === 'number' ? error.code : 1;
            const extraErr = stderr || (error.killed ? `Process killed after timeout (${timeoutMs}ms)` : error.message);
            resolve({
              exitCode,
              stdout: stdout ?? '',
              stderr: extraErr,
            });
          }
        );
      });

      // Bidirectional multi-encoding scrub across both stdout and stderr
      const activeSecrets = this.#vault.collectActiveSecretsForScrubber();
      const stdoutScrub = this.#scrubber.scrub(rawExec.stdout, activeSecrets);
      const stderrScrub = this.#scrubber.scrub(rawExec.stderr, activeSecrets);
      const totalRedactions = stdoutScrub.redactionsCount + stderrScrub.redactionsCount;
      const redactedAliases = Array.from(
        new Set([...stdoutScrub.redactedAliases, ...stderrScrub.redactedAliases])
      ).sort();

      const primaryAlias = Array.from(allAliases)[0] ?? null;
      this.#vault.appendAudit({
        action: 'EXEC_ALLOW',
        alias: primaryAlias,
        agentId: req.agentId ?? null,
        grantId: req.grantId ?? null,
        toolName: 'exec',
        target: cmdBase,
        decision: 'ALLOW',
        reason: `Executed "${cmdBase}" (exitCode=${rawExec.exitCode})`,
        redactionsCount: totalRedactions,
        metadata: {
          referencedAliases: Array.from(allAliases),
          exitCode: rawExec.exitCode,
          redactedAliases,
        },
      });

      if (totalRedactions > 0) {
        this.#vault.appendAudit({
          action: 'OUTPUT_SCRUB',
          alias: redactedAliases[0] ?? primaryAlias,
          agentId: req.agentId ?? null,
          toolName: 'exec',
          target: cmdBase,
          decision: 'SCRUB',
          reason: `Redacted ${totalRedactions} credential artifact(s) from subprocess stdout/stderr`,
          redactionsCount: totalRedactions,
          metadata: {
            redactedAliases,
            stdoutMatches: stdoutScrub.matches,
            stderrMatches: stderrScrub.matches,
          },
        });
      }

      return {
        exitCode: rawExec.exitCode,
        stdout: stdoutScrub.scrubbedText,
        stderr: stderrScrub.scrubbedText,
        redactionsCount: totalRedactions,
        redactedAliases,
        durationMs: Number((performance.now() - t0).toFixed(3)),
      };
    } finally {
      plaintextMap.clear();
      for (const k of Object.keys(req.secretEnv ?? {})) {
        delete sterileEnv[k];
      }
    }
  }
}
