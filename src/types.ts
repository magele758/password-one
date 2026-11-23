// Core domain types, policies, audit structures, and error classes for Password One

export const SERVICE_VERSION = '0.1.0';
export const DEFAULT_DEV_MASTER_KEY = 'pw1-local-dev-master-key-change-in-prod';

export type AllowedToolKind = 'http' | 'exec';

export type CrossOriginRedirectMode = 'block' | 'strip';

export interface SecretPolicyInput {
  /** Exact hostnames (e.g. "api.stripe.com") or subdomain wildcards (e.g. "*.stripe.com") */
  allowedHosts?: string[];
  /** Allowed execution gateways: "http" and/or "exec" */
  allowedTools?: AllowedToolKind[];
  /** Allowed binary basenames when "exec" tool is permitted (e.g. ["curl", "psql", "node"]) */
  allowedCommands?: string[];
  /** Allow plain HTTP (default false; enable only for loopback / test environments) */
  allowHttp?: boolean;
  /** Allow injecting secret into subprocess environment variables */
  allowEnvInjection?: boolean;
  /** Behavior when an upstream HTTP response attempts a cross-origin 3xx redirect */
  crossOriginRedirect?: CrossOriginRedirectMode;
  /** Maximum TTL in seconds allowed when minting a scoped grant for this secret */
  maxLeaseTtlSeconds?: number;
  /** Require an explicit scoped grantId (grant_xxx) for every broker execution */
  requireGrant?: boolean;
}

export interface SecretPolicy {
  allowedHosts: string[];
  allowedTools: AllowedToolKind[];
  allowedCommands: string[];
  allowHttp: boolean;
  allowEnvInjection: boolean;
  crossOriginRedirect: CrossOriginRedirectMode;
  maxLeaseTtlSeconds: number;
  requireGrant: boolean;
}

export interface UpsertSecretInput {
  alias: string;
  value: string;
  description?: string;
  policy: SecretPolicyInput;
}

export interface SecretMetadata {
  id: string;
  alias: string;
  handle: string;
  placeholder: string;
  description: string;
  version: number;
  policy: SecretPolicy;
  policyHash: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateGrantInput {
  alias: string;
  agentId: string;
  allowedTools?: AllowedToolKind[];
  allowedHosts?: string[];
  maxUses?: number;
  ttlSeconds?: number;
}

export interface ScopedGrant {
  grantId: string;
  alias: string;
  agentId: string;
  allowedTools: AllowedToolKind[];
  allowedHosts: string[];
  maxUses: number;
  usedCount: number;
  expiresAt: string;
  revoked: boolean;
  createdAt: string;
}

export type HttpAuthBinding =
  | { type: 'bearer'; secret: string }
  | { type: 'basic'; username: string; secret: string }
  | { type: 'header'; headerName: string; secret: string; prefix?: string }
  | { type: 'query'; paramName: string; secret: string };

export interface ProxyHttpRequest {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  query?: Record<string, string>;
  body?: string;
  auth?: HttpAuthBinding;
  agentId?: string;
  grantId?: string;
  maxRedirects?: number;
  timeoutMs?: number;
}

export interface RedirectHopRecord {
  fromUrl: string;
  toUrl: string;
  statusCode: number;
  crossOrigin: boolean;
  strippedCredentials: boolean;
}

export interface ProxyHttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  finalUrl: string;
  redirects: RedirectHopRecord[];
  redactionsCount: number;
  redactedAliases: string[];
  durationMs: number;
}

export interface ProxyExecRequest {
  command: string;
  args?: string[];
  /** Non-secret explicit environment variables */
  env?: Record<string, string>;
  /** Secret environment bindings: ENV_VAR_NAME -> "pw1://alias" or "{{pw1://alias}}" */
  secretEnv?: Record<string, string>;
  cwd?: string;
  timeoutMs?: number;
  agentId?: string;
  grantId?: string;
}

export interface ProxyExecResponse {
  exitCode: number;
  stdout: string;
  stderr: string;
  redactionsCount: number;
  redactedAliases: string[];
  durationMs: number;
}

export type EncodingKind =
  | 'raw'
  | 'url_encoded'
  | 'base64_std'
  | 'base64_url'
  | 'json_escaped'
  | 'basic_auth'
  | 'heuristic_pattern';

export interface ScrubMatchSummary {
  label: string;
  encoding: EncodingKind;
  count: number;
}

export interface ScrubResult {
  scrubbedText: string;
  redactionsCount: number;
  redactedAliases: string[];
  matches: ScrubMatchSummary[];
}

export type AuditDecision = 'ALLOW' | 'DENY' | 'SCRUB' | 'MUTATE';

export interface AuditEntry {
  seq: number;
  eventId: string;
  timestamp: string;
  action: string;
  alias: string | null;
  agentId: string | null;
  grantId: string | null;
  toolName: string | null;
  target: string | null;
  decision: AuditDecision;
  reason: string;
  redactionsCount: number;
  metadata: Record<string, unknown>;
  prevHash: string;
  entryHash: string;
}

export interface AuditVerificationResult {
  valid: boolean;
  entriesChecked: number;
  headHash: string;
  brokenAtSeq?: number;
  reason?: string;
}

export type ErrorCode =
  | 'INVALID_INPUT'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'SECRET_NOT_FOUND'
  | 'POLICY_VIOLATION'
  | 'POLICY_TAMPER_DETECTED'
  | 'LEASE_INVALID'
  | 'UPSTREAM_ERROR';

export class PasswordOneError extends Error {
  readonly code: ErrorCode;
  readonly statusCode: number;

  constructor(code: ErrorCode, message: string, statusCode = 400) {
    super(message);
    this.name = 'PasswordOneError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

export class SecretNotFoundError extends PasswordOneError {
  constructor(alias: string) {
    super('SECRET_NOT_FOUND', `Secret handle not found for alias "${alias}"`, 404);
    this.name = 'SecretNotFoundError';
  }
}

export class PolicyViolationError extends PasswordOneError {
  constructor(message: string) {
    super('POLICY_VIOLATION', message, 403);
    this.name = 'PolicyViolationError';
  }
}

export class PolicyTamperError extends PasswordOneError {
  constructor(alias: string) {
    super(
      'POLICY_TAMPER_DETECTED',
      `Cryptographic AAD verification failed for secret "${alias}": stored policy or ciphertext was tampered with`,
      409
    );
    this.name = 'PolicyTamperError';
  }
}

export class LeaseError extends PasswordOneError {
  constructor(message: string) {
    super('LEASE_INVALID', message, 403);
    this.name = 'LeaseError';
  }
}
