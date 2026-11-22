import { randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  canonicalJson,
  computePolicyHash,
  decryptSecretEnvelope,
  deriveKek,
  encryptSecretEnvelope,
  normalizePolicy,
  sha256Hex,
  validateAlias,
  validateHostPattern,
} from './crypto.ts';
import { OutputScrubber, type ActiveSecretMaterial } from './scrubber.ts';
import {
  LeaseError,
  PasswordOneError,
  PolicyTamperError,
  PolicyViolationError,
  SecretNotFoundError,
  type AllowedToolKind,
  type AuditDecision,
  type AuditEntry,
  type AuditVerificationResult,
  type CreateGrantInput,
  type CrossOriginRedirectMode,
  type ScopedGrant,
  type SecretMetadata,
  type SecretPolicy,
  type UpsertSecretInput,
} from './types.ts';

const GENESIS_HASH = '0'.repeat(64);
const VAULT_SENTINEL_ID = '__vault_key_verifier__';
const VAULT_SENTINEL_PLAINTEXT = 'pw1:vault:verified:v1';

export function hostMatchesPattern(hostname: string, pattern: string): boolean {
  const host = hostname.trim().toLowerCase();
  const pat = pattern.trim().toLowerCase();
  if (!host || !pat) return false;
  if (pat.startsWith('*.')) {
    const suffix = pat.slice(1); // ".example.com"
    return host.length > suffix.length && host.endsWith(suffix);
  }
  return host === pat;
}

export function hostMatchesAny(hostname: string, patterns: readonly string[]): boolean {
  for (const p of patterns) {
    if (hostMatchesPattern(hostname, p)) return true;
  }
  return false;
}

function isHostPatternSubset(childPattern: string, parentPatterns: readonly string[]): boolean {
  if (childPattern.startsWith('*.')) {
    const syntheticHost = `sub.${childPattern.slice(2)}`;
    return parentPatterns.some(
      (p) => p === childPattern || (p.startsWith('*.') && hostMatchesPattern(syntheticHost, p) && childPattern.endsWith(p.slice(1)))
    );
  }
  return hostMatchesAny(childPattern, parentPatterns);
}

export interface ResolvedSecretRecord {
  metadata: SecretMetadata;
  plaintext: string;
}

export interface VaultOptions {
  dbPath?: string;
  masterKey: string;
  scryptN?: number;
}

function computeAuditHash(params: {
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
  canonicalMetadata: string;
  prevHash: string;
}): string {
  const payload = [
    String(params.seq),
    params.eventId,
    params.timestamp,
    params.action,
    params.alias ?? '',
    params.agentId ?? '',
    params.grantId ?? '',
    params.toolName ?? '',
    params.target ?? '',
    params.decision,
    params.reason,
    String(params.redactionsCount),
    params.canonicalMetadata,
    params.prevHash,
  ].join('|');
  return sha256Hex(payload);
}

export class PasswordOneVault {
  readonly #db: DatabaseSync;
  readonly #kek: Buffer;
  readonly #scrubber: OutputScrubber;
  readonly dbPath: string;

  constructor(options: VaultOptions) {
    this.dbPath = options.dbPath ?? ':memory:';
    if (this.dbPath !== ':memory:') {
      mkdirSync(dirname(this.dbPath), { recursive: true });
    }
    this.#db = new DatabaseSync(this.dbPath);
    this.#db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;');
    this.#initSchema();
    this.#kek = this.#initOrVerifyMasterKey(options.masterKey, options.scryptN ?? 16384);
    this.#scrubber = new OutputScrubber();
  }

  #initSchema(): void {
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS vault_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS secrets (
        id TEXT PRIMARY KEY,
        alias TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL,
        version INTEGER NOT NULL,
        allowed_hosts_json TEXT NOT NULL,
        allowed_tools_json TEXT NOT NULL,
        allowed_commands_json TEXT NOT NULL,
        allow_http INTEGER NOT NULL,
        allow_env_injection INTEGER NOT NULL,
        cross_origin_redirect TEXT NOT NULL,
        max_lease_ttl_seconds INTEGER NOT NULL,
        require_grant INTEGER NOT NULL,
        policy_hash TEXT NOT NULL,
        dek_salt TEXT NOT NULL,
        iv TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        auth_tag TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS grants (
        grant_id TEXT PRIMARY KEY,
        alias TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        allowed_tools_json TEXT NOT NULL,
        allowed_hosts_json TEXT NOT NULL,
        max_uses INTEGER NOT NULL,
        used_count INTEGER NOT NULL DEFAULT 0,
        expires_at TEXT NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,
        alias TEXT,
        agent_id TEXT,
        grant_id TEXT,
        tool_name TEXT,
        target TEXT,
        decision TEXT NOT NULL,
        reason TEXT NOT NULL,
        redactions_count INTEGER NOT NULL DEFAULT 0,
        metadata_json TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL
      );
    `);
  }

  #initOrVerifyMasterKey(masterKey: string, scryptN: number): Buffer {
    const getMeta = this.#db.prepare('SELECT value FROM vault_meta WHERE key = ?');
    const setMeta = this.#db.prepare('INSERT INTO vault_meta (key, value) VALUES (?, ?)');

    const existingSaltRow = getMeta.get('vault_salt') as { value: string } | undefined;
    const existingVerifierRow = getMeta.get('key_verifier') as { value: string } | undefined;

    if (!existingSaltRow) {
      const salt = randomBytes(32);
      const kek = deriveKek(masterKey, salt, scryptN);
      const verifier = encryptSecretEnvelope({
        kek,
        secretId: VAULT_SENTINEL_ID,
        alias: VAULT_SENTINEL_ID,
        version: 1,
        policyHash: sha256Hex('vault-verifier'),
        plaintext: VAULT_SENTINEL_PLAINTEXT,
      });
      setMeta.run('vault_salt', salt.toString('base64'));
      setMeta.run('scrypt_n', String(scryptN));
      setMeta.run('key_verifier', JSON.stringify(verifier));
      return kek;
    }

    const storedNRow = getMeta.get('scrypt_n') as { value: string } | undefined;
    const effectiveN = storedNRow ? Number(storedNRow.value) : scryptN;
    const salt = Buffer.from(existingSaltRow.value, 'base64');
    const kek = deriveKek(masterKey, salt, effectiveN);

    if (existingVerifierRow) {
      try {
        const envelope = JSON.parse(existingVerifierRow.value) as {
          dekSalt: string;
          iv: string;
          ciphertext: string;
          authTag: string;
        };
        const check = decryptSecretEnvelope({
          kek,
          secretId: VAULT_SENTINEL_ID,
          alias: VAULT_SENTINEL_ID,
          version: 1,
          policyHash: sha256Hex('vault-verifier'),
          envelope,
        });
        if (check !== VAULT_SENTINEL_PLAINTEXT) {
          throw new Error('Sentinel mismatch');
        }
      } catch {
        kek.fill(0);
        throw new PasswordOneError('POLICY_VIOLATION', 'Invalid PW1_MASTER_KEY for existing vault database', 401);
      }
    }

    return kek;
  }

  #rowToPolicy(row: Record<string, unknown>): SecretPolicy {
    // Reconstruct directly from relational columns so any SQLite tampering alters canonical hash -> fails GCM AAD!
    const allowedHosts = JSON.parse(String(row.allowed_hosts_json)) as string[];
    const allowedTools = JSON.parse(String(row.allowed_tools_json)) as AllowedToolKind[];
    const allowedCommands = JSON.parse(String(row.allowed_commands_json)) as string[];
    return {
      allowedHosts,
      allowedTools,
      allowedCommands,
      allowHttp: Boolean(Number(row.allow_http)),
      allowEnvInjection: Boolean(Number(row.allow_env_injection)),
      crossOriginRedirect: String(row.cross_origin_redirect) as CrossOriginRedirectMode,
      maxLeaseTtlSeconds: Number(row.max_lease_ttl_seconds),
      requireGrant: Boolean(Number(row.require_grant)),
    };
  }

  #rowToMetadata(row: Record<string, unknown>): SecretMetadata {
    const alias = String(row.alias);
    const policy = this.#rowToPolicy(row);
    const recomputedHash = computePolicyHash(policy);
    return {
      id: String(row.id),
      alias,
      handle: `pw1://${alias}`,
      placeholder: `{{pw1://${alias}}}`,
      description: String(row.description),
      version: Number(row.version),
      policy,
      policyHash: recomputedHash,
      createdAt: String(row.created_at),
      updatedAt: String(row.updated_at),
    };
  }

  upsertSecret(input: UpsertSecretInput): SecretMetadata {
    const alias = validateAlias(input.alias);
    if (!input.value || typeof input.value !== 'string' || input.value.length < 4) {
      throw new PasswordOneError('INVALID_INPUT', 'Secret value must be a string of at least 4 characters');
    }
    const policy = normalizePolicy(input.policy);
    const policyHash = computePolicyHash(policy);
    const now = new Date().toISOString();
    const description = (input.description ?? '').trim();

    const existing = this.#db
      .prepare('SELECT id, version, created_at FROM secrets WHERE alias = ?')
      .get(alias) as { id: string; version: number; created_at: string } | undefined;

    const secretId = existing ? existing.id : `sec_${randomUUID().replace(/-/g, '')}`;
    const version = existing ? Number(existing.version) + 1 : 1;
    const createdAt = existing ? existing.created_at : now;

    const envelope = encryptSecretEnvelope({
      kek: this.#kek,
      secretId,
      alias,
      version,
      policyHash,
      plaintext: input.value,
    });

    if (existing) {
      this.#db
        .prepare(
          `UPDATE secrets SET
            description = ?,
            version = ?,
            allowed_hosts_json = ?,
            allowed_tools_json = ?,
            allowed_commands_json = ?,
            allow_http = ?,
            allow_env_injection = ?,
            cross_origin_redirect = ?,
            max_lease_ttl_seconds = ?,
            require_grant = ?,
            policy_hash = ?,
            dek_salt = ?,
            iv = ?,
            ciphertext = ?,
            auth_tag = ?,
            updated_at = ?
          WHERE alias = ?`
        )
        .run(
          description,
          version,
          JSON.stringify(policy.allowedHosts),
          JSON.stringify(policy.allowedTools),
          JSON.stringify(policy.allowedCommands),
          policy.allowHttp ? 1 : 0,
          policy.allowEnvInjection ? 1 : 0,
          policy.crossOriginRedirect,
          policy.maxLeaseTtlSeconds,
          policy.requireGrant ? 1 : 0,
          policyHash,
          envelope.dekSalt,
          envelope.iv,
          envelope.ciphertext,
          envelope.authTag,
          now,
          alias
        );
    } else {
      this.#db
        .prepare(
          `INSERT INTO secrets (
            id, alias, description, version,
            allowed_hosts_json, allowed_tools_json, allowed_commands_json,
            allow_http, allow_env_injection, cross_origin_redirect,
            max_lease_ttl_seconds, require_grant, policy_hash,
            dek_salt, iv, ciphertext, auth_tag, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          secretId,
          alias,
          description,
          version,
          JSON.stringify(policy.allowedHosts),
          JSON.stringify(policy.allowedTools),
          JSON.stringify(policy.allowedCommands),
          policy.allowHttp ? 1 : 0,
          policy.allowEnvInjection ? 1 : 0,
          policy.crossOriginRedirect,
          policy.maxLeaseTtlSeconds,
          policy.requireGrant ? 1 : 0,
          policyHash,
          envelope.dekSalt,
          envelope.iv,
          envelope.ciphertext,
          envelope.authTag,
          createdAt,
          now
        );
    }

    this.appendAudit({
      action: existing ? 'SECRET_ROTATE' : 'SECRET_CREATE',
      alias,
      decision: 'MUTATE',
      reason: existing ? `Rotated secret to version ${version}` : 'Created policy-bound secret',
      metadata: {
        version,
        policyHash,
        allowedHosts: policy.allowedHosts,
        allowedTools: policy.allowedTools,
      },
    });

    return this.getSecretMetadata(alias);
  }

  listSecrets(): SecretMetadata[] {
    const rows = this.#db
      .prepare(
        `SELECT id, alias, description, version,
                allowed_hosts_json, allowed_tools_json, allowed_commands_json,
                allow_http, allow_env_injection, cross_origin_redirect,
                max_lease_ttl_seconds, require_grant, policy_hash,
                created_at, updated_at
         FROM secrets ORDER BY alias ASC`
      )
      .all();
    return rows.map((r) => this.#rowToMetadata(r));
  }

  getSecretMetadata(alias: string): SecretMetadata {
    const row = this.#db
      .prepare(
        `SELECT id, alias, description, version,
                allowed_hosts_json, allowed_tools_json, allowed_commands_json,
                allow_http, allow_env_injection, cross_origin_redirect,
                max_lease_ttl_seconds, require_grant, policy_hash,
                created_at, updated_at
         FROM secrets WHERE alias = ?`
      )
      .get(alias);
    if (!row) {
      throw new SecretNotFoundError(alias);
    }
    return this.#rowToMetadata(row);
  }

  deleteSecret(alias: string): boolean {
    const existing = this.#db.prepare('SELECT id FROM secrets WHERE alias = ?').get(alias);
    if (!existing) {
      return false;
    }
    this.#db.prepare('UPDATE grants SET revoked = 1 WHERE alias = ?').run(alias);
    this.#db.prepare('DELETE FROM secrets WHERE alias = ?').run(alias);
    this.appendAudit({
      action: 'SECRET_DELETE',
      alias,
      decision: 'MUTATE',
      reason: 'Deleted secret and revoked active grants',
    });
    return true;
  }

  /**
   * Internal-only broker method: verifies AAD against live relational policy columns before releasing plaintext.
   */
  resolveSecretForBroker(alias: string): ResolvedSecretRecord {
    const row = this.#db.prepare('SELECT * FROM secrets WHERE alias = ?').get(alias);
    if (!row) {
      throw new SecretNotFoundError(alias);
    }

    let policy: SecretPolicy;
    try {
      policy = this.#rowToPolicy(row);
    } catch {
      this.appendAudit({
        action: 'TAMPER_DETECTED',
        alias,
        decision: 'DENY',
        reason: 'Malformed policy JSON in SQLite row',
      });
      throw new PolicyTamperError(alias);
    }

    const recomputedPolicyHash = computePolicyHash(policy);
    const storedPolicyHash = String(row.policy_hash);

    let plaintext: string;
    try {
      plaintext = decryptSecretEnvelope({
        kek: this.#kek,
        secretId: String(row.id),
        alias: String(row.alias),
        version: Number(row.version),
        policyHash: recomputedPolicyHash,
        envelope: {
          dekSalt: String(row.dek_salt),
          iv: String(row.iv),
          ciphertext: String(row.ciphertext),
          authTag: String(row.auth_tag),
        },
      });
    } catch (err) {
      this.appendAudit({
        action: 'TAMPER_DETECTED',
        alias,
        decision: 'DENY',
        reason: 'AES-256-GCM AAD verification failed (stored policy or ciphertext modified)',
        metadata: {
          storedPolicyHash,
          recomputedPolicyHash,
        },
      });
      throw err instanceof PolicyTamperError ? err : new PolicyTamperError(alias);
    }

    if (storedPolicyHash !== recomputedPolicyHash) {
      this.appendAudit({
        action: 'TAMPER_DETECTED',
        alias,
        decision: 'DENY',
        reason: 'Policy hash mismatch detected',
      });
      throw new PolicyTamperError(alias);
    }

    return {
      metadata: this.#rowToMetadata(row),
      plaintext,
    };
  }

  collectActiveSecretsForScrubber(): ActiveSecretMaterial[] {
    const rows = this.#db.prepare('SELECT * FROM secrets').all();
    const active: ActiveSecretMaterial[] = [];
    for (const row of rows) {
      const alias = String(row.alias);
      try {
        const policy = this.#rowToPolicy(row);
        const recomputedPolicyHash = computePolicyHash(policy);
        const value = decryptSecretEnvelope({
          kek: this.#kek,
          secretId: String(row.id),
          alias,
          version: Number(row.version),
          policyHash: recomputedPolicyHash,
          envelope: {
            dekSalt: String(row.dek_salt),
            iv: String(row.iv),
            ciphertext: String(row.ciphertext),
            authTag: String(row.auth_tag),
          },
        });
        active.push({ alias, value });
      } catch {
        // Tampered rows cannot be decrypted; broker execution will hard-reject them on access.
      }
    }
    return active;
  }

  createGrant(input: CreateGrantInput): ScopedGrant {
    const meta = this.getSecretMetadata(input.alias);
    const agentId = (input.agentId ?? '').trim();
    if (!agentId) {
      throw new PasswordOneError('INVALID_INPUT', 'agentId is required to issue a scoped grant');
    }

    const requestedTools = input.allowedTools ?? meta.policy.allowedTools;
    if (requestedTools.length === 0) {
      throw new PasswordOneError('INVALID_INPUT', 'Grant allowedTools cannot be empty');
    }
    for (const t of requestedTools) {
      if (!meta.policy.allowedTools.includes(t)) {
        throw new PolicyViolationError(
          `Grant cannot permit tool "${t}" because secret "${meta.alias}" only allows [${meta.policy.allowedTools.join(', ')}]`
        );
      }
    }

    let grantHosts: string[] = meta.policy.allowedHosts;
    if (input.allowedHosts && input.allowedHosts.length > 0) {
      grantHosts = input.allowedHosts.map((h) => validateHostPattern(h));
      for (const gh of grantHosts) {
        if (!isHostPatternSubset(gh, meta.policy.allowedHosts)) {
          throw new PolicyViolationError(
            `Grant host "${gh}" exceeds allowedHosts [${meta.policy.allowedHosts.join(', ')}] of secret "${meta.alias}"`
          );
        }
      }
    }

    const maxUses = input.maxUses ?? 10;
    if (!Number.isInteger(maxUses) || maxUses < 1 || maxUses > 10000) {
      throw new PasswordOneError('INVALID_INPUT', 'maxUses must be an integer between 1 and 10000');
    }

    const ttlSeconds = input.ttlSeconds ?? Math.min(300, meta.policy.maxLeaseTtlSeconds);
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > meta.policy.maxLeaseTtlSeconds) {
      throw new PolicyViolationError(
        `Grant ttlSeconds (${ttlSeconds}) exceeds secret maxLeaseTtlSeconds (${meta.policy.maxLeaseTtlSeconds})`
      );
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();
    const grantId = `grant_${randomBytes(12).toString('hex')}`;
    const createdAt = now.toISOString();

    const sortedTools = Array.from(new Set(requestedTools)).sort() as AllowedToolKind[];
    const sortedHosts = Array.from(new Set(grantHosts)).sort();

    this.#db
      .prepare(
        `INSERT INTO grants (
          grant_id, alias, agent_id, allowed_tools_json, allowed_hosts_json,
          max_uses, used_count, expires_at, revoked, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, 0, ?)`
      )
      .run(
        grantId,
        meta.alias,
        agentId,
        JSON.stringify(sortedTools),
        JSON.stringify(sortedHosts),
        maxUses,
        expiresAt,
        createdAt
      );

    this.appendAudit({
      action: 'GRANT_CREATE',
      alias: meta.alias,
      agentId,
      grantId,
      decision: 'MUTATE',
      reason: `Issued scoped grant (maxUses=${maxUses}, ttlSeconds=${ttlSeconds})`,
      metadata: {
        allowedTools: sortedTools,
        allowedHosts: sortedHosts,
        expiresAt,
      },
    });

    return {
      grantId,
      alias: meta.alias,
      agentId,
      allowedTools: sortedTools,
      allowedHosts: sortedHosts,
      maxUses,
      usedCount: 0,
      expiresAt,
      revoked: false,
      createdAt,
    };
  }

  consumeGrant(params: {
    grantId: string;
    alias: string;
    agentId?: string;
    tool: AllowedToolKind;
    targetHost?: string;
  }): ScopedGrant {
    const row = this.#db.prepare('SELECT * FROM grants WHERE grant_id = ?').get(params.grantId);
    if (!row) {
      throw new LeaseError(`Grant "${params.grantId}" does not exist`);
    }
    if (String(row.alias) !== params.alias) {
      throw new LeaseError(`Grant "${params.grantId}" is not bound to secret "${params.alias}"`);
    }
    if (Number(row.revoked) !== 0) {
      throw new LeaseError(`Grant "${params.grantId}" has been revoked`);
    }
    const boundAgent = String(row.agent_id);
    if (params.agentId && params.agentId !== boundAgent) {
      throw new LeaseError(`Grant "${params.grantId}" is bound to agent "${boundAgent}", not "${params.agentId}"`);
    }
    const expiresAt = String(row.expires_at);
    if (Date.parse(expiresAt) <= Date.now()) {
      throw new LeaseError(`Grant "${params.grantId}" expired at ${expiresAt}`);
    }

    const allowedTools = JSON.parse(String(row.allowed_tools_json)) as AllowedToolKind[];
    if (!allowedTools.includes(params.tool)) {
      throw new LeaseError(`Grant "${params.grantId}" does not allow tool "${params.tool}"`);
    }

    const allowedHosts = JSON.parse(String(row.allowed_hosts_json)) as string[];
    if (params.tool === 'http' && params.targetHost) {
      if (!hostMatchesAny(params.targetHost, allowedHosts)) {
        throw new LeaseError(`Grant "${params.grantId}" does not allow host "${params.targetHost}"`);
      }
    }

    const updateRes = this.#db
      .prepare(
        `UPDATE grants
         SET used_count = used_count + 1
         WHERE grant_id = ? AND revoked = 0 AND used_count < max_uses`
      )
      .run(params.grantId);

    if (Number(updateRes.changes) === 0) {
      throw new LeaseError(`Grant "${params.grantId}" has exhausted its maxUses (${String(row.max_uses)})`);
    }

    return {
      grantId: String(row.grant_id),
      alias: String(row.alias),
      agentId: boundAgent,
      allowedTools,
      allowedHosts,
      maxUses: Number(row.max_uses),
      usedCount: Number(row.used_count) + 1,
      expiresAt,
      revoked: false,
      createdAt: String(row.created_at),
    };
  }

  appendAudit(input: {
    action: string;
    alias?: string | null;
    agentId?: string | null;
    grantId?: string | null;
    toolName?: string | null;
    target?: string | null;
    decision: AuditDecision;
    reason: string;
    redactionsCount?: number;
    metadata?: Record<string, unknown>;
  }): AuditEntry {
    // Scrub reason, target, and metadata before writing so no secret ever touches audit_logs
    const activeSecrets = this.collectActiveSecretsForScrubber();
    const safeReason = this.#scrubber.scrub(input.reason, activeSecrets).scrubbedText;
    const safeTarget = input.target ? this.#scrubber.scrub(input.target, activeSecrets).scrubbedText : null;
    const rawMetaStr = canonicalJson(input.metadata ?? {});
    const safeMetaStr = this.#scrubber.scrub(rawMetaStr, activeSecrets).scrubbedText;
    let parsedSafeMeta: Record<string, unknown> = {};
    try {
      parsedSafeMeta = JSON.parse(safeMetaStr) as Record<string, unknown>;
    } catch {
      parsedSafeMeta = { scrubbedRaw: safeMetaStr };
    }
    const canonicalMeta = canonicalJson(parsedSafeMeta);

    const lastRow = this.#db
      .prepare('SELECT seq, entry_hash FROM audit_logs ORDER BY seq DESC LIMIT 1')
      .get() as { seq: number; entry_hash: string } | undefined;

    const nextSeq = lastRow ? Number(lastRow.seq) + 1 : 1;
    const prevHash = lastRow ? String(lastRow.entry_hash) : GENESIS_HASH;
    const eventId = `aud_${randomUUID().replace(/-/g, '')}`;
    const timestamp = new Date().toISOString();
    const redactionsCount = input.redactionsCount ?? 0;

    const entryHash = computeAuditHash({
      seq: nextSeq,
      eventId,
      timestamp,
      action: input.action,
      alias: input.alias ?? null,
      agentId: input.agentId ?? null,
      grantId: input.grantId ?? null,
      toolName: input.toolName ?? null,
      target: safeTarget,
      decision: input.decision,
      reason: safeReason,
      redactionsCount,
      canonicalMetadata: canonicalMeta,
      prevHash,
    });

    this.#db
      .prepare(
        `INSERT INTO audit_logs (
          seq, event_id, timestamp, action, alias, agent_id, grant_id,
          tool_name, target, decision, reason, redactions_count,
          metadata_json, prev_hash, entry_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        nextSeq,
        eventId,
        timestamp,
        input.action,
        input.alias ?? null,
        input.agentId ?? null,
        input.grantId ?? null,
        input.toolName ?? null,
        safeTarget,
        input.decision,
        safeReason,
        redactionsCount,
        canonicalMeta,
        prevHash,
        entryHash
      );

    return {
      seq: nextSeq,
      eventId,
      timestamp,
      action: input.action,
      alias: input.alias ?? null,
      agentId: input.agentId ?? null,
      grantId: input.grantId ?? null,
      toolName: input.toolName ?? null,
      target: safeTarget,
      decision: input.decision,
      reason: safeReason,
      redactionsCount,
      metadata: parsedSafeMeta,
      prevHash,
      entryHash,
    };
  }

  listAuditLogs(limit = 100): AuditEntry[] {
    const safeLimit = Math.max(1, Math.min(1000, Math.trunc(limit)));
    const rows = this.#db
      .prepare('SELECT * FROM audit_logs ORDER BY seq DESC LIMIT ?')
      .all(safeLimit);
    return rows.map((r) => ({
      seq: Number(r.seq),
      eventId: String(r.event_id),
      timestamp: String(r.timestamp),
      action: String(r.action),
      alias: r.alias !== null ? String(r.alias) : null,
      agentId: r.agent_id !== null ? String(r.agent_id) : null,
      grantId: r.grant_id !== null ? String(r.grant_id) : null,
      toolName: r.tool_name !== null ? String(r.tool_name) : null,
      target: r.target !== null ? String(r.target) : null,
      decision: String(r.decision) as AuditDecision,
      reason: String(r.reason),
      redactionsCount: Number(r.redactions_count),
      metadata: JSON.parse(String(r.metadata_json)) as Record<string, unknown>,
      prevHash: String(r.prev_hash),
      entryHash: String(r.entry_hash),
    }));
  }

  verifyAuditChain(): AuditVerificationResult {
    const rows = this.#db.prepare('SELECT * FROM audit_logs ORDER BY seq ASC').all();
    let expectedPrev = GENESIS_HASH;
    let expectedSeq = 1;

    for (const r of rows) {
      const seq = Number(r.seq);
      if (seq !== expectedSeq) {
        return {
          valid: false,
          entriesChecked: expectedSeq - 1,
          headHash: expectedPrev,
          brokenAtSeq: seq,
          reason: `Audit sequence gap detected: expected seq ${expectedSeq}, found ${seq}`,
        };
      }

      const prevHash = String(r.prev_hash);
      if (prevHash !== expectedPrev) {
        return {
          valid: false,
          entriesChecked: seq - 1,
          headHash: expectedPrev,
          brokenAtSeq: seq,
          reason: `prev_hash mismatch at seq ${seq}`,
        };
      }

      let canonicalMeta: string;
      try {
        canonicalMeta = canonicalJson(JSON.parse(String(r.metadata_json)));
      } catch {
        return {
          valid: false,
          entriesChecked: seq - 1,
          headHash: expectedPrev,
          brokenAtSeq: seq,
          reason: `Corrupted metadata_json at seq ${seq}`,
        };
      }

      const recomputed = computeAuditHash({
        seq,
        eventId: String(r.event_id),
        timestamp: String(r.timestamp),
        action: String(r.action),
        alias: r.alias !== null ? String(r.alias) : null,
        agentId: r.agent_id !== null ? String(r.agent_id) : null,
        grantId: r.grant_id !== null ? String(r.grant_id) : null,
        toolName: r.tool_name !== null ? String(r.tool_name) : null,
        target: r.target !== null ? String(r.target) : null,
        decision: String(r.decision) as AuditDecision,
        reason: String(r.reason),
        redactionsCount: Number(r.redactions_count),
        canonicalMetadata: canonicalMeta,
        prevHash,
      });

      if (recomputed !== String(r.entry_hash)) {
        return {
          valid: false,
          entriesChecked: seq - 1,
          headHash: expectedPrev,
          brokenAtSeq: seq,
          reason: `entry_hash mismatch at seq ${seq}: row content was modified`,
        };
      }

      expectedPrev = recomputed;
      expectedSeq += 1;
    }

    return {
      valid: true,
      entriesChecked: rows.length,
      headHash: expectedPrev,
    };
  }

  getStats(): {
    secretsCount: number;
    activeGrantsCount: number;
    auditEntriesCount: number;
    auditVerification: AuditVerificationResult;
  } {
    const nowIso = new Date().toISOString();
    const secretsRow = this.#db.prepare('SELECT COUNT(*) AS cnt FROM secrets').get() as { cnt: number };
    const grantsRow = this.#db
      .prepare('SELECT COUNT(*) AS cnt FROM grants WHERE revoked = 0 AND used_count < max_uses AND expires_at > ?')
      .get(nowIso) as { cnt: number };
    const auditVerification = this.verifyAuditChain();
    return {
      secretsCount: Number(secretsRow.cnt),
      activeGrantsCount: Number(grantsRow.cnt),
      auditEntriesCount: auditVerification.entriesChecked,
      auditVerification,
    };
  }

  close(): void {
    this.#kek.fill(0);
    this.#db.close();
  }
}
