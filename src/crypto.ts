import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes,
  scryptSync,
} from 'node:crypto';
import {
  PasswordOneError,
  PolicyTamperError,
  type AllowedToolKind,
  type SecretPolicy,
  type SecretPolicyInput,
} from './types.ts';

export interface EncryptedEnvelope {
  dekSalt: string;
  iv: string;
  ciphertext: string;
  authTag: string;
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  const entries = keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
  return `{${entries.join(',')}}`;
}

export function validateAlias(alias: string): string {
  const trimmed = alias.trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,126}[a-zA-Z0-9]$/.test(trimmed) || trimmed.includes('..')) {
    throw new PasswordOneError(
      'INVALID_INPUT',
      `Invalid secret alias "${alias}": use 2-128 chars matching [a-zA-Z0-9._/-] without ".."`
    );
  }
  return trimmed;
}

export function validateHostPattern(pattern: string): string {
  const normalized = pattern.trim().toLowerCase();
  if (!normalized || normalized === '*' || normalized === '*.*') {
    throw new PasswordOneError(
      'INVALID_INPUT',
      `Unsafe wildcard host pattern "${pattern}" is forbidden; bind secrets to explicit hostnames or "*.domain.tld"`
    );
  }
  const candidate = normalized.startsWith('*.') ? normalized.slice(2) : normalized;
  if (
    !candidate ||
    candidate.includes('*') ||
    candidate.includes('/') ||
    candidate.includes(':') ||
    candidate.includes('@') ||
    !/^[a-z0-9.-]+$/.test(candidate)
  ) {
    throw new PasswordOneError('INVALID_INPUT', `Invalid host pattern "${pattern}"`);
  }
  if (normalized.startsWith('*.') && !candidate.includes('.') && candidate !== 'local') {
    throw new PasswordOneError(
      'INVALID_INPUT',
      `Wildcard host pattern "${pattern}" must include at least a registrable domain`
    );
  }
  return normalized;
}

export function normalizePolicy(input: SecretPolicyInput): SecretPolicy {
  const rawTools = input.allowedTools ?? ['http'];
  const toolSet = new Set<AllowedToolKind>();
  for (const t of rawTools) {
    if (t !== 'http' && t !== 'exec') {
      throw new PasswordOneError('INVALID_INPUT', `Unsupported tool kind "${String(t)}"`);
    }
    toolSet.add(t);
  }
  if (toolSet.size === 0) {
    throw new PasswordOneError('INVALID_INPUT', 'Secret policy must allow at least one tool ("http" or "exec")');
  }
  const allowedTools = Array.from(toolSet).sort() as AllowedToolKind[];

  const hostSet = new Set<string>();
  for (const h of input.allowedHosts ?? []) {
    hostSet.add(validateHostPattern(h));
  }
  const allowedHosts = Array.from(hostSet).sort();

  if (allowedTools.includes('http') && allowedHosts.length === 0) {
    throw new PasswordOneError(
      'INVALID_INPUT',
      'Secrets permitting "http" must bind at least one explicit allowedHost pattern'
    );
  }

  const cmdSet = new Set<string>();
  for (const c of input.allowedCommands ?? []) {
    const trimmed = c.trim();
    if (!trimmed || trimmed.includes('/') || trimmed.includes(' ')) {
      throw new PasswordOneError(
        'INVALID_INPUT',
        `Invalid command basename "${c}" in allowedCommands (provide binary name only, e.g. "curl")`
      );
    }
    cmdSet.add(trimmed);
  }
  const allowedCommands = Array.from(cmdSet).sort();

  const crossOriginRedirect = input.crossOriginRedirect ?? 'block';
  if (crossOriginRedirect !== 'block' && crossOriginRedirect !== 'strip') {
    throw new PasswordOneError('INVALID_INPUT', `Invalid crossOriginRedirect "${String(crossOriginRedirect)}"`);
  }

  const maxLeaseTtlSeconds = input.maxLeaseTtlSeconds ?? 900;
  if (!Number.isInteger(maxLeaseTtlSeconds) || maxLeaseTtlSeconds < 1 || maxLeaseTtlSeconds > 86400) {
    throw new PasswordOneError('INVALID_INPUT', 'maxLeaseTtlSeconds must be an integer between 1 and 86400');
  }

  return {
    allowedHosts,
    allowedTools,
    allowedCommands,
    allowHttp: Boolean(input.allowHttp ?? false),
    allowEnvInjection: Boolean(input.allowEnvInjection ?? false),
    crossOriginRedirect,
    maxLeaseTtlSeconds,
    requireGrant: Boolean(input.requireGrant ?? false),
  };
}

export function computePolicyHash(policy: SecretPolicy): string {
  return sha256Hex(canonicalJson(policy));
}

export function buildSecretAad(
  secretId: string,
  alias: string,
  version: number,
  canonicalPolicyHash: string
): Buffer {
  return Buffer.from(`pw1:aad:v1|${secretId}|${alias}|${version}|${canonicalPolicyHash}`, 'utf8');
}

export function deriveKek(masterKey: string, vaultSalt: Buffer, scryptN = 16384): Buffer {
  if (!masterKey || masterKey.length < 8) {
    throw new PasswordOneError('INVALID_INPUT', 'PW1_MASTER_KEY must be at least 8 characters long');
  }
  return scryptSync(masterKey, vaultSalt, 32, {
    N: scryptN,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
}

export function deriveDek(kek: Buffer, dekSalt: Buffer, secretId: string, version: number): Buffer {
  const info = Buffer.from(`pw1:dek:v1:${secretId}:${version}`, 'utf8');
  const ab = hkdfSync('sha256', kek, dekSalt, info, 32);
  return Buffer.from(ab);
}

export function encryptSecretEnvelope(params: {
  kek: Buffer;
  secretId: string;
  alias: string;
  version: number;
  policyHash: string;
  plaintext: string;
}): EncryptedEnvelope {
  const dekSalt = randomBytes(32);
  const iv = randomBytes(12);
  const dek = deriveDek(params.kek, dekSalt, params.secretId, params.version);
  try {
    const aad = buildSecretAad(params.secretId, params.alias, params.version, params.policyHash);
    const cipher = createCipheriv('aes-256-gcm', dek, iv, { authTagLength: 16 });
    cipher.setAAD(aad);
    const enc1 = cipher.update(params.plaintext, 'utf8');
    const enc2 = cipher.final();
    const ciphertext = Buffer.concat([enc1, enc2]);
    const authTag = cipher.getAuthTag();
    return {
      dekSalt: dekSalt.toString('base64'),
      iv: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      authTag: authTag.toString('base64'),
    };
  } finally {
    dek.fill(0);
  }
}

export function decryptSecretEnvelope(params: {
  kek: Buffer;
  secretId: string;
  alias: string;
  version: number;
  policyHash: string;
  envelope: EncryptedEnvelope;
}): string {
  const dekSalt = Buffer.from(params.envelope.dekSalt, 'base64');
  const iv = Buffer.from(params.envelope.iv, 'base64');
  const ciphertext = Buffer.from(params.envelope.ciphertext, 'base64');
  const authTag = Buffer.from(params.envelope.authTag, 'base64');
  const dek = deriveDek(params.kek, dekSalt, params.secretId, params.version);
  try {
    const aad = buildSecretAad(params.secretId, params.alias, params.version, params.policyHash);
    const decipher = createDecipheriv('aes-256-gcm', dek, iv, { authTagLength: 16 });
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);
    const dec1 = decipher.update(ciphertext);
    const dec2 = decipher.final();
    return Buffer.concat([dec1, dec2]).toString('utf8');
  } catch {
    throw new PolicyTamperError(params.alias);
  } finally {
    dek.fill(0);
  }
}
