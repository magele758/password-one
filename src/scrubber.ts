import type { EncodingKind, ScrubMatchSummary, ScrubResult } from './types.ts';

export interface ActiveSecretMaterial {
  alias: string;
  value: string;
}

interface CompiledVariant {
  alias: string;
  encoding: EncodingKind;
  needle: string;
  replacement: string;
}

interface HeuristicRule {
  label: string;
  regex: RegExp;
  replacement: string;
}

const HEURISTIC_RULES: HeuristicRule[] = [
  {
    label: 'pem_private_key',
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    replacement: '[REDACTED:pattern:pem_private_key]',
  },
  {
    label: 'jwt',
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    replacement: '[REDACTED:pattern:jwt]',
  },
  {
    label: 'github_token',
    regex: /\b(?:ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghu_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|ghr_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
    replacement: '[REDACTED:pattern:github_token]',
  },
  {
    label: 'api_key',
    regex: /\b(?:sk_live_[A-Za-z0-9]{12,}|sk_test_[A-Za-z0-9]{12,}|rk_live_[A-Za-z0-9]{12,}|sk-proj-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9_-]{20,})\b/g,
    replacement: '[REDACTED:pattern:api_key]',
  },
  {
    label: 'aws_access_key',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    replacement: '[REDACTED:pattern:aws_access_key]',
  },
  {
    label: 'slack_token',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/g,
    replacement: '[REDACTED:pattern:slack_token]',
  },
];

function fullSymbolPercentEncode(input: string, lowerHex = false): string {
  let out = '';
  const bytes = Buffer.from(input, 'utf8');
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    const isAlphaNum =
      (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a);
    if (isAlphaNum) {
      out += String.fromCharCode(b);
    } else {
      const hex = b.toString(16).padStart(2, '0');
      out += `%${lowerHex ? hex.toLowerCase() : hex.toUpperCase()}`;
    }
  }
  return out;
}

function computeThreePhaseBase64Slices(secret: string): { std: string[]; url: string[] } {
  const bytes = Buffer.from(secret, 'utf8');
  const std: string[] = [];
  const url: string[] = [];
  // Require at least 9 aligned bytes (12 base64 chars) to avoid false positives on short strings
  for (const offset of [0, 1, 2]) {
    const rem = bytes.length - offset;
    const alignedLen = rem - (rem % 3);
    if (alignedLen >= 9) {
      const slice = bytes.subarray(offset, offset + alignedLen);
      std.push(slice.toString('base64'));
      url.push(slice.toString('base64url'));
    }
  }
  return { std, url };
}

function safeUnescapePercent(span: string): string {
  // Decode contiguous %XX hex byte runs as UTF-8 while tolerating surrounding raw punctuation
  return span.replace(/(?:%[0-9A-Fa-f]{2})+/g, (pctRun) => {
    try {
      return decodeURIComponent(pctRun);
    } catch {
      const bytes: number[] = [];
      for (let i = 0; i < pctRun.length; i += 3) {
        bytes.push(parseInt(pctRun.slice(i + 1, i + 3), 16));
      }
      return Buffer.from(bytes).toString('utf8');
    }
  });
}

function tryDecodeBase64Utf8(token: string): string | null {
  try {
    const normalized = token.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (normalized.length % 4)) % 4;
    const padded = normalized + '='.repeat(padLen);
    const buf = Buffer.from(padded, 'base64');
    if (buf.length < 4) return null;
    return buf.toString('utf8');
  } catch {
    return null;
  }
}

export class OutputScrubber {
  readonly #enableHeuristics: boolean;

  constructor(options?: { enableHeuristics?: boolean }) {
    this.#enableHeuristics = options?.enableHeuristics ?? true;
  }

  buildVariants(secrets: readonly ActiveSecretMaterial[]): CompiledVariant[] {
    const variants: CompiledVariant[] = [];
    const seen = new Set<string>();

    const pushVariant = (alias: string, encoding: EncodingKind, needle: string, prefix = ''): void => {
      if (!needle || needle.length < 4) return;
      const key = `${alias}|${ needle }`;
      if (seen.has(key)) return;
      seen.add(key);
      variants.push({
        alias,
        encoding,
        needle,
        replacement: `${prefix}[REDACTED:pw1://${alias}]`,
      });
    };

    for (const { alias, value } of secrets) {
      if (!value || value.length < 4) continue;

      // 1. Raw plaintext
      pushVariant(alias, 'raw', value);

      // 2. Basic-Auth colon suffix & common Basic prefixes
      for (const user of ['api', 'admin', 'user', 'token', 'x-api-key', '']) {
        const pair = `${user}:${value}`;
        const b64 = Buffer.from(pair, 'utf8').toString('base64');
        pushVariant(alias, 'basic_auth', `Basic ${b64}`, 'Basic ');
        pushVariant(alias, 'basic_auth', b64);
      }

      // 3. Standard Base64 (padded + unpadded)
      const b64Std = Buffer.from(value, 'utf8').toString('base64');
      pushVariant(alias, 'base64_std', b64Std);
      pushVariant(alias, 'base64_std', b64Std.replace(/=+$/, ''));

      // 4. URL-Safe Base64
      const b64Url = Buffer.from(value, 'utf8').toString('base64url');
      pushVariant(alias, 'base64_url', b64Url);

      // 5. URL-Encoded (RFC 3986 + aggressive symbol percent-encoding upper & lower)
      const uriComp = encodeURIComponent(value);
      if (uriComp !== value) {
        pushVariant(alias, 'url_encoded', uriComp);
        pushVariant(alias, 'url_encoded', uriComp.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase()));
      }
      const fullUpper = fullSymbolPercentEncode(value, false);
      const fullLower = fullSymbolPercentEncode(value, true);
      if (fullUpper !== value) pushVariant(alias, 'url_encoded', fullUpper);
      if (fullLower !== value) pushVariant(alias, 'url_encoded', fullLower);

      // 6. JSON-escaped (single & nested double serialization)
      const jsonSingle = JSON.stringify(value).slice(1, -1);
      if (jsonSingle !== value) {
        pushVariant(alias, 'json_escaped', jsonSingle);
        const jsonDouble = JSON.stringify(jsonSingle).slice(1, -1);
        if (jsonDouble !== jsonSingle) {
          pushVariant(alias, 'json_escaped', jsonDouble);
        }
      }

      // 3-phase Base64 interior slices for misaligned streams
      const phases = computeThreePhaseBase64Slices(value);
      for (const s of phases.std) pushVariant(alias, ' basic_auth'.trim() as EncodingKind, s);
      for (const u of phases.url) pushVariant(alias, 'base64_url', u);
    }

    // Match longest needles first so full tokens replace cleanly before interior slices
    variants.sort((a, b) => b.needle.length - a.needle.length);
    return variants;
  }

  scrub(input: string, secrets: readonly ActiveSecretMaterial[]): ScrubResult {
    if (!input) {
      return {
        scrubbedText: input,
        redactionsCount: 0,
        redactedAliases: [],
        matches: [],
      };
    }

    let text = input;
    const counts = new Map<string, ScrubMatchSummary>();
    const redactedAliasesSet = new Set<string>();
    let totalRedactions = 0;

    const recordHit = (label: string, encoding: EncodingKind, count: number, alias?: string): void => {
      if (count <= 0) return;
      totalRedactions += count;
      if (alias) redactedAliasesSet.add(alias);
      const mapKey = `${label}|${encoding}`;
      const existing = counts.get(mapKey);
      if (existing) {
        existing.count += count;
      } else {
        counts.set(mapKey, { label, encoding, count });
      }
    };

    const validSecrets = secrets.filter((s) => s.value && s.value.length >= 4);

    if (validSecrets.length > 0) {
      // Pass A: Active HTTP Basic Auth header decode inspection (catches arbitrary username:secret)
      text = text.replace(/\b(Basic\s+)([A-Za-z0-9+/=_-]{8,})/gi, (full, prefix: string, token: string) => {
        const decoded = tryDecodeBase64Utf8(token);
        if (!decoded) return full;
        for (const s of validSecrets) {
          if (decoded.includes(s.value)) {
            recordHit(`pw1://${s.alias}`, 'basic_auth', 1, s.alias);
            return `${prefix}[REDACTED:pw1://${s.alias}]`;
          }
        }
        return full;
      });

      // Pass B: Active percent-encoded span inspection (catches partial/mixed %XX encodings)
      if (text.includes('%')) {
        text = text.replace(/[^\s]*%[0-9A-Fa-f]{2}[^\s]*/g, (span) => {
          if (span.includes('[REDACTED:')) return span;
          const decoded = safeUnescapePercent(span);
          let replaced = decoded;
          let matchedAny = false;
          for (const s of validSecrets) {
            if (replaced.includes(s.value)) {
              const parts = replaced.split(s.value);
              const occurrences = parts.length - 1;
              recordHit(`pw1://${s.alias}`, 'url_encoded', occurrences, s.alias);
              replaced = parts.join(`[REDACTED:pw1://${s.alias}]`);
              matchedAny = true;
            }
          }
          return matchedAny ? replaced : span;
        });
      }

      // Pass C: Active standalone Base64 / Base64URL token decode inspection (catches user:secret or JSON-wrapped b64)
      text = text.replace(/(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/]{12,}={0,2}|[A-Za-z0-9_-]{12,})(?![A-Za-z0-9+/=_-])/g, (token) => {
        if (token.includes('REDACTED')) return token;
        const decoded = tryDecodeBase64Utf8(token);
        if (!decoded) return token;
        for (const s of validSecrets) {
          if (decoded.includes(s.value)) {
            const kind: EncodingKind = decoded.includes(`:${s.value}`)
              ? 'basic_auth'
              : token.includes('-') || token.includes('_')
                ? 'base64_url'
                : 'base64_std';
            recordHit(`pw1://${s.alias}`, kind, 1, s.alias);
            return `[REDACTED:pw1://${s.alias}]`;
          }
        }
        return token;
      });

      // Pass D: Deterministic 6-encoding exact & substring variant replacement
      const variants = this.buildVariants(validSecrets);
      for (const v of variants) {
        if (!text.includes(v.needle)) continue;
        // Split outside existing [REDACTED:...] markers so markers are never corrupted
        const segments = text.split(/(\[REDACTED:[^\]]+\])/g);
        let hitCount = 0;
        for (let i = 0; i < segments.length; i++) {
          const seg = segments[i]!;
          if (seg.startsWith('[REDACTED:') && seg.endsWith(']')) continue;
          if (seg.includes(v.needle)) {
            const parts = seg.split(v.needle);
            hitCount += parts.length - 1;
            segments[i] = parts.join(v.replacement);
          }
        }
        if (hitCount > 0) {
          text = segments.join('');
          recordHit(`pw1://${v.alias}`, v.encoding, hitCount, v.alias);
        }
      }
    }

    // Pass E: Defense-in-depth heuristic patterns for unregistered leaked credentials
    if (this.#enableHeuristics) {
      for (const rule of HEURISTIC_RULES) {
        const segments = text.split(/(\[REDACTED:[^\]]+\])/g);
        let ruleHits = 0;
        for (let i = 0; i < segments.length; i++) {
          const seg = segments[i]!;
          if (seg.startsWith('[REDACTED:') && seg.endsWith(']')) continue;
          segments[i] = seg.replace(rule.regex, () => {
            ruleHits += 1;
            return rule.replacement;
          });
        }
        if (ruleHits > 0) {
          text = segments.join('');
          recordHit(`pattern:${rule.label}`, 'heuristic_pattern', ruleHits);
        }
      }
    }

    return {
      scrubbedText: text,
      redactionsCount: totalRedactions,
      redactedAliases: Array.from(redactedAliasesSet).sort(),
      matches: Array.from(counts.values()),
    };
  }

  scrubHeaders(
    headers: Record<string, string>,
    secrets: readonly ActiveSecretMaterial[]
  ): { headers: Record<string, string>; redactionsCount: number; redactedAliases: string[] } {
    const out: Record<string, string> = {};
    let redactionsCount = 0;
    const aliasSet = new Set<string>();

    for (const [k, v] of Object.entries(headers)) {
      const lower = k.toLowerCase();
      if (lower === 'authorization' || lower === 'proxy-authorization' || lower === 'www-authenticate') {
        const res = this.scrub(v, secrets);
        out[k] = res.scrubbedText;
        redactionsCount += res.redactionsCount;
        for (const a of res.redactedAliases) aliasSet.add(a);
      } else {
        const res = this.scrub(v, secrets);
        out[k] = res.scrubbedText;
        redactionsCount += res.redactionsCount;
        for (const a of res.redactedAliases) aliasSet.add(a);
      }
    }

    return {
      headers: out,
      redactionsCount,
      redactedAliases: Array.from(aliasSet).sort(),
    };
  }
}
