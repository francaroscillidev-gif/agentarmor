/**
 * Data Loss Prevention (DLP) Redaction Engine
 * Prevents agents or tools from leaking secrets (OpenAI, AWS, GitHub, SSH private keys, etc.)
 */

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  replacement: string;
}

export const KNOWN_SECRET_PATTERNS: SecretPattern[] = [
  // OpenAI API Key
  {
    name: 'OpenAI API Key',
    pattern: /\bsk-[a-zA-Z0-9_-]{20,64}\b/g,
    replacement: '[REDACTED_OPENAI_KEY]'
  },
  // Anthropic API Key
  {
    name: 'Anthropic API Key',
    pattern: /\bsk-ant-[a-zA-Z0-9_-]{20,100}\b/g,
    replacement: '[REDACTED_ANTHROPIC_KEY]'
  },
  // GitHub Personal Access Token
  {
    name: 'GitHub Token',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}\b/g,
    replacement: '[REDACTED_GITHUB_TOKEN]'
  },
  // AWS Access Key ID
  {
    name: 'AWS Access Key ID',
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    replacement: '[REDACTED_AWS_KEY_ID]'
  },
  // Generic Private Key Headers
  {
    name: 'Private Key Block',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    replacement: '[REDACTED_PRIVATE_KEY]'
  },
  // Generic bearer tokens in env format (KEY=value)
  {
    name: 'Generic Secret in Env',
    pattern: /(?:API_KEY|SECRET_KEY|AUTH_TOKEN|PRIVATE_KEY|DATABASE_URL|PASSWORD)\s*=\s*['"]?([a-zA-Z0-9_\-\.\:\/@]{8,})['"]?/gi,
    replacement: '$1=[REDACTED_SECRET]'
  }
];

export class DlpEngine {
  private patterns: SecretPattern[];

  constructor(customPatterns: SecretPattern[] = []) {
    this.patterns = [...KNOWN_SECRET_PATTERNS, ...customPatterns];
  }

  /**
   * Scans a string and masks any detected secrets.
   */
  public redact(text: string): { sanitized: string; redactedSecrets: string[] } {
    let sanitized = text;
    const found: string[] = [];

    for (const pat of this.patterns) {
      // Test first
      if (pat.pattern.test(sanitized)) {
        found.push(pat.name);
        sanitized = sanitized.replace(pat.pattern, pat.replacement);
      }
    }

    return {
      sanitized,
      redactedSecrets: Array.from(new Set(found))
    };
  }

  /**
   * Deep sanitize arbitrary objects/JSON payloads
   */
  public sanitizeObject<T>(input: T): T {
    if (typeof input === 'string') {
      return this.redact(input).sanitized as unknown as T;
    }
    if (Array.isArray(input)) {
      return input.map(item => this.sanitizeObject(item)) as unknown as T;
    }
    if (input !== null && typeof input === 'object') {
      const output: Record<string, any> = {};
      for (const [key, value] of Object.entries(input)) {
        output[key] = this.sanitizeObject(value);
      }
      return output as unknown as T;
    }
    return input;
  }
}
