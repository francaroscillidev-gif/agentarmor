/**
 * Policy Engine
 * Evaluates requested commands and tool invocations against a deterministic zero-trust policy.
 */

import path from 'node:path';
import os from 'node:os';
import { ArmorConfig, SecurityEvaluation, SecurityViolation } from './types.js';

export const DEFAULT_BLOCKED_COMMAND_PATTERNS: RegExp[] = [
  /\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f?|--recursive)\s+[\/\~]/i, // rm -rf / or ~
  /\brm\s+-[a-zA-Z]*f[a-zA-Z]*r?\s+[\/\~]/i,
  /\bmkfs\b/i,
  /\bdd\s+if=.*of=\/dev\/(?:sd|hd|nvme|disk)/i,
  /\bchmod\s+(?:-R\s+)?777\s+\//i,
  /\bchown\s+(?:-R\s+)?root\s+\//i,
  /\bcurl\b.*\|\s*(?:bash|sh|zsh)\b/i, // piping untrusted curl directly to shell
  /\bwget\b.*\|\s*(?:bash|sh|zsh)\b/i,
  /\b(?:shutdown|reboot|init\s+0|poweroff)\b/i,
  /\b:(){ :|:& };:\b/ // fork bomb
];

export const DEFAULT_PROTECTED_PATHS: string[] = [
  '.ssh',
  '.gnupg',
  '.aws',
  '.kube',
  path.join(os.homedir(), '.ssh'),
  path.join(os.homedir(), '.gnupg'),
  path.join(os.homedir(), '.aws'),
  path.join(os.homedir(), '.kube'),
  path.join(os.homedir(), '.config', 'gcloud'),
  '/etc/shadow',
  '/etc/passwd',
  '/etc/sudoers',
  '.env',
  '.env.local',
  '.env.production'
];

export class PolicyEngine {
  private config: ArmorConfig;
  private blockedPatterns: RegExp[];
  private protectedPaths: string[];

  constructor(config: ArmorConfig = {}) {
    this.config = config;
    this.blockedPatterns = [...DEFAULT_BLOCKED_COMMAND_PATTERNS];
    this.protectedPaths = [...DEFAULT_PROTECTED_PATHS, ...(config.protectedPaths || [])];
  }

  /**
   * Evaluates a shell command string.
   */
  public evaluateCommand(cmd: string): SecurityEvaluation {
    const violations: SecurityViolation[] = [];

    // 1. Check for destructive command patterns
    for (const pattern of this.blockedPatterns) {
      if (pattern.test(cmd)) {
        violations.push({
          code: 'ERR_DANGEROUS_COMMAND',
          message: `Command matches high-risk destructive signature: ${pattern.toString()}`,
          severity: 'critical',
          matchedRule: pattern.toString(),
          target: cmd
        });
      }
    }

    // 2. Check for accessing protected system or user credential paths
    for (const targetPath of this.protectedPaths) {
      const escaped = targetPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(`(?:\\b|/|\\s)${escaped}(?:\\b|/|\\s|$)`, 'i');
      if (regex.test(cmd)) {
        violations.push({
          code: 'ERR_PROTECTED_PATH_ACCESS',
          message: `Attempted access to protected credential/system path: ${targetPath}`,
          severity: 'critical',
          matchedRule: targetPath,
          target: cmd
        });
      }
    }

    const hasCritical = violations.some(v => v.severity === 'critical' || v.severity === 'high');

    return {
      allowed: !hasCritical,
      severity: hasCritical ? 'block' : (violations.length > 0 ? 'warn' : 'allow'),
      reason: violations.length > 0 ? violations[0].message : 'Passed security policy',
      violations
    };
  }

  /**
   * Evaluates a file system read/write action.
   */
  public evaluateFileAccess(filePath: string, operation: 'read' | 'write' | 'delete'): SecurityEvaluation {
    const violations: SecurityViolation[] = [];
    const resolved = path.resolve(filePath);

    for (const targetPath of this.protectedPaths) {
      const resolvedTarget = path.resolve(targetPath);
      if (resolved === resolvedTarget || resolved.startsWith(resolvedTarget + path.sep)) {
        violations.push({
          code: 'ERR_BLOCKED_FILE_ACCESS',
          message: `Disallowed ${operation} on protected path: ${resolved}`,
          severity: 'critical',
          matchedRule: targetPath,
          target: resolved
        });
      }
    }

    const blocked = violations.length > 0;
    return {
      allowed: !blocked,
      severity: blocked ? 'block' : 'allow',
      reason: blocked ? violations[0].message : 'Allowed',
      violations
    };
  }
}
