/**
 * Audit Logger
 * Writes immutable, structured security events to JSONL format.
 */

import fs from 'node:fs';
import path from 'node:path';

export interface AuditEvent {
  timestamp: string;
  eventType: 'COMMAND_EVALUATION' | 'DLP_REDACTION' | 'INJECTION_DETECTED' | 'TOOL_CALL_BLOCKED' | 'SANDBOX_ROLLBACK';
  status: 'ALLOWED' | 'BLOCKED' | 'WARNED' | 'SANITIZED';
  details: Record<string, any>;
}

export class AuditLogger {
  private logPath: string;

  constructor(logDir: string = process.cwd()) {
    this.logPath = path.join(logDir, '.agentarmor_audit.jsonl');
  }

  public log(event: Omit<AuditEvent, 'timestamp'>): void {
    const fullEvent: AuditEvent = {
      timestamp: new Date().toISOString(),
      ...event
    };
    try {
      fs.appendFileSync(this.logPath, JSON.stringify(fullEvent) + '\n', 'utf-8');
    } catch {
      // In case of permission errors, fail safely without crashing
    }
  }

  public getLogPath(): string {
    return this.logPath;
  }
}
