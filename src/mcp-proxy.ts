/**
 * MCP Proxy Interceptor
 * Transparently wraps standard MCP stdio JSON-RPC traffic,
 * enforcing zero-trust policies on 'tools/call' requests.
 */

import readline from 'node:readline';
import { PolicyEngine } from './policy.js';
import { DlpEngine } from './dlp.js';

export class McpProxy {
  private policy: PolicyEngine;
  private dlp: DlpEngine;

  constructor(policy: PolicyEngine = new PolicyEngine(), dlp: DlpEngine = new DlpEngine()) {
    this.policy = policy;
    this.dlp = dlp;
  }

  /**
   * Evaluates an incoming JSON-RPC MCP request.
   */
  public interceptRequest(rawJson: string): { action: 'forward' | 'block'; response?: string; forwardedJson?: string } {
    try {
      const msg = JSON.parse(rawJson);

      // Check if it's a tools/call request
      if (msg.method === 'tools/call' && msg.params) {
        const toolName = msg.params.name;
        const args = msg.params.arguments || {};

        // 1. If it's a shell/bash execution tool
        if (toolName.includes('command') || toolName.includes('bash') || toolName.includes('shell') || toolName.includes('exec')) {
          const cmd = args.command || args.cmd || args.CommandLine || '';
          if (cmd) {
            const evalResult = this.policy.evaluateCommand(cmd);
            if (!evalResult.allowed) {
              // Return standard JSON-RPC error response, blocking execution
              const errorResponse = {
                jsonrpc: '2.0',
                id: msg.id,
                error: {
                  code: -32000,
                  message: `[AgentArmor Security Violation] Command blocked: ${evalResult.reason}`,
                  data: evalResult.violations
                }
              };
              return { action: 'block', response: JSON.stringify(errorResponse) };
            }
          }
        }

        // 2. If it's a file read/write tool
        if (toolName.includes('file') || toolName.includes('write') || toolName.includes('read')) {
          const filePath = args.path || args.Path || args.filename || '';
          const op = (toolName.includes('write') || toolName.includes('edit')) ? 'write' : 'read';
          if (filePath) {
            const evalResult = this.policy.evaluateFileAccess(filePath, op);
            if (!evalResult.allowed) {
              const errorResponse = {
                jsonrpc: '2.0',
                id: msg.id,
                error: {
                  code: -32000,
                  message: `[AgentArmor Security Violation] File operation blocked: ${evalResult.reason}`,
                  data: evalResult.violations
                }
              };
              return { action: 'block', response: JSON.stringify(errorResponse) };
            }
          }
        }

        // 3. Inbound DLP sanitize arguments
        msg.params.arguments = this.dlp.sanitizeObject(args);
      }

      return { action: 'forward', forwardedJson: JSON.stringify(msg) };
    } catch {
      // If not JSON, pass through as-is
      return { action: 'forward', forwardedJson: rawJson };
    }
  }

  /**
   * Sanitizes outbound responses back to LLM to prevent leaking keys
   */
  public interceptResponse(rawJson: string): string {
    const { sanitized } = this.dlp.redact(rawJson);
    return sanitized;
  }
}
