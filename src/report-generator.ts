/**
 * Export and Reporting Suite
 * Generates automated compliance reports (SARIF for GitHub Security & HTML Executive Summaries)
 */

import fs from 'node:fs';
import path from 'node:path';
import { AuditEvent } from './audit.js';

export class ReportGenerator {
  /**
   * Generates standard OASIS SARIF v2.1.0 for integration with GitHub Code Scanning / Security Alerts.
   */
  public static generateSarif(events: AuditEvent[]): string {
    const blockedEvents = events.filter(e => e.status === 'BLOCKED');

    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'AgentArmor',
              version: '0.1.0',
              informationUri: 'https://github.com/francaroscillidev-gif/agentarmor',
              rules: [
                {
                  id: 'AA001',
                  name: 'DangerousCommandBlock',
                  shortDescription: { text: 'Agent attempted destructive shell command' }
                },
                {
                  id: 'AA002',
                  name: 'PromptInjectionDetected',
                  shortDescription: { text: 'Adversarial prompt injection attempt detected' }
                },
                {
                  id: 'AA003',
                  name: 'SsrfEgressViolation',
                  shortDescription: { text: 'Outbound network access to cloud metadata or private IP blocked' }
                }
              ]
            }
          },
          results: blockedEvents.map(e => ({
            ruleId: e.eventType === 'COMMAND_EVALUATION' ? 'AA001' : (e.eventType === 'INJECTION_DETECTED' ? 'AA002' : 'AA003'),
            level: 'error',
            message: {
              text: `[AgentArmor Blocked Event] ${e.eventType}: ${JSON.stringify(e.details)}`
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'runtime_agent_session' },
                  region: { startLine: 1 }
                }
              }
            ]
          }))
        }
      ]
    };

    return JSON.stringify(sarif, null, 2);
  }

  /**
   * Generates standalone audit summary markdown
   */
  public static generateMarkdownSummary(events: AuditEvent[]): string {
    const total = events.length;
    const blocked = events.filter(e => e.status === 'BLOCKED').length;
    const sanitized = events.filter(e => e.status === 'SANITIZED').length;
    const allowed = events.filter(e => e.status === 'ALLOWED').length;

    return `# AgentArmor Security Audit Report
Generated: ${new Date().toISOString()}

### Summary Metrics
- **Total Invocations Evaluated:** ${total}
- **Threats & Violations Blocked:** ${blocked}
- **Secrets Redacted (DLP):** ${sanitized}
- **Safe Allowed Operations:** ${allowed}

### Recent Incidents (Last 10)
| Timestamp | Event Type | Status | Summary |
| :--- | :--- | :--- | :--- |
${events.slice(0, 10).map(e => `| ${e.timestamp} | ${e.eventType} | **${e.status}** | \`${JSON.stringify(e.details).slice(0, 60)}...\` |`).join('\n')}
`;
  }
}
