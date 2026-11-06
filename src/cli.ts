#!/usr/bin/env node

/**
 * AgentArmor CLI
 * Interactive and transparent wrapper for AI agent tooling and security verification.
 */

import { PolicyEngine } from './policy.js';
import { DlpEngine } from './dlp.js';
import { SandboxManager } from './sandbox.js';
import { McpProxy } from './mcp-proxy.js';
import { InjectionDetector } from './injection.js';
import { AuditLogger } from './audit.js';
import { CircuitBreaker } from './circuit-breaker.js';

const args = process.argv.slice(2);
const command = args[0] || 'help';
const logger = new AuditLogger();

function printBanner() {
  console.log(`
   █████╗  ██████╗ ███████╗███╗   ██╗████████╗ █████╗ ██████╗ ███╗   ███╗ ██████╗ ██████╗ 
  ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗████╗ ████║██╔═══██╗██╔══██╗
  ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ███████║██████╔╝██╔████╔██║██║   ██║██████╔╝
  ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██║██╔══██╗██║╚██╔╝██║██║   ██║██╔══██╗
  ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ██║  ██║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝
  Shielding Autonomous AI Agents & MCP with Zero-Trust Execution
`);
}

switch (command) {
  case 'check-cmd': {
    const cmdToCheck = args.slice(1).join(' ');
    if (!cmdToCheck) {
      console.error('Error: specify a command to evaluate. E.g.: agentarmor check-cmd "rm -rf /"');
      process.exit(1);
    }
    const policy = new PolicyEngine();
    const result = policy.evaluateCommand(cmdToCheck);
    logger.log({
      eventType: 'COMMAND_EVALUATION',
      status: result.allowed ? 'ALLOWED' : 'BLOCKED',
      details: { cmd: cmdToCheck, reason: result.reason, violations: result.violations }
    });

    console.log(`Command: "${cmdToCheck}"`);
    console.log(`Status:  ${result.allowed ? '✅ ALLOWED' : '❌ BLOCKED'}`);
    console.log(`Severity: ${result.severity}`);
    if (!result.allowed) {
      console.log(`Reason:   ${result.reason}`);
      console.log('Violations:', JSON.stringify(result.violations, null, 2));
      process.exit(2);
    }
    break;
  }

  case 'check-prompt': {
    const promptText = args.slice(1).join(' ');
    if (!promptText) {
      console.error('Error: specify a prompt to evaluate.');
      process.exit(1);
    }
    const detector = new InjectionDetector();
    const res = detector.evaluate(promptText);

    logger.log({
      eventType: 'INJECTION_DETECTED',
      status: res.isInjection ? 'BLOCKED' : 'ALLOWED',
      details: { prompt: promptText, score: res.score, triggers: res.triggers }
    });

    console.log(`Prompt: "${promptText}"`);
    console.log(`Risk Status: ${res.isInjection ? '🚨 INJECTION DETECTED' : '✅ SAFE'}`);
    console.log(`Confidence Score: ${res.score.toFixed(2)}`);
    if (res.triggers.length > 0) {
      console.log('Triggers matched:', res.triggers);
      process.exit(2);
    }
    break;
  }

  case 'redact': {
    const text = args.slice(1).join(' ');
    const dlp = new DlpEngine();
    const result = dlp.redact(text);
    if (result.redactedSecrets.length > 0) {
      logger.log({
        eventType: 'DLP_REDACTION',
        status: 'SANITIZED',
        details: { redactedTypes: result.redactedSecrets }
      });
    }
    console.log('Sanitized output:');
    console.log(result.sanitized);
    if (result.redactedSecrets.length > 0) {
      console.log('\nRedacted Secret Types:', result.redactedSecrets);
    }
    break;
  }

  case 'checkpoint': {
    const sandbox = new SandboxManager();
    const snap = sandbox.createCheckpoint(args[1] || 'Manual CLI Checkpoint');
    console.log(`✅ Safety Checkpoint Created: ${snap.id}`);
    break;
  }

  case 'rollback': {
    const sandbox = new SandboxManager();
    const success = sandbox.rollback();
    if (success) {
      logger.log({
        eventType: 'SANDBOX_ROLLBACK',
        status: 'SANITIZED',
        details: { success: true }
      });
      console.log('✅ Workspace successfully restored to safety checkpoint!');
    } else {
      console.log('❌ Failed to rollback workspace (no git tracking or clean state).');
    }
    break;
  }

  case 'proxy-mcp': {
    printBanner();
    console.log('[AgentArmor] Starting MCP Zero-Trust Interceptor on STDIN/STDOUT...');
    const proxy = new McpProxy();
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk) => {
      const res = proxy.interceptRequest(chunk.toString());
      if (res.action === 'block' && res.response) {
        process.stdout.write(res.response + '\n');
      } else if (res.forwardedJson) {
        process.stdout.write(res.forwardedJson + '\n');
      }
    });
    break;
  }

  case 'help':
  default:
    printBanner();
    console.log(`Usage: agentarmor <command> [options]

Commands:
  check-cmd <command>      Evaluate shell command against security policies
  check-prompt <text>      Detect prompt injections, persona hijacks and jailbreaks
  redact <text>            Run DLP scanner & mask secrets (OpenAI, AWS, GitHub keys)
  checkpoint [desc]        Create an instant git-backed safety restore point
  rollback                 Instantly revert any damage made by an agent
  proxy-mcp                Run MCP transparent zero-trust proxy
`);
    break;
}
