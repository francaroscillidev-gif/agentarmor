/**
 * Core types for AgentArmor
 */

export type ActionSeverity = 'allow' | 'warn' | 'block';

export interface SecurityEvaluation {
  allowed: boolean;
  severity: ActionSeverity;
  reason?: string;
  violations: SecurityViolation[];
}

export interface SecurityViolation {
  code: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  matchedRule: string;
  target?: string;
}

export interface ArmorConfig {
  blockedCommands?: string[];
  protectedPaths?: string[];
  allowedDomains?: string[];
  enableDLP?: boolean;
  enableRollback?: boolean;
  strictMode?: boolean;
}

export interface ToolExecutionRequest {
  toolName: string;
  arguments: Record<string, any>;
  agentId?: string;
  timestamp?: number;
}
