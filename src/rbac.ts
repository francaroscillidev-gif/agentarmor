/**
 * Multi-Tenancy Role-Based Access Control (RBAC) Engine
 * Allows assigning distinct privilege tiers to different agents (e.g. read-only researcher, full-stack coder, devops deployer)
 */

export type AgentRole = 'viewer' | 'researcher' | 'developer' | 'devops' | 'admin';

export interface RolePermissions {
  canReadFiles: boolean;
  canWriteFiles: boolean;
  canExecuteShell: boolean;
  canExecuteDdlSql: boolean;
  canAccessNetwork: boolean;
  allowedToolNamespaces: string[];
}

export const ROLE_DEFINITIONS: Record<AgentRole, RolePermissions> = {
  viewer: {
    canReadFiles: true,
    canWriteFiles: false,
    canExecuteShell: false,
    canExecuteDdlSql: false,
    canAccessNetwork: false,
    allowedToolNamespaces: ['read', 'get', 'list', 'search']
  },
  researcher: {
    canReadFiles: true,
    canWriteFiles: false,
    canExecuteShell: false,
    canExecuteDdlSql: false,
    canAccessNetwork: true,
    allowedToolNamespaces: ['read', 'get', 'list', 'search', 'fetch', 'browse']
  },
  developer: {
    canReadFiles: true,
    canWriteFiles: true,
    canExecuteShell: true,
    canExecuteDdlSql: false,
    canAccessNetwork: true,
    allowedToolNamespaces: ['*']
  },
  devops: {
    canReadFiles: true,
    canWriteFiles: true,
    canExecuteShell: true,
    canExecuteDdlSql: true,
    canAccessNetwork: true,
    allowedToolNamespaces: ['*']
  },
  admin: {
    canReadFiles: true,
    canWriteFiles: true,
    canExecuteShell: true,
    canExecuteDdlSql: true,
    canAccessNetwork: true,
    allowedToolNamespaces: ['*']
  }
};

export class RbacEngine {
  private agentRoles: Map<string, AgentRole> = new Map();

  public registerAgent(agentId: string, role: AgentRole): void {
    this.agentRoles.set(agentId, role);
  }

  public getRole(agentId?: string): AgentRole {
    if (!agentId) return 'developer'; // default
    return this.agentRoles.get(agentId) || 'developer';
  }

  public canExecuteTool(agentId: string | undefined, toolName: string): { allowed: boolean; reason?: string } {
    const role = this.getRole(agentId);
    const perms = ROLE_DEFINITIONS[role];

    // Check namespace wildcard
    if (perms.allowedToolNamespaces.includes('*')) {
      return { allowed: true };
    }

    const matches = perms.allowedToolNamespaces.some(ns => toolName.toLowerCase().includes(ns));
    if (!matches) {
      return {
        allowed: false,
        reason: `RBAC Violation: Role '${role}' assigned to agent is not permitted to invoke tool '${toolName}'.`
      };
    }

    return { allowed: true };
  }
}
