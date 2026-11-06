/**
 * Semantic SQL Injection & Dangerous DDL/DML Guard
 * Protects database connections and MCP SQL tools from data destruction and unauthorized exfiltration.
 */

export interface SqlEvaluation {
  allowed: boolean;
  reason?: string;
  isDestructive: boolean;
  isInjection: boolean;
}

export const DANGEROUS_SQL_PATTERNS: { name: string; pattern: RegExp; destructive: boolean }[] = [
  // Catastrophic DDL
  { name: 'DROP TABLE/DATABASE', pattern: /\bDROP\s+(?:TABLE|DATABASE|SCHEMA|VIEW)\b/i, destructive: true },
  { name: 'TRUNCATE TABLE', pattern: /\bTRUNCATE\s+(?:TABLE)?\b/i, destructive: true },
  { name: 'ALTER TABLE DROP', pattern: /\bALTER\s+TABLE\s+.*\bDROP\b/i, destructive: true },
  // Destructive DML without WHERE clause
  { name: 'DELETE ALL ROWS', pattern: /^\s*DELETE\s+FROM\s+[a-zA-Z0-9_.]+\s*;?\s*$/i, destructive: true },
  { name: 'UPDATE ALL ROWS', pattern: /^\s*UPDATE\s+[a-zA-Z0-9_.]+\s+SET\s+[^;]+;\s*$/i, destructive: true },
  // Classic SQL Injection tautologies & stacked execution
  { name: 'OR 1=1 Tautology', pattern: /\bOR\s+(?:1\s*=\s*1|'1'\s*=\s*'1'|true)\b/i, destructive: false },
  { name: 'SQL Comment Truncation', pattern: /(?:--|#|\/\*).*$/m, destructive: false },
  { name: 'UNION Based Extraction', pattern: /\bUNION\s+(?:ALL\s+)?SELECT\b/i, destructive: false },
  { name: 'Admin Privilege Grant', pattern: /\bGRANT\s+ALL\s+PRIVILEGES\b/i, destructive: true }
];

export class SqlGuard {
  /**
   * Evaluates a SQL query string.
   */
  public evaluateQuery(sql: string, allowDDL = false): SqlEvaluation {
    const trimmed = sql.trim();

    for (const rule of DANGEROUS_SQL_PATTERNS) {
      if (rule.pattern.test(trimmed)) {
        if (rule.destructive && !allowDDL) {
          return {
            allowed: false,
            reason: `Disallowed dangerous SQL operation: ${rule.name}`,
            isDestructive: true,
            isInjection: false
          };
        }
        if (!rule.destructive) {
          return {
            allowed: false,
            reason: `Potential SQL Injection / Tautology detected: ${rule.name}`,
            isDestructive: false,
            isInjection: true
          };
        }
      }
    }

    return {
      allowed: true,
      isDestructive: false,
      isInjection: false
    };
  }
}
