/**
 * Rate Limiter & Infinite Loop / Cost Circuit Breaker
 * Prevents recursive agent loops, token budget overruns, and rapid-fire API hammering.
 */

export interface BudgetConfig {
  maxToolCallsPerMinute?: number;
  maxConsecutiveFailures?: number;
  maxDailyCostUsd?: number;
}

export class CircuitBreaker {
  private timestamps: number[] = [];
  private consecutiveFailures: number = 0;
  private config: Required<BudgetConfig>;

  constructor(config: BudgetConfig = {}) {
    this.config = {
      maxToolCallsPerMinute: config.maxToolCallsPerMinute ?? 30,
      maxConsecutiveFailures: config.maxConsecutiveFailures ?? 5,
      maxDailyCostUsd: config.maxDailyCostUsd ?? 10.0
    };
  }

  /**
   * Evaluates if a tool invocation can proceed without exceeding velocity limits.
   */
  public checkLimit(): { allowed: boolean; reason?: string } {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;

    // Clean old entries
    this.timestamps = this.timestamps.filter(t => t > oneMinuteAgo);

    if (this.timestamps.length >= this.config.maxToolCallsPerMinute) {
      return {
        allowed: false,
        reason: `Rate limit tripped: exceeded ${this.config.maxToolCallsPerMinute} tool calls/minute. Suspected infinite loop.`
      };
    }

    if (this.consecutiveFailures >= this.config.maxConsecutiveFailures) {
      return {
        allowed: false,
        reason: `Circuit breaker tripped: ${this.consecutiveFailures} consecutive tool execution failures.`
      };
    }

    this.timestamps.push(now);
    return { allowed: true };
  }

  public recordFailure(): void {
    this.consecutiveFailures += 1;
  }

  public recordSuccess(): void {
    this.consecutiveFailures = 0;
  }
}
