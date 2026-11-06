/**
 * AI Tool Honeypot & Deception Detector
 * Seeds dummy high-value lures (e.g. fake .env secrets, fake AWS credentials, honeypot tools)
 * If an injected prompt or rogue agent touches the honeypot, an immediate emergency lockdown is triggered.
 */

export interface HoneypotTrap {
  name: string;
  type: 'fake_secret' | 'honeypot_path' | 'shadow_tool';
  signature: string;
}

export const CANARY_SECRETS: HoneypotTrap[] = [
  {
    name: 'Canary OpenAI Key',
    type: 'fake_secret',
    signature: 'sk-proj-canary-trap-88371946281047120391'
  },
  {
    name: 'Canary AWS Root Credential',
    type: 'fake_secret',
    signature: 'AKIA_CANARY_HONEYPOT_TRAP_001'
  },
  {
    name: 'Canary Database Connection',
    type: 'fake_secret',
    signature: 'postgres://root:canary_trap_pwd@honeypot.internal/production_db'
  },
  {
    name: 'Shadow Honeypot Directory',
    type: 'honeypot_path',
    signature: '/tmp/.agentarmor_honeypot_credentials'
  }
];

export class HoneypotEngine {
  private traps: HoneypotTrap[];
  private tripped: boolean = false;
  private trippedTrap?: HoneypotTrap;

  constructor(customTraps: HoneypotTrap[] = []) {
    this.traps = [...CANARY_SECRETS, ...customTraps];
  }

  /**
   * Scans input text or arguments for any canary lures.
   */
  public inspect(content: string): { compromised: boolean; trap?: HoneypotTrap; alertMessage?: string } {
    for (const trap of this.traps) {
      if (content.includes(trap.signature)) {
        this.tripped = true;
        this.trippedTrap = trap;
        return {
          compromised: true,
          trap,
          alertMessage: `🚨 CRITICAL HONEYPOT TRIGGERED: Rogue activity touched canary trap '${trap.name}'!`
        };
      }
    }
    return { compromised: false };
  }

  public isLockdownActive(): boolean {
    return this.tripped;
  }

  public getCanaries(): HoneypotTrap[] {
    return [...this.traps];
  }
}
