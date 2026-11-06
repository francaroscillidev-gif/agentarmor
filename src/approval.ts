/**
 * Human-in-the-Loop (HITL) Interactive Approval Prompt
 * For medium/high severity commands (e.g. database migrations, package uninstalls),
 * pauses execution and requests explicit terminal approval before continuing.
 */

import readline from 'node:readline';

export class ApprovalGateway {
  /**
   * Prompts user in CLI for confirmation.
   */
  public async requestApproval(actionDescription: string, riskReason: string): Promise<boolean> {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    console.log(`\n⚠️  [AgentArmor Security Warning] An agent requested a sensitive action:`);
    console.log(`   Action: ${actionDescription}`);
    console.log(`   Risk:   ${riskReason}\n`);

    return new Promise((resolve) => {
      rl.question('   👉 Allow this execution? (y/N): ', (answer) => {
        rl.close();
        const allowed = answer.trim().toLowerCase() === 'y' || answer.trim().toLowerCase() === 'yes';
        resolve(allowed);
      });
    });
  }
}
