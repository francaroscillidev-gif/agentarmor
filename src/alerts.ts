/**
 * Multi-Platform Webhook & Alert Dispatcher
 * Sends instant notifications to Discord, Slack, Telegram, or custom webhooks
 * when high-risk security threats (injections, SSRF, destructive commands, honeypot trips) occur.
 */

export interface WebhookConfig {
  slackWebhookUrl?: string;
  discordWebhookUrl?: string;
  customWebhookUrl?: string;
  minSeverity?: 'low' | 'medium' | 'high' | 'critical';
}

export interface SecurityAlertPayload {
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: string;
  timestamp: string;
  target?: string;
}

export class WebhookDispatcher {
  private config: WebhookConfig;

  constructor(config: WebhookConfig = {}) {
    this.config = config;
  }

  /**
   * Formats and dispatches alerts to configured channels.
   */
  public async dispatchAlert(alert: SecurityAlertPayload): Promise<{ dispatched: boolean; targets: string[] }> {
    const targets: string[] = [];

    // Discord Embed format
    if (this.config.discordWebhookUrl) {
      try {
        const discordBody = {
          embeds: [
            {
              title: `🛡️ AgentArmor Security Alert: ${alert.title}`,
              description: alert.details,
              color: alert.severity === 'critical' ? 15158332 : 15105570,
              fields: [
                { name: 'Severity', value: alert.severity.toUpperCase(), inline: true },
                { name: 'Timestamp', value: alert.timestamp, inline: true }
              ],
              footer: { text: 'AgentArmor Zero-Trust AI Gateway' }
            }
          ]
        };
        await fetch(this.config.discordWebhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(discordBody)
        });
        targets.push('discord');
      } catch {}
    }

    // Slack Incoming Webhook format
    if (this.config.slackWebhookUrl) {
      try {
        const slackBody = {
          text: `🚨 *[AgentArmor Alert]* ${alert.title}\n*Severity:* ${alert.severity.toUpperCase()}\n*Details:* ${alert.details}`
        };
        await fetch(this.config.slackWebhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(slackBody)
        });
        targets.push('slack');
      } catch {}
    }

    // Generic Custom Webhook
    if (this.config.customWebhookUrl) {
      try {
        await fetch(this.config.customWebhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(alert)
        });
        targets.push('custom');
      } catch {}
    }

    return {
      dispatched: targets.length > 0,
      targets
    };
  }
}
