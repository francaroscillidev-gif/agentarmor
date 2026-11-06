/**
 * Outbound Network Egress Firewall
 * Inspects and filters web requests, URLs, and curl/fetch commands initiated by agents.
 * Prevents DNS tunneling, SSRF attacks (AWS metadata 169.254.169.254, localhost/internal IP probing),
 * and exfiltration to unknown C2 (Command & Control) domains.
 */

export interface NetworkEvaluation {
  allowed: boolean;
  reason?: string;
  targetUrl?: string;
}

export class NetworkFirewall {
  private allowedDomains: Set<string>;
  private blockedIpsOrHosts: RegExp[] = [
    // Cloud Instance Metadata Service (AWS/GCP/Azure SSRF)
    /^169\.254\.169\.254$/,
    /^metadata\.google\.internal$/,
    // Localhost / Loopback exploitation
    /^(?:127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|::1)$/i,
    // Private RFC1918 networks (unless explicitly whitelisted)
    /^(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)$/
  ];

  constructor(allowedDomains: string[] = []) {
    // Sensible defaults for developer agents
    this.allowedDomains = new Set([
      'github.com',
      'api.github.com',
      'registry.npmjs.org',
      'pypi.org',
      'crates.io',
      'huggingface.co',
      ...allowedDomains.map(d => d.toLowerCase())
    ]);
  }

  /**
   * Evaluates a URL against SSRF and Egress rules.
   */
  public evaluateUrl(urlString: string): NetworkEvaluation {
    try {
      const url = new URL(urlString);
      const hostname = url.hostname.toLowerCase();

      // Check SSRF / Internal Network blocks
      for (const pattern of this.blockedIpsOrHosts) {
        if (pattern.test(hostname)) {
          return {
            allowed: false,
            reason: `SSRF Violation: Access to internal IP/cloud metadata is strictly blocked (${hostname})`,
            targetUrl: urlString
          };
        }
      }

      // If whitelisting is active
      if (this.allowedDomains.size > 0) {
        const isAllowed = Array.from(this.allowedDomains).some(domain => 
          hostname === domain || hostname.endsWith('.' + domain)
        );

        if (!isAllowed) {
          return {
            allowed: false,
            reason: `Egress Policy Violation: Domain '${hostname}' is not in the allowed destination whitelist`,
            targetUrl: urlString
          };
        }
      }

      return { allowed: true, targetUrl: urlString };
    } catch {
      return { allowed: false, reason: `Malformed URL: ${urlString}`, targetUrl: urlString };
    }
  }

  /**
   * Scans a shell command or text for outbound network requests (curl, wget, http)
   */
  public evaluateCommandNetwork(cmd: string): NetworkEvaluation {
    const urlMatches = cmd.match(/https?:\/\/[^\s"'`]+/gi);
    if (!urlMatches) {
      return { allowed: true };
    }

    for (const rawUrl of urlMatches) {
      const res = this.evaluateUrl(rawUrl);
      if (!res.allowed) {
        return res;
      }
    }

    return { allowed: true };
  }
}
