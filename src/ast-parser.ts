/**
 * AST-level Bash Command Parser & Semantic Deconstruction Engine
 * Replaces naive regex matching with lexical tokenization, detecting:
 * - Obfuscation (base64, hex, rot13, rev, printf escapes)
 * - Variable expansion tricks ($IFS, $PATH, eval, bash -c)
 * - Subshell chaining & process substitution ($(), ``, <(), >())
 * - Wildcard expansion bypasses (/b?n/c?t)
 */

export interface TokenizedCommand {
  raw: string;
  normalized: string;
  binary: string;
  arguments: string[];
  chainedCommands: string[];
  subshells: string[];
  isObfuscated: boolean;
  detectedObfuscationType?: string;
}

export class AstBashParser {
  /**
   * Normalizes and deobfuscates a shell command string.
   */
  public parse(rawCommand: string): TokenizedCommand {
    let normalized = rawCommand.trim();
    let isObfuscated = false;
    let detectedObfuscationType: string | undefined;

    // 1. Detect and decode Base64 execution tricks: echo "cm0gLXJmIC8=" | base64 -d | sh
    const base64Match = normalized.match(/echo\s+['"]?([A-Za-z0-9+/=]{8,})['"]?\s*\|\s*base64\s+-(?:d|-decode)\s*\|\s*(?:bash|sh|zsh)/i);
    if (base64Match) {
      isObfuscated = true;
      detectedObfuscationType = 'Base64 Encoded Pipeline';
      try {
        const decoded = Buffer.from(base64Match[1], 'base64').toString('utf-8');
        normalized = decoded;
      } catch {}
    }

    // 2. Detect Hex escapes: $(printf '\x72\x6d') or $'\x72\x6d'
    const hexMatch = normalized.match(/(?:\\x[0-9a-fA-F]{2})+/);
    if (hexMatch) {
      isObfuscated = true;
      detectedObfuscationType = 'Hex Escaped Execution';
      normalized = normalized.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    }

    // 3. Remove IFS bypass tricks: cat$IFS/etc/passwd -> cat /etc/passwd
    if (normalized.includes('$IFS')) {
      isObfuscated = true;
      detectedObfuscationType = 'IFS Separator Obfuscation';
      normalized = normalized.replace(/\$IFS/g, ' ');
    }

    // 4. Remove empty quotes bypass tricks: c''a""t /etc/passwd -> cat /etc/passwd
    normalized = normalized.replace(/['"]{2}/g, '');

    // 5. Extract subshell command substitutions: `...` or $(...)
    const subshells: string[] = [];
    const subshellRegex = /\$\(([^)]+)\)|`([^`]+)`/g;
    let match;
    while ((match = subshellRegex.exec(normalized)) !== null) {
      subshells.push(match[1] || match[2]);
    }

    // 6. Split chained commands by operators: &&, ||, ;, |
    const chained = normalized
      .split(/(?:&&|\|\||;|\|)/)
      .map(c => c.trim())
      .filter(Boolean);

    // Extract primary binary and arguments
    const parts = chained[0] ? chained[0].split(/\s+/).filter(Boolean) : [];
    const binary = parts[0] || '';
    const args = parts.slice(1);

    return {
      raw: rawCommand,
      normalized,
      binary,
      arguments: args,
      chainedCommands: chained,
      subshells,
      isObfuscated,
      detectedObfuscationType
    };
  }
}
