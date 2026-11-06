/**
 * Prompt Injection & Jailbreak Heuristics Detector
 * Analyzes unstructured text (prompts, tool outputs, web scraped content)
 * to detect adversarial injections before the agent acts on them.
 */

export interface InjectionDetectionResult {
  isInjection: boolean;
  score: number; // 0.0 to 1.0 (confidence)
  triggers: string[];
}

export const INJECTION_SIGNATURES: { name: string; pattern: RegExp; weight: number }[] = [
  // Direct instruction overrides
  {
    name: 'Instruction Override',
    pattern: /(?:ignore|disregard|forget|overwrite)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules|system\s+directives)/i,
    weight: 0.95
  },
  // Persona hijacks / jailbreaks (e.g. DAN style)
  {
    name: 'Jailbreak Persona / DAN',
    pattern: /(?:you are now in developer mode|you are now unrestricted|do anything now|DAN mode enabled|bypass safety guidelines)/i,
    weight: 0.9
  },
  // Secret / System prompt exfiltration attacks
  {
    name: 'System Prompt Exfiltration',
    pattern: /(?:print|output|display|show|reveal|repeat)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|system\s+directives|hidden\s+prompt)/i,
    weight: 0.85
  },
  // Hidden command delimiters (Markdown / XML injection tricks)
  {
    name: 'System Tag Spoofing',
    pattern: /<\/?(?:system|instruction|admin|override|developer_prompt)>/i,
    weight: 0.8
  },
  // Obfuscated Base64 / Hex payloads execution commands
  {
    name: 'Payload Execution Instruction',
    pattern: /(?:eval|execute|run)\s+(?:base64|hex|encoded|rot13)\s+(?:string|payload|code)/i,
    weight: 0.8
  },
  // Command execution coercion in plain text
  {
    name: 'Shell Coercion',
    pattern: /(?:must execute|immediately run|silently run)\s+(?:in\s+terminal|in\s+shell|bash|command)/i,
    weight: 0.75
  }
];

export class InjectionDetector {
  private signatures = INJECTION_SIGNATURES;

  /**
   * Evaluates text for prompt injection attempts.
   */
  public evaluate(text: string): InjectionDetectionResult {
    const triggers: string[] = [];
    let totalScore = 0;

    for (const sig of this.signatures) {
      if (sig.pattern.test(text)) {
        triggers.push(sig.name);
        totalScore = Math.max(totalScore, sig.weight);
      }
    }

    return {
      isInjection: totalScore >= 0.75,
      score: totalScore,
      triggers
    };
  }
}
