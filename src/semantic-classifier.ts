/**
 * Semantic Vector & Fast Cosine Similarity Prompt Injection Classifier
 * Combines exact semantic distance metrics with known adversarial attack vectors.
 */

export interface SemanticVectorResult {
  isAttack: boolean;
  similarity: number;
  matchedCategory: string;
}

// Canonical high-entropy adversarial attack embeddings centroids (normalized TF-IDF token frequencies)
export const ADVERSARIAL_ATTACK_VECTORS: { category: string; tokens: Record<string, number> }[] = [
  {
    category: 'Jailbreak Persona Exfiltration',
    tokens: {
      ignore: 0.35, previous: 0.3, instructions: 0.3, system: 0.3, prompt: 0.3,
      developer: 0.25, override: 0.25, unrestricted: 0.25, dump: 0.2, bypass: 0.2
    }
  },
  {
    category: 'Privileged Shell Coercion',
    tokens: {
      sudo: 0.35, root: 0.3, terminal: 0.25, bash: 0.25, exec: 0.25,
      chmod: 0.2, passwd: 0.2, shadow: 0.2, curl: 0.15, wget: 0.15
    }
  },
  {
    category: 'Credential Exfiltration Tunnel',
    tokens: {
      webhook: 0.3, evil: 0.3, exfiltrate: 0.3, send: 0.2, keys: 0.25,
      post: 0.2, http: 0.15, pastebin: 0.25, token: 0.2, secret: 0.2
    }
  }
];

export class SemanticInjectionClassifier {
  /**
   * Tokenizes text into normalized frequency vector.
   */
  private vectorize(text: string): Record<string, number> {
    const words = text.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter(Boolean);
    const vec: Record<string, number> = {};
    if (words.length === 0) return vec;

    for (const w of words) {
      vec[w] = (vec[w] || 0) + 1;
    }
    // L2 normalize
    let norm = 0;
    for (const count of Object.values(vec)) norm += count * count;
    norm = Math.sqrt(norm);
    for (const k of Object.keys(vec)) vec[k] /= norm;
    return vec;
  }

  /**
   * Computes cosine similarity between two sparse vectors (0.0 to 1.0).
   */
  private cosineSimilarity(v1: Record<string, number>, v2: Record<string, number>): number {
    let dot = 0;
    for (const [k, val1] of Object.entries(v1)) {
      if (v2[k]) dot += val1 * v2[k];
    }
    return dot;
  }

  /**
   * Classifies input text against known adversarial vector profiles.
   */
  public classify(text: string, threshold = 0.45): SemanticVectorResult {
    const inputVec = this.vectorize(text);
    let maxSim = 0;
    let bestCat = 'Benign';

    for (const attack of ADVERSARIAL_ATTACK_VECTORS) {
      const sim = this.cosineSimilarity(inputVec, attack.tokens);
      if (sim > maxSim) {
        maxSim = sim;
        bestCat = attack.category;
      }
    }

    return {
      isAttack: maxSim >= threshold,
      similarity: Number(maxSim.toFixed(3)),
      matchedCategory: maxSim >= threshold ? bestCat : 'None'
    };
  }
}
