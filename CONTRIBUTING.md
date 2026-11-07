# Contributing to AgentArmor

First off, thank you for considering contributing to **AgentArmor**! 🛡️  
As an open-source zero-trust runtime for autonomous AI agents, security, determinism, and performance are our highest priorities.

---

## 📜 Code of Conduct
We are committed to providing a friendly, safe, and welcoming environment for all contributors regardless of background or identity. Please be respectful and constructive in all discussions.

---

## 🛠️ Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/francaroscillidev-gif/agentarmor.git
   cd agentarmor
   ```

2. **Install dependencies:**
   ```bash
   bun install # or npm install
   ```

3. **Build TypeScript:**
   ```bash
   bun run build
   ```

4. **Run the test suite:**
   ```bash
   bun test # or npm test
   ```

---

## 🚀 Contribution Guidelines

- **Zero-Trust by Default:** Any new tool inspection or parser should fail closed (block/warn) rather than fail open.
- **Unit Tests Required:** Every new feature, heuristic, or security check must include accompanying unit tests in `src/tests/armor.test.ts`.
- **Zero Overhead:** Security evaluations must remain non-blocking and execute in sub-millisecond latency.
- **Git Commit Convention:** We follow Conventional Commits:
  - `feat:` New capability or security heuristic
  - `fix:` Bug fix in policy evaluation
  - `docs:` Documentation improvements
  - `test:` Additional test cases

---

## 🔒 Responsible Security Vulnerability Disclosure

If you discover a security vulnerability in AgentArmor itself, **please DO NOT open a public issue.**  
Instead, please email directly to:
📧 **[francaroscillidev@gmail.com](mailto:francaroscillidev@gmail.com)** with the subject `[SECURITY VULNERABILITY] AgentArmor`.
