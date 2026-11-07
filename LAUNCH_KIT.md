# AgentArmor v0.1.0 Official Launch Kit 🚀

This document contains everything you need to announce and showcase **AgentArmor** to the world.

---

## 1. 🌐 GitHub Official Release Summary

- **Repository:** https://github.com/francaroscillidev-gif/agentarmor
- **Tag:** `v0.1.0`
- **Release Title:** AgentArmor v0.1.0: Zero-Trust Security Gateway & Deterministic Sandbox for AI Agents & MCP
- **Author:** Franca Roscilli (francaroscillidev-gif)
- **License:** Apache 2.0

### Release Notes Markdown (for GitHub Releases tab):
```markdown
## 🛡️ AgentArmor v0.1.0: The Zero-Trust Security Gateway for AI Agents

We are thrilled to introduce the first official public release of **AgentArmor**!

### Key Highlights:
- **AST-Level Bash Deconstruction:** Unmasks Base64 pipelines, IFS evasions, hex encodings, and subshell injections before shell execution.
- **Data Loss Prevention (DLP):** Real-time automatic masking of OpenAI, AWS, GitHub, and private cryptographic keys.
- **Semantic Vector & Heuristic Prompt Injection Defense:** Stops instruction overrides, DAN persona hijacks, and system prompt exfiltrations.
- **Network Egress & SSRF Protection:** Blocks cloud metadata (169.254.169.254) and unauthorized private network probing.
- **SQL Injection & DDL Guard:** Intercepts `DROP TABLE`, `TRUNCATE`, and tautology injections before hitting database tools.
- **Canary Honeypot Deception Engine:** Traps rogue agent behaviors with zero false positives.
- **Multi-Tenant RBAC:** Fine-grained privilege tiers (`viewer`, `researcher`, `developer`, `devops`, `admin`).
- **Live Local Dashboard:** Real-time visual monitoring UI on `http://localhost:3456`.
- **Compliance & Standards:** Exports OASIS SARIF v2.1.0 for GitHub Security Code Scanning.

### Quick Start:
```bash
git clone https://github.com/francaroscillidev-gif/agentarmor.git
cd agentarmor
bun install && bun run build
node dist/cli.js benchmark
```
```

---

## 2. 🗞️ Hacker News (Show HN) Post

**Post Title:**  
`Show HN: AgentArmor – Open-source zero-trust security gateway and sandbox for AI agents & MCP`

**Post URL (or text body):**  
`https://github.com/francaroscillidev-gif/agentarmor`

**Text Body (if Text Post):**
```text
Hey HN,

I built AgentArmor (https://github.com/francaroscillidev-gif/agentarmor) because giving autonomous coding agents (Claude Code, Cursor, Cline, AutoGen) direct bash and tool execution rights is terrifying in production.

Traditional defenses rely on naive regexes that are easily bypassed via Base64 pipelines, IFS tricks, or indirect prompt injections from web scraping.

AgentArmor sits as a transparent, zero-latency layer between the LLM / MCP client and host execution:
1. Lexical AST Bash deconstruction to counter evasion tricks.
2. Bidirectional DLP that automatically redacts API keys (OpenAI, AWS, GitHub) before they leave your machine.
3. Network SSRF guard blocking AWS/GCP instance metadata (169.254.169.254) and internal subnet scanning.
4. Canary honeypots to detect unauthorized exfiltration with zero false positives.
5. Git-backed instant snapshot and 1-click rollback if an agent hallucinates.
6. A local real-time dashboard UI (port 3456).

It's completely open source under Apache 2.0. I'd love your feedback on the architecture, edge cases, and policy engine!
```

---

## 3. 🐦 X (Twitter) Launch Thread

**Tweet 1 (Hook):**  
> Giving autonomous AI agents shell & tool access is the future, but a single prompt injection or accidental `rm -rf` can destroy everything.
> 
> Introducing **AgentArmor** 🛡️: An open-source, zero-trust security gateway and sandbox for AI Agents & MCP.
> 
> 🔗 https://github.com/francaroscillidev-gif/agentarmor
> 
> Here is what it does 🧵👇

**Tweet 2 (Core Features):**  
> 1/ 🧬 **AST-Level Bash Parser:** Naive regexes miss `echo "..." | base64 -d | sh`. AgentArmor normalizes and deconstructs command trees before execution.
> 
> 2/ 🔒 **Instant DLP:** Automatically redacts OpenAI, Anthropic, AWS, and private SSH keys so they never leak into LLM prompts.

**Tweet 3 (SSRF & DB Guard):**  
> 3/ 🌐 **Egress & SSRF Firewall:** Blocks agents from pinging AWS/GCP metadata (`169.254.169.254`) or scanning local private ports.
> 
> 4/ 🗄️ **SQL Guard:** Intercepts `DROP TABLE`, `TRUNCATE`, and injection tautologies before touching database MCP tools.

**Tweet 4 (Call to Action):**  
> It also features canary honeypots, git-backed 1-click rollback, and a live web dashboard.
> 
> Built with TypeScript, tested, and 100% open source under Apache 2.0.
> 
> ⭐ Star the repo & check it out:  
> https://github.com/francaroscillidev-gif/agentarmor
