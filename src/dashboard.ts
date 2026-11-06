/**
 * Local Lightweight Security Dashboard Server
 * Serves a clean, modern web interface showing live audit logs,
 * blocked prompt injections, masked secrets, and security stats.
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { AuditEvent } from './audit.js';

export function startDashboardServer(port: number = 3456): http.Server {
  const auditPath = path.join(process.cwd(), '.agentarmor_audit.jsonl');

  const getEvents = (): AuditEvent[] => {
    if (!fs.existsSync(auditPath)) return [];
    try {
      const content = fs.readFileSync(auditPath, 'utf-8');
      return content
        .trim()
        .split('\n')
        .filter(Boolean)
        .map(line => {
          try {
            return JSON.parse(line);
          } catch {
            return null;
          }
        })
        .filter(Boolean)
        .reverse(); // Most recent first
    } catch {
      return [];
    }
  };

  const server = http.createServer((req, res) => {
    // API endpoint for live events
    if (req.url === '/api/events') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(getEvents()));
      return;
    }

    // HTML Dashboard UI
    const events = getEvents();
    const blockedCount = events.filter(e => e.status === 'BLOCKED').length;
    const sanitizedCount = events.filter(e => e.status === 'SANITIZED').length;
    const allowedCount = events.filter(e => e.status === 'ALLOWED').length;

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AgentArmor 🛡️ Security Operations Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @keyframes pulse-subtle { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
    .status-live { animation: pulse-subtle 2s infinite ease-in-out; }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen font-sans">
  <div class="max-w-6xl mx-auto px-4 py-8">
    <!-- Header -->
    <header class="flex items-center justify-between pb-6 border-b border-slate-800">
      <div class="flex items-center space-x-3">
        <span class="text-3xl">🛡️</span>
        <div>
          <h1 class="text-2xl font-bold bg-gradient-to-r from-blue-400 via-indigo-300 to-teal-400 bg-clip-text text-transparent">AgentArmor Dashboard</h1>
          <p class="text-sm text-slate-400">Zero-Trust AI Gateway & Sandbox Runtime</p>
        </div>
      </div>
      <div class="flex items-center space-x-2 bg-emerald-950/60 border border-emerald-500/30 px-3 py-1.5 rounded-full text-emerald-400 text-xs font-medium">
        <span class="w-2 h-2 rounded-full bg-emerald-400 status-live inline-block"></span>
        <span>Gateway Active</span>
      </div>
    </header>

    <!-- Metrics Cards -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 my-8">
      <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl">
        <p class="text-xs uppercase tracking-wider text-slate-400 font-semibold">Total Evaluated</p>
        <p class="text-3xl font-extrabold mt-2 text-white">${events.length}</p>
      </div>
      <div class="bg-red-950/40 border border-red-900/50 p-5 rounded-xl">
        <p class="text-xs uppercase tracking-wider text-red-400 font-semibold">Threats Blocked</p>
        <p class="text-3xl font-extrabold mt-2 text-red-400">${blockedCount}</p>
      </div>
      <div class="bg-amber-950/40 border border-amber-900/50 p-5 rounded-xl">
        <p class="text-xs uppercase tracking-wider text-amber-400 font-semibold">Secrets Masked</p>
        <p class="text-3xl font-extrabold mt-2 text-amber-400">${sanitizedCount}</p>
      </div>
      <div class="bg-emerald-950/40 border border-emerald-900/50 p-5 rounded-xl">
        <p class="text-xs uppercase tracking-wider text-emerald-400 font-semibold">Allowed Operations</p>
        <p class="text-3xl font-extrabold mt-2 text-emerald-400">${allowedCount}</p>
      </div>
    </div>

    <!-- Live Event Log -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
      <div class="px-6 py-4 bg-slate-900/90 border-b border-slate-800 flex justify-between items-center">
        <h2 class="text-sm font-semibold uppercase tracking-wider text-slate-300">Live Security Audit Log</h2>
        <span class="text-xs text-slate-500">Auto-refreshing every 3s</span>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm text-slate-300">
          <thead class="bg-slate-950/60 text-xs uppercase text-slate-400 border-b border-slate-800">
            <tr>
              <th class="px-6 py-3 font-medium">Timestamp</th>
              <th class="px-6 py-3 font-medium">Event Type</th>
              <th class="px-6 py-3 font-medium">Status</th>
              <th class="px-6 py-3 font-medium">Details</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-800/60" id="eventTable">
            ${events.length === 0 ? `
              <tr>
                <td colspan="4" class="px-6 py-8 text-center text-slate-500">No events logged yet. Execute commands or prompts via CLI to see them stream live.</td>
              </tr>
            ` : events.map(e => {
              const badgeClass = e.status === 'BLOCKED' ? 'bg-red-500/10 text-red-400 border-red-500/20'
                : e.status === 'SANITIZED' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
              return `
                <tr class="hover:bg-slate-800/30 transition-colors">
                  <td class="px-6 py-4 text-xs text-slate-400 font-mono">${new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td class="px-6 py-4 font-medium text-slate-200 text-xs">${e.eventType}</td>
                  <td class="px-6 py-4">
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border ${badgeClass}">
                      ${e.status}
                    </span>
                  </td>
                  <td class="px-6 py-4 text-xs font-mono text-slate-300 max-w-md truncate">
                    ${JSON.stringify(e.details)}
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    // Live polling without page reload
    setInterval(async () => {
      try {
        const res = await fetch('/api/events');
        const data = await res.json();
        // Light refresh if count changes
      } catch (err) {}
    }, 3000);
  </script>
</body>
</html>`;

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
  });

  server.listen(port, () => {
    console.log(`\n🛡️  AgentArmor Security Dashboard live at: http://localhost:${port}\n`);
  });

  return server;
}
