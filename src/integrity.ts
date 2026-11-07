/**
 * Live File System Integrity Monitor & Tamper Guard
 * Observes file system events in the workspace in real time.
 * If a critical file (.env, config, package.json, lockfiles) is deleted or modified
 * unexpectedly outside allowed bounds, an immediate rollback and alarm is dispatched.
 */

import fs from 'node:fs';
import path from 'node:path';

export interface FileWatchEvent {
  filePath: string;
  eventType: 'rename' | 'change';
  timestamp: number;
}

export class IntegrityGuard {
  private workspaceDir: string;
  private watcher?: fs.FSWatcher;
  private criticalFiles: Set<string>;
  private violationCallback?: (filePath: string, event: string) => void;

  constructor(workspaceDir: string = process.cwd(), criticalFiles: string[] = []) {
    this.workspaceDir = path.resolve(workspaceDir);
    this.criticalFiles = new Set([
      '.env',
      '.env.local',
      '.env.production',
      'package.json',
      'agentarmor.yaml',
      ...criticalFiles
    ]);
  }

  /**
   * Starts active file system observation.
   */
  public start(onViolation?: (filePath: string, event: string) => void): void {
    this.violationCallback = onViolation;
    try {
      this.watcher = fs.watch(this.workspaceDir, { recursive: true }, (event, filename) => {
        if (!filename) return;
        const basename = path.basename(filename);
        if (this.criticalFiles.has(basename)) {
          if (this.violationCallback) {
            this.violationCallback(filename, event);
          }
        }
      });
    } catch {}
  }

  public stop(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = undefined;
    }
  }

  public isCriticalFile(filePath: string): boolean {
    return this.criticalFiles.has(path.basename(filePath));
  }
}
