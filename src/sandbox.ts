/**
 * Git-backed Snapshot and Instant Rollback Runner
 * Before an agent executes potentially dangerous multi-file edits or commands,
 * an automated shadow branch / stash point is created.
 */

import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export interface SnapshotMeta {
  id: string;
  timestamp: number;
  commitHash?: string;
  description: string;
}

export class SandboxManager {
  private workspaceDir: string;
  private snapshots: SnapshotMeta[] = [];

  constructor(workspaceDir: string = process.cwd()) {
    this.workspaceDir = workspaceDir;
  }

  /**
   * Checks if workspace is a git repo.
   */
  public isGitRepo(): boolean {
    return fs.existsSync(path.join(this.workspaceDir, '.git'));
  }

  /**
   * Creates an instantaneous safety checkpoint.
   */
  public createCheckpoint(description: string = 'Agent session checkpoint'): SnapshotMeta {
    const id = `aa_snap_${Date.now()}`;
    const meta: SnapshotMeta = {
      id,
      timestamp: Date.now(),
      description
    };

    if (this.isGitRepo()) {
      try {
        // Create an untracked stash/commit tag to save full working state
        execSync('git add -A', { cwd: this.workspaceDir, stdio: 'pipe' });
        const hash = execSync(`git write-tree`, { cwd: this.workspaceDir, encoding: 'utf-8' }).trim();
        meta.commitHash = hash;
      } catch (err) {
        // Fallback or warning
      }
    }

    this.snapshots.push(meta);
    return meta;
  }

  /**
   * Reverts all changes back to the specified checkpoint or the most recent one.
   */
  public rollback(snapshotId?: string): boolean {
    if (!this.isGitRepo()) {
      return false;
    }

    try {
      const snap = snapshotId 
        ? this.snapshots.find(s => s.id === snapshotId)
        : this.snapshots[this.snapshots.length - 1];

      if (snap?.commitHash) {
        execSync(`git read-tree --reset -u ${snap.commitHash}`, { cwd: this.workspaceDir, stdio: 'pipe' });
        return true;
      } else {
        execSync('git reset --hard HEAD && git clean -fd', { cwd: this.workspaceDir, stdio: 'pipe' });
        return true;
      }
    } catch (err) {
      return false;
    }
  }

  public getSnapshots(): SnapshotMeta[] {
    return [...this.snapshots];
  }
}
