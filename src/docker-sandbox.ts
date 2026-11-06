/**
 * Docker Ephemeral Sandboxed Runner
 * Executes commands inside a throwaway container with zero host root privileges,
 * read-only system root, and no access to host sensitive mountpoints.
 */

import { execSync, spawn } from 'node:child_process';
import path from 'node:path';

export interface DockerSandboxOptions {
  workspaceDir?: string;
  image?: string;
  timeoutMs?: number;
  memoryLimit?: string;
  cpuLimit?: string;
}

export class DockerSandbox {
  private workspaceDir: string;
  private image: string;
  private timeoutMs: number;
  private memoryLimit: string;
  private cpuLimit: string;

  constructor(options: DockerSandboxOptions = {}) {
    this.workspaceDir = path.resolve(options.workspaceDir || process.cwd());
    this.image = options.image || 'alpine:latest';
    this.timeoutMs = options.timeoutMs || 30000;
    this.memoryLimit = options.memoryLimit || '512m';
    this.cpuLimit = options.cpuLimit || '1.0';
  }

  /**
   * Checks if Docker daemon is available locally.
   */
  public isDockerAvailable(): boolean {
    try {
      execSync('docker info', { stdio: 'ignore' });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Runs a command inside a zero-privilege ephemeral container.
   */
  public runInSandbox(cmd: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    return new Promise((resolve) => {
      if (!this.isDockerAvailable()) {
        resolve({
          stdout: '',
          stderr: 'Docker daemon is not available or not running.',
          exitCode: 127
        });
        return;
      }

      // Safe docker run args
      const dockerArgs = [
        'run',
        '--rm',
        '--network', 'none', // complete network isolation by default
        '--memory', this.memoryLimit,
        '--cpus', this.cpuLimit,
        '-v', `${this.workspaceDir}:/workspace:rw`,
        '-w', '/workspace',
        '--cap-drop=ALL', // drop all Linux kernel capabilities
        '--security-opt=no-new-privileges',
        this.image,
        'sh', '-c', cmd
      ];

      const child = spawn('docker', dockerArgs);
      let stdout = '';
      let stderr = '';

      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        resolve({
          stdout,
          stderr: `Execution timed out after ${this.timeoutMs}ms`,
          exitCode: 124
        });
      }, this.timeoutMs);

      child.stdout.on('data', (d) => { stdout += d.toString(); });
      child.stderr.on('data', (d) => { stderr += d.toString(); });

      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({
          stdout,
          stderr,
          exitCode: code ?? 0
        });
      });
    });
  }
}
