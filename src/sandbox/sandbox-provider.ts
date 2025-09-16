/**
 * Pluggable sandbox provider interface
 * Supports Docker (local dev) and Daytona microVMs (production)
 */

export interface SandboxConfig {
  memory?: string;
  cpu?: string;
  network?: 'none' | 'isolated' | 'bridge';
  timeout?: number;
  readonly?: boolean;
  environment?: Record<string, string>;
}

export interface SandboxResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  networkActivity: NetworkActivity[];
  fileSystemActivity: FileSystemActivity[];
  processActivity: ProcessActivity[];
  duration: number;
}

export interface NetworkActivity {
  timestamp: Date;
  direction: 'outbound' | 'inbound';
  host: string;
  port: number;
  protocol: string;
}

export interface FileSystemActivity {
  timestamp: Date;
  operation: 'read' | 'write' | 'create' | 'delete';
  path: string;
  size?: number;
}

export interface ProcessActivity {
  timestamp: Date;
  command: string;
  args: string[];
  pid: number;
  parentPid?: number;
}

export interface GitCloneResult {
  success: boolean;
  repoPath: string;
  error?: string;
  duration: number;
}

export interface OSVScanResult {
  success: boolean;
  vulnerabilities: any[];
  scanOutput: string;
  error?: string;
  duration: number;
}

export abstract class SandboxProvider {
  abstract name: string;

  abstract initialize(): Promise<void>;
  abstract cleanup(): Promise<void>;

  abstract executeInSandbox(
    command: string,
    args: string[],
    config: SandboxConfig
  ): Promise<SandboxResult>;

  abstract isAvailable(): Promise<boolean>;

  /**
   * Clone a git repository using Docker volumes for isolation
   */
  async cloneRepository(
    repoUrl: string,
    targetPath: string = '/tmp/repo',
    config: SandboxConfig = {}
  ): Promise<GitCloneResult> {
    const startTime = Date.now();

    try {
      const result = await this.cloneWithGitImage(repoUrl, targetPath, config);
      const duration = Date.now() - startTime;

      if (result.success) {
        return {
          success: true,
          repoPath: targetPath,
          duration
        };
      } else {
        return {
          success: false,
          repoPath: targetPath,
          error: result.error || 'Unknown clone error',
          duration
        };
      }
    } catch (error) {
      return {
        success: false,
        repoPath: targetPath,
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Abstract method for cloning with git - must be implemented by providers
   */
  abstract cloneWithGitImage(
    repoUrl: string,
    targetPath: string,
    config: SandboxConfig
  ): Promise<{ success: boolean; error?: string }>;

  /**
   * Abstract method for scanning with OSV - must be implemented by providers
   */
  abstract scanWithOSVImage(
    sourcePath: string,
    config: SandboxConfig
  ): Promise<{ success: boolean; results?: any; error?: string }>;

  /**
   * Run OSV vulnerability scanner using Docker volumes for isolation
   */
  async runOSVScan(
    targetPath: string,
    config: SandboxConfig = {}
  ): Promise<OSVScanResult> {
    const startTime = Date.now();

    try {
      const scanResult = await this.scanWithOSVImage(targetPath, config);
      const duration = Date.now() - startTime;

      if (scanResult.success) {
        return {
          success: true,
          vulnerabilities: scanResult.results?.results || [],
          scanOutput: JSON.stringify(scanResult.results, null, 2),
          duration
        };
      } else {
        return {
          success: false,
          vulnerabilities: [],
          scanOutput: '',
          error: scanResult.error || 'OSV scan failed',
          duration
        };
      }
    } catch (error) {
      return {
        success: false,
        vulnerabilities: [],
        scanOutput: '',
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime
      };
    }
  }
}