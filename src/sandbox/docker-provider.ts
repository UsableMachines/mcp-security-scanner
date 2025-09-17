/**
 * Docker-based sandbox provider for local development
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { SandboxProvider, SandboxConfig, SandboxResult } from './sandbox-provider';

const execAsync = promisify(exec);

export class DockerSandboxProvider extends SandboxProvider {
  name = 'docker';
  private containerPrefix = 'mcp-scanner';

  async initialize(): Promise<void> {
    // Build base sandbox image if it doesn't exist
    try {
      await execAsync('docker image inspect mcp-scanner-base');
    } catch {
      console.log('Building Docker sandbox image...');
      await this.buildSandboxImage();
    }
  }

  async cleanup(): Promise<void> {
    // Clean up any remaining containers
    try {
      const { stdout } = await execAsync(
        `docker ps -aq --filter "name=${this.containerPrefix}"`
      );
      if (stdout.trim()) {
        await execAsync(`docker rm -f ${stdout.trim().split('\n').join(' ')}`);
      }
    } catch (error) {
      console.warn('Docker cleanup warning:', error);
    }
  }

  async executeInSandbox(
    command: string,
    args: string[],
    config: SandboxConfig
  ): Promise<SandboxResult> {
    const containerId = `${this.containerPrefix}-${Date.now()}`;
    const startTime = Date.now();

    try {
      const dockerArgs = this.buildDockerArgs(containerId, config);
      const fullCommand = [command, ...args].join(' ');
      
      // Start container with monitoring
      const dockerCmd = [
        'docker run',
        '--name', containerId,
        ...dockerArgs,
        'alpine/git:latest',
        'sh', '-c',
        `'${fullCommand}'`
      ].join(' ');

      const { stdout, stderr } = await execAsync(dockerCmd);

      // Collect monitoring data
      const networkActivity = await this.extractNetworkActivity(containerId);
      const fileSystemActivity = await this.extractFileSystemActivity(containerId);
      const processActivity = await this.extractProcessActivity(containerId);

      return {
        exitCode: 0,
        stdout,
        stderr,
        networkActivity,
        fileSystemActivity,
        processActivity,
        duration: Date.now() - startTime
      };

    } catch (error: any) {
      return {
        exitCode: error.code || 1,
        stdout: '',
        stderr: error.message,
        networkActivity: [],
        fileSystemActivity: [],
        processActivity: [],
        duration: Date.now() - startTime
      };
    } finally {
      // Cleanup container
      try {
        await execAsync(`docker rm -f ${containerId}`);
      } catch {}
    }
  }

  /**
   * Clone repository using Docker volumes for isolation
   */
  async cloneWithGitImage(
    repoUrl: string,
    targetPath: string,
    config: SandboxConfig
  ): Promise<{ success: boolean; error?: string }> {
    const volumeName = `mcp-git-${Date.now()}`;

    try {
      // Step 1: Create Docker volume
      await execAsync(`docker volume create ${volumeName}`);

      // Step 2: Clone repository into volume using alpine/git
      const cloneCmd = [
        'docker run --rm',
        `-v ${volumeName}:${targetPath}`,
        'alpine/git:latest',
        'clone --depth=1',
        repoUrl,
        targetPath
      ].join(' ');

      const { stdout, stderr } = await execAsync(cloneCmd);

      if (stderr && !stderr.includes('Cloning into')) {
        // Cleanup volume on failure
        await execAsync(`docker volume rm ${volumeName}`).catch(() => {});
        return {
          success: false,
          error: stderr
        };
      }

      // Store volume name for later OSV scanning
      (this as any)._currentVolume = volumeName;

      return { success: true };
    } catch (error: any) {
      // Cleanup volume on failure
      await execAsync(`docker volume rm ${volumeName}`).catch(() => {});
      return {
        success: false,
        error: error.message || String(error)
      };
    }
  }

  /**
   * Scan repository using Google's OSV scanner with Docker volumes
   */
  async scanWithOSVImage(
    sourcePath: string,
    config: SandboxConfig
  ): Promise<{ success: boolean; results?: any; error?: string }> {
    const volumeName = (this as any)._currentVolume;

    if (!volumeName) {
      return {
        success: false,
        error: 'No volume available for scanning - clone repository first'
      };
    }

    try {
      // First, let's check what manifest files are available
      const listCmd = [
        'docker run --rm',
        `-v ${volumeName}:${sourcePath}`,
        'alpine:latest',
        'find', sourcePath,
        '-name "package*.json" -o -name "go.mod" -o -name "requirements.txt" -o -name "Cargo.toml" -o -name "pom.xml"'
      ].join(' ');

      const { stdout: manifestList } = await execAsync(listCmd);
      const manifestFiles = manifestList.trim().split('\n').filter(Boolean);

      if (manifestFiles.length === 0) {
        return {
          success: false,
          error: 'No supported manifest files found in repository'
        };
      }

      // Use the first manifest file found (prioritize package.json for MCP servers)
      const primaryManifest = manifestFiles.find(f => f.includes('package')) || manifestFiles[0];

      // Step 3: Run OSV scanner with the volume mounted
      const scanCmd = [
        'docker run --rm',
        `-v ${volumeName}:/src`,
        'ghcr.io/google/osv-scanner:latest',
        '--format=json',
        '-L', primaryManifest.replace(sourcePath, '/src')
      ].join(' ');

      const { stdout, stderr } = await execAsync(scanCmd);

      // OSV scanner returns non-zero exit code when vulnerabilities are found
      // So we need to parse stdout even if the command "failed"
      if (stdout.trim()) {
        try {
          const results = JSON.parse(stdout);
          return {
            success: true,
            results
          };
        } catch (parseError) {
          return {
            success: false,
            error: `Failed to parse OSV results: ${parseError}`
          };
        }
      } else {
        return {
          success: false,
          error: stderr || 'OSV scan produced no output'
        };
      }
    } catch (error: any) {
      // Check if error is due to no vulnerabilities found (which is actually success)
      if (error.message && error.message.includes('no vulnerabilities found')) {
        return {
          success: true,
          results: { results: [] }
        };
      }

      return {
        success: false,
        error: error.message || String(error)
      };
    }
    // Don't cleanup volume here - let it be cleaned up after dependency analysis
  }

  /**
   * Clean up the current Docker volume after dependency analysis is complete
   */
  async cleanupCurrentVolume(): Promise<void> {
    const volumeName = (this as any)._currentVolume;
    if (volumeName) {
      try {
        await execAsync(`docker volume rm ${volumeName}`);
        delete (this as any)._currentVolume;
      } catch (error) {
        console.warn('Warning: Failed to cleanup Docker volume:', error);
      }
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      await execAsync('docker --version');
      return true;
    } catch {
      return false;
    }
  }

  private buildDockerArgs(containerId: string, config: SandboxConfig): string[] {
    const args = [
      '--rm',
      '--detach=false',
      '--security-opt=no-new-privileges',
      '--cap-drop=ALL',
      '--read-only'
    ];

    if (config.memory) {
      args.push(`--memory=${config.memory}`);
    }
    
    if (config.cpu) {
      args.push(`--cpus=${config.cpu}`);
    }

    switch (config.network) {
      case 'none':
        args.push('--network=none');
        break;
      case 'isolated':
        args.push('--network=bridge', '--add-host=host.docker.internal:host-gateway');
        break;
      default:
        args.push('--network=none');
    }

    if (config.timeout) {
      args.push(`--stop-timeout=${config.timeout}`);
    }

    if (config.environment) {
      Object.entries(config.environment).forEach(([key, value]) => {
        args.push(`--env=${key}=${value}`);
      });
    }

    return args;
  }

  private async buildSandboxImage(): Promise<void> {
    const dockerfile = `
FROM node:18-alpine
RUN apk add --no-cache strace tcpdump
WORKDIR /sandbox
USER nobody
`;
    
    // Write Dockerfile and build
    await execAsync('mkdir -p .docker-build');
    require('fs').writeFileSync('.docker-build/Dockerfile', dockerfile);
    await execAsync('docker build -t mcp-scanner-base .docker-build/');
  }

  private async extractNetworkActivity(containerId: string): Promise<any[]> {
    // TODO: Implement network monitoring via tcpdump logs
    return [];
  }

  private async extractFileSystemActivity(containerId: string): Promise<any[]> {
    // TODO: Implement filesystem monitoring via strace logs  
    return [];
  }

  private async extractProcessActivity(containerId: string): Promise<any[]> {
    // TODO: Implement process monitoring
    return [];
  }

  /**
   * Scan Docker image using OSV Scanner Docker image
   */
  async scanDockerImageWithOSV(
    dockerImage: string,
    config: SandboxConfig = {}
  ): Promise<{ success: boolean; results?: any; error?: string }> {
    try {
      console.log(`Scanning Docker image: ${dockerImage} using OSV Scanner Docker image`);

      // Step 1: Pull the image
      console.log(`Pulling Docker image: ${dockerImage}`);
      await execAsync(`docker pull ${dockerImage}`, { timeout: 120000 });

      // Step 2: Save image as tar archive
      const tarFileName = `${dockerImage.replace(/[\/\:]/g, '_')}.tar`;
      const tarPath = `/tmp/${tarFileName}`;
      console.log(`Saving Docker image to tar: ${tarPath}`);
      await execAsync(`docker save -o ${tarPath} ${dockerImage}`, { timeout: 120000 });

      // Step 3: Scan the tar archive with OSV Scanner
      const scanCmd = [
        'docker run --rm',
        `-v ${tarPath}:/tmp/${tarFileName}`,
        'ghcr.io/google/osv-scanner:latest',
        'scan image',
        '--archive',
        '--format=json',
        `/tmp/${tarFileName}`
      ].join(' ');

      console.log(`Running OSV scan command: ${scanCmd}`);
      const { stdout, stderr } = await execAsync(scanCmd, { timeout: 180000 });

      // Cleanup tar file
      try {
        await execAsync(`rm ${tarPath}`);
      } catch (cleanupError) {
        console.warn(`Warning: Failed to cleanup tar file ${tarPath}:`, cleanupError);
      }

      if (stdout && stdout.trim()) {
        try {
          const results = JSON.parse(stdout);
          console.log(`OSV scan completed for ${dockerImage}`);
          return {
            success: true,
            results
          };
        } catch (parseError) {
          return {
            success: false,
            error: `Failed to parse OSV results: ${parseError}`
          };
        }
      } else {
        // No stdout might mean no vulnerabilities found
        return {
          success: true,
          results: { results: [] }
        };
      }
    } catch (error: any) {
      // Check if error is due to no vulnerabilities found (which is actually success)
      if (error.stdout && error.stdout.trim()) {
        try {
          const results = JSON.parse(error.stdout);
          console.log(`OSV scan completed for ${dockerImage} (found vulnerabilities)`);
          return {
            success: true,
            results
          };
        } catch (parseError) {
          // Fall through to error case
        }
      }

      return {
        success: false,
        error: error.message || String(error)
      };
    }
  }
}