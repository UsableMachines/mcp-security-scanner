/**
 * Sandbox manager that automatically selects and manages sandbox providers
 */

import { SandboxProvider, SandboxConfig, SandboxResult } from './sandbox-provider';
import { DockerSandboxProvider } from './docker-provider';
import { DaytonaSandboxProvider } from './daytona-provider';
import { configManager } from '../config';

export type SandboxProviderType = 'docker' | 'daytona' | 'auto';

export class SandboxManager {
  private providers: Map<string, SandboxProvider> = new Map();
  private activeProvider: SandboxProvider | null = null;

  constructor(private config: {
    preferredProvider?: SandboxProviderType;
    daytona?: {
      apiEndpoint: string;
      apiKey: string;
    };
  }) {
    this.initializeProviders();
  }

  async initialize(): Promise<void> {
    // Test provider availability and select best one
    const provider = await this.selectBestProvider();
    if (!provider) {
      throw new Error('No sandbox providers available');
    }

    this.activeProvider = provider;
    await provider.initialize();
    
    if (configManager.isDebugMode()) {
      console.log(`Initialized sandbox provider: ${provider.name}`);
    }
  }

  async cleanup(): Promise<void> {
    if (this.activeProvider) {
      await this.activeProvider.cleanup();
    }
  }

  async executeInSandbox(
    command: string,
    args: string[],
    config: SandboxConfig = {}
  ): Promise<SandboxResult> {
    if (!this.activeProvider) {
      throw new Error('Sandbox manager not initialized');
    }

    console.log(`Executing in ${this.activeProvider.name}: ${command} ${args.join(' ')}`);
    
    const result = await this.activeProvider.executeInSandbox(command, args, config);
    
    console.log(`Execution completed in ${result.duration}ms with exit code ${result.exitCode}`);
    
    return result;
  }

  getCurrentProvider(): string | null {
    return this.activeProvider?.name || null;
  }

  private initializeProviders(): void {
    // Always register Docker provider
    this.providers.set('docker', new DockerSandboxProvider());

    // Register Daytona provider if configured
    if (this.config.daytona) {
      this.providers.set('daytona', new DaytonaSandboxProvider(
        this.config.daytona.apiEndpoint,
        this.config.daytona.apiKey
      ));
    }
  }

  private async selectBestProvider(): Promise<SandboxProvider | null> {
    const preferred = this.config.preferredProvider;

    // If specific provider requested, try it first
    if (preferred && preferred !== 'auto' && this.providers.has(preferred)) {
      const provider = this.providers.get(preferred)!;
      if (await provider.isAvailable()) {
        return provider;
      } else {
        console.warn(`Preferred provider '${preferred}' not available, falling back to auto-select`);
      }
    }

    // Auto-select best available provider
    // Priority: Daytona (production) > Docker (dev)
    const providerOrder = ['daytona', 'docker'];
    
    for (const providerName of providerOrder) {
      const provider = this.providers.get(providerName);
      if (provider && await provider.isAvailable()) {
        return provider;
      }
    }

    return null;
  }

  // Utility method for MCP-specific sandbox execution
  async executeMCPServer(
    mcpServerPath: string,
    mcpConfig?: any,
    sandboxConfig: SandboxConfig = {}
  ): Promise<SandboxResult & { mcpAnalysis: any }> {
    // Enhanced config for MCP server analysis
    const config: SandboxConfig = {
      memory: '1G',
      timeout: 300, // 5 minutes
      network: 'isolated', // Allow monitored network access
      readonly: true,
      environment: {
        NODE_ENV: 'test',
        MCP_CONFIG: JSON.stringify(mcpConfig || {})
      },
      ...sandboxConfig
    };

    const result = await this.executeInSandbox('node', [mcpServerPath], config);

    // Analyze MCP-specific behavior from monitoring data
    const mcpAnalysis = this.analyzeMCPBehavior(result);

    return {
      ...result,
      mcpAnalysis
    };
  }

  private analyzeMCPBehavior(result: SandboxResult): any {
    return {
      suspiciousNetworkConnections: result.networkActivity.filter(activity => 
        activity.host !== 'localhost' && !activity.host.startsWith('127.')
      ),
      sensitiveFileAccess: result.fileSystemActivity.filter(activity =>
        activity.path.includes('passwd') || 
        activity.path.includes('shadow') ||
        activity.path.includes('.env') ||
        activity.path.includes('credentials')
      ),
      commandExecution: result.processActivity.filter(activity =>
        ['sh', 'bash', 'cmd', 'powershell', 'python', 'curl', 'wget'].includes(activity.command)
      ),
      // TODO: Add MCP protocol-specific analysis
      mcpToolDeclarations: [],
      mcpResourceExposure: [],
      suspiciousPatterns: []
    };
  }

  /**
   * Get the active sandbox provider for direct use
   */
  async getProvider(): Promise<SandboxProvider | null> {
    if (!this.activeProvider) {
      await this.initialize();
    }
    return this.activeProvider;
  }

  // MCP-specific deployment methods
  async createIsolatedEnvironment(): Promise<string> {
    await this.initialize();

    if (!this.activeProvider) {
      throw new Error('No active sandbox provider for creating isolated environment');
    }

    // Generate unique environment ID
    const envId = `mcp-env-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    return envId;
  }

  async deployMCPConfiguration(mcpConfig: any): Promise<any> {
    await this.initialize();

    if (!this.activeProvider) {
      throw new Error('No active sandbox provider for MCP deployment');
    }

    try {
      // Simulate MCP deployment by extracting servers and running them
      const results: any[] = [];

      for (const [serverName, config] of Object.entries(mcpConfig.mcpServers || {})) {
        console.log(`Deploying MCP server: ${serverName}`);

        const serverConfig = config as any;
        const result = await this.activeProvider.executeInSandbox(
          serverConfig.command || 'echo',
          serverConfig.args || [],
          {
            timeout: 30,
            environment: serverConfig.env || {}
          }
        );

        results.push({
          serverName,
          ...result
        });
      }

      // Combine all results
      const combinedResult = {
        deploymentSuccess: results.every(r => r.exitCode === 0),
        networkActivity: results.flatMap(r => r.networkActivity || []),
        processActivity: results.flatMap(r => r.processActivity || []),
        fileSystemActivity: results.flatMap(r => r.fileSystemActivity || []),
        servers: results.map(r => ({ name: r.serverName, exitCode: r.exitCode }))
      };

      return combinedResult;
    } catch (error) {
      throw new Error(`MCP deployment failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async captureTraffic(sandboxId: string): Promise<any> {
    // Implementation for traffic capture would go here
    // For now return empty structure
    return {
      connections: [],
      requests: [],
      responses: []
    };
  }

  /**
   * Scan Docker image for vulnerabilities using OSV Scanner
   */
  async scanDockerImageWithOSV(dockerImage: string): Promise<{
    vulnerabilities: Array<{
      id: string;
      severity?: string;
      summary: string;
      affected: Array<{
        package: { name: string; ecosystem: string };
        versions: string[];
      }>;
    }>;
    totalVulnerabilities: number;
    severityBreakdown: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  }> {
    if (!this.activeProvider) {
      throw new Error('Sandbox manager not initialized');
    }

    try {
      console.log(`Scanning Docker image: ${dockerImage}`);

      // Use the Docker provider's OSV scanning capability
      if (this.activeProvider?.name === 'docker') {
        const dockerProvider = this.activeProvider as any;
        if (dockerProvider.scanDockerImageWithOSV) {
          const scanResult = await dockerProvider.scanDockerImageWithOSV(dockerImage);

          if (!scanResult.success) {
            throw new Error(scanResult.error || 'Docker image OSV scan failed');
          }

          const osvData = scanResult.results;
          if (!osvData || !osvData.results || osvData.results.length === 0) {
            // No vulnerabilities found
            console.log(`✅ Docker image "${dockerImage}" - No vulnerabilities found`);
            return {
              vulnerabilities: [],
              totalVulnerabilities: 0,
              severityBreakdown: { critical: 0, high: 0, medium: 0, low: 0 }
            };
          }

          // Extract and categorize vulnerabilities
          const vulnerabilities = osvData.results || [];
          let critical = 0, high = 0, medium = 0, low = 0;

          const processedVulns = vulnerabilities.flatMap((result: any) => {
        return (result.packages || []).flatMap((pkg: any) => {
          return (pkg.vulnerabilities || []).map((vuln: any) => {
            // Categorize severity
            const severity = vuln.database_specific?.severity?.toLowerCase() || 'unknown';
            switch (severity) {
              case 'critical': critical++; break;
              case 'high': high++; break;
              case 'medium': medium++; break;
              case 'low': low++; break;
              default: medium++; // Default unknown to medium
            }

            return {
              id: vuln.id,
              severity: severity,
              summary: vuln.summary || 'No summary available',
              affected: vuln.affected || []
            };
          });
        });
      });

          const totalVulnerabilities = processedVulns.length;

          console.log(`OSV scan complete: ${totalVulnerabilities} vulnerabilities found (${critical} critical, ${high} high, ${medium} medium, ${low} low)`);

          return {
            vulnerabilities: processedVulns,
            totalVulnerabilities,
            severityBreakdown: { critical, high, medium, low }
          };
        } else {
          throw new Error('Docker provider does not support image OSV scanning');
        }
      } else {
        throw new Error('Docker image scanning is only supported with Docker sandbox provider');
      }

    } catch (error) {
      console.error(`Docker image OSV scan failed: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    }
  }
}