/**
 * Sandbox manager that automatically selects and manages sandbox providers
 */

import { SandboxProvider, SandboxConfig, SandboxResult } from './sandbox-provider';
import { DockerSandboxProvider } from './docker-provider';
import { DaytonaSandboxProvider } from './daytona-provider';

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
    
    console.log(`Initialized sandbox provider: ${provider.name}`);
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
}