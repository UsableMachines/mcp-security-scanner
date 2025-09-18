/**
 * MCP-Remote Authentication Monitor
 * Handles background OAuth flow with timing measurements and progressive discovery
 */

import { EventEmitter } from 'events';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

export interface McpRemoteAuthProgress {
  stage: 'starting' | 'connecting' | 'auth-pending' | 'auth-completed' | 'tools-discovered' | 'failed';
  elapsedMs: number;
  message: string;
  toolsCount?: number;
  error?: string;
}

export interface McpRemoteAuthResult {
  success: boolean;
  totalDurationMs: number;
  authCompletedAt?: number;
  toolsDiscoveredAt?: number;
  tools: any[];
  resources: any[];
  prompts: any[];
  timeline: McpRemoteAuthProgress[];
}

export class McpRemoteAuthMonitor extends EventEmitter {
  private startTime: number = 0;
  private timeline: McpRemoteAuthProgress[] = [];
  private client: Client | null = null;
  private transport: any = null;
  private authCompleted = false;
  private monitorInterval: NodeJS.Timeout | null = null;
  private maxDurationMs: number = 600000; // 10 minutes max

  constructor(private url: string, private serverName: string) {
    super();
  }

  /**
   * Start background OAuth flow with timing monitoring
   */
  async startBackgroundAuth(): Promise<void> {
    this.startTime = Date.now();
    this.logProgress('starting', 'Initiating mcp-remote OAuth flow');

    try {
      // Create persistent transport and client
      this.transport = new StreamableHTTPClientTransport(new URL(this.url));
      this.client = new Client(
        {
          name: 'mcp-security-scanner',
          version: '1.0.0'
        },
        {
          capabilities: {
            tools: {},
            resources: {},
            prompts: {}
          }
        }
      );

      // Start connection in background (don't await)
      this.backgroundConnect();

      // Start monitoring progress
      this.startProgressMonitor();

    } catch (error) {
      this.logProgress('failed', `Failed to initialize: ${error}`);
    }
  }

  /**
   * Background connection attempt with retries
   */
  private async backgroundConnect(): Promise<void> {
    try {
      this.logProgress('connecting', 'Attempting MCP connection to mcp-remote proxy');

      // Connect client to transport
      await this.client!.connect(this.transport);

      this.logProgress('auth-pending', 'Connection established, OAuth flow in progress');

      // Initialize the client (this might trigger OAuth)
      // Note: Using any type to bypass strict schema validation for monitoring purposes
      const capabilities: any = await (this.client as any).request(
        { method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: { tools: {}, resources: {}, prompts: {} }, clientInfo: { name: 'mcp-security-scanner', version: '1.0.0' } } }
      );

      this.authCompleted = true;
      this.logProgress('auth-completed', 'OAuth authentication completed successfully');

      // Try to discover tools/resources
      await this.discoverCapabilities();

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.logProgress('failed', `Connection failed: ${errorMessage}`);
    }
  }

  /**
   * Discover tools, resources, and prompts after auth completes
   */
  private async discoverCapabilities(): Promise<void> {
    try {
      // Use any type to bypass schema validation for monitoring purposes
      const tools: any = await (this.client as any).request({ method: 'tools/list' });
      const resources: any = await (this.client as any).request({ method: 'resources/list' });
      const prompts: any = await (this.client as any).request({ method: 'prompts/list' });

      const toolsData = tools;
      const resourcesData = resources;
      const promptsData = prompts;

      const toolsCount = toolsData.tools?.length || 0;
      const resourcesCount = resourcesData.resources?.length || 0;
      const promptsCount = promptsData.prompts?.length || 0;

      this.logProgress('tools-discovered',
        `Discovered ${toolsCount} tools, ${resourcesCount} resources, ${promptsCount} prompts`,
        toolsCount
      );

      this.emit('capabilities-discovered', {
        tools: toolsData.tools || [],
        resources: resourcesData.resources || [],
        prompts: promptsData.prompts || []
      });

    } catch (error) {
      this.logProgress('auth-completed', 'Auth completed but tool discovery failed - server may have no capabilities');
    }
  }

  /**
   * Monitor progress and emit updates
   */
  private startProgressMonitor(): void {
    this.monitorInterval = setInterval(() => {
      const elapsed = Date.now() - this.startTime;

      // Emit progress update
      this.emit('progress', this.getCurrentProgress());

      // Check for timeout
      if (elapsed > this.maxDurationMs) {
        this.logProgress('failed', 'OAuth flow timed out after 10 minutes');
        this.stopMonitoring();
      }

      // Log milestone every 30 seconds
      if (elapsed % 30000 < 1000) {
        const minutes = Math.floor(elapsed / 60000);
        const seconds = Math.floor((elapsed % 60000) / 1000);
        console.log(`   ⏱️  mcp-remote OAuth monitor: ${minutes}m ${seconds}s elapsed...`);
      }

    }, 1000); // Check every second
  }

  /**
   * Log progress with timing
   */
  private logProgress(stage: McpRemoteAuthProgress['stage'], message: string, toolsCount?: number): void {
    const elapsed = Date.now() - this.startTime;
    const progress: McpRemoteAuthProgress = {
      stage,
      elapsedMs: elapsed,
      message,
      toolsCount
    };

    this.timeline.push(progress);
    console.log(`🔍 [${elapsed}ms] ${message}`);

    this.emit('progress', progress);

    // Log auth completion timing
    if (stage === 'auth-completed') {
      const minutes = Math.floor(elapsed / 60000);
      const seconds = Math.floor((elapsed % 60000) / 1000);
      console.log(`✅ mcp-remote OAuth completed in ${minutes}m ${seconds}s`);
    }
  }

  /**
   * Get current progress snapshot
   */
  private getCurrentProgress(): McpRemoteAuthProgress {
    const elapsed = Date.now() - this.startTime;
    const latestStage = this.timeline[this.timeline.length - 1]?.stage || 'starting';

    return {
      stage: latestStage,
      elapsedMs: elapsed,
      message: `OAuth monitoring: ${Math.floor(elapsed / 1000)}s elapsed`,
      toolsCount: this.timeline.find(t => t.toolsCount)?.toolsCount
    };
  }

  /**
   * Check if authentication has completed
   */
  isAuthCompleted(): boolean {
    return this.authCompleted;
  }

  /**
   * Get final results
   */
  getFinalResults(): McpRemoteAuthResult {
    const totalDuration = Date.now() - this.startTime;
    const authCompletedEntry = this.timeline.find(t => t.stage === 'auth-completed');
    const toolsDiscoveredEntry = this.timeline.find(t => t.stage === 'tools-discovered');

    return {
      success: this.authCompleted,
      totalDurationMs: totalDuration,
      authCompletedAt: authCompletedEntry?.elapsedMs,
      toolsDiscoveredAt: toolsDiscoveredEntry?.elapsedMs,
      tools: [], // Will be populated by capabilities discovery
      resources: [],
      prompts: [],
      timeline: [...this.timeline]
    };
  }

  /**
   * Stop monitoring and cleanup
   */
  async stopMonitoring(): Promise<McpRemoteAuthResult> {
    if (this.monitorInterval) {
      clearInterval(this.monitorInterval);
      this.monitorInterval = null;
    }

    if (this.client) {
      try {
        await this.client.close();
      } catch (error) {
        // Ignore cleanup errors
      }
    }

    return this.getFinalResults();
  }

  /**
   * Get current auth timing statistics
   */
  getAuthStats(): { elapsed: number, stage: string, isCompleted: boolean } {
    return {
      elapsed: Date.now() - this.startTime,
      stage: this.timeline[this.timeline.length - 1]?.stage || 'starting',
      isCompleted: this.authCompleted
    };
  }
}