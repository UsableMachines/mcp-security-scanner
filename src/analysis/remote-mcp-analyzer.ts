/**
 * Remote MCP Analyzer
 * Handles connection and analysis of remote MCP servers via HTTP/SSE
 */

import { MCPProtocolData } from './docker-behavioral-analyzer';
import { RemoteOAuthHandler, RemoteServerConfig } from './remote-oauth-handler';

export interface RemoteMCPAnalysisResult {
  serverName: string;
  serverUrl: string;
  executionSuccess: boolean;
  protocolData: MCPProtocolData;
  securityAnalysis: {
    risks: Array<{
      type: string;
      severity: 'critical' | 'high' | 'medium' | 'low';
      description: string;
      evidence: string[];
      toolName?: string;
      context: string;
      confidence?: number; // TODO: Confidence calculation feature requires investigation
    }>;
    summary: string;
    recommendations: string[];
  };
  executionMetrics: {
    connectionTime: number;
    responseTime: number;
    networkConnections: number;
    authMethod: string;
  };
}

export class RemoteMCPAnalyzer {
  private oauthHandler: RemoteOAuthHandler;

  constructor() {
    this.oauthHandler = new RemoteOAuthHandler();
  }

  /**
   * Analyze multiple remote MCP servers in parallel
   */
  async analyzeRemoteMCPServersInParallel(
    remoteConfigs: RemoteServerConfig[]
  ): Promise<RemoteMCPAnalysisResult[]> {
    console.log(`🌐 Starting parallel remote MCP analysis for ${remoteConfigs.length} servers...`);

    const analysisPromises = remoteConfigs.map(config =>
      this.analyzeRemoteMCPServer(config)
    );

    const results = await Promise.allSettled(analysisPromises);
    const successfulResults: RemoteMCPAnalysisResult[] = [];
    const failedAnalyses: string[] = [];

    for (const [index, result] of results.entries()) {
      if (result.status === 'fulfilled') {
        successfulResults.push(result.value);
        console.log(`✅ Remote analysis completed for: ${remoteConfigs[index].serverName}`);
      } else {
        const serverName = remoteConfigs[index].serverName;
        failedAnalyses.push(serverName);
        console.error(`❌ Remote analysis failed for ${serverName}:`, result.reason);
      }
    }

    if (failedAnalyses.length > 0) {
      console.warn(`⚠️ Failed to analyze ${failedAnalyses.length} remote servers: ${failedAnalyses.join(', ')}`);
    }

    console.log(`🌐 Parallel remote analysis complete: ${successfulResults.length}/${remoteConfigs.length} successful`);

    return successfulResults;
  }

  /**
   * Analyze a single remote MCP server
   */
  async analyzeRemoteMCPServer(config: RemoteServerConfig): Promise<RemoteMCPAnalysisResult> {
    console.log(`🔍 Analyzing remote MCP server: ${config.serverName} (${config.url})`);

    const startTime = Date.now();
    let authMethod = 'none';

    try {
      // Step 1: Handle OAuth authentication if needed
      let effectiveUrl = config.url;

      if (this.requiresAuthentication(config)) {
        console.log(`🔐 Authentication required for ${config.serverName}`);
        effectiveUrl = await this.oauthHandler.authenticateRemoteServer(config);
        authMethod = 'oauth2-proxy';
      }

      // Step 2: Connect to remote MCP server and capture protocol data
      const protocolData = await this.captureRemoteMCPProtocol(config, effectiveUrl);
      const connectionTime = Date.now() - startTime;

      // Step 3: Perform security analysis (reuse existing AI analysis)
      console.log(`🤖 Running security analysis on remote server data for ${config.serverName}...`);
      const securityAnalysis = await this.performSecurityAnalysis(config.serverName, protocolData);

      // Step 4: Calculate execution metrics
      const executionMetrics = {
        connectionTime,
        responseTime: connectionTime,
        networkConnections: 1, // The remote connection itself
        authMethod
      };

      return {
        serverName: config.serverName,
        serverUrl: config.url,
        executionSuccess: true,
        protocolData,
        securityAnalysis,
        executionMetrics
      };

    } catch (error) {
      console.warn(`❌ Remote MCP analysis failed for ${config.serverName}:`, error);

      return {
        serverName: config.serverName,
        serverUrl: config.url,
        executionSuccess: false,
        protocolData: {
          serverInfo: { name: config.serverName },
          tools: [],
          resources: [],
          prompts: [],
          executionLogs: [`Remote connection failed: ${error instanceof Error ? error.message : String(error)}`],
          networkActivity: [],
          fileSystemActivity: []
        },
        securityAnalysis: {
          risks: [{
            type: 'CONNECTION_FAILED',
            severity: 'high',
            description: `Failed to connect to remote MCP server: ${config.serverName}`,
            evidence: [error instanceof Error ? error.message : String(error)],
            context: 'connection_error',
            confidence: 1.0
          }],
          summary: `Connection failed for remote server "${config.serverName}"`,
          recommendations: ['Verify server URL and authentication credentials', 'Check network connectivity']
        },
        executionMetrics: {
          connectionTime: Date.now() - startTime,
          responseTime: 0,
          networkConnections: 0,
          authMethod: 'failed'
        }
      };
    }
  }

  /**
   * Connect to remote MCP server and capture protocol interactions
   */
  private async captureRemoteMCPProtocol(config: RemoteServerConfig, effectiveUrl: string): Promise<MCPProtocolData> {
    const { Client } = require('@modelcontextprotocol/sdk/client/index.js');

    let client: any = null;
    let transport: any = null;

    try {
      // Determine transport type based on URL and config
      const transportType = this.determineTransportType(config);

      if (transportType === 'sse') {
        // Server-Sent Events transport
        const { SSEClientTransport } = require('@modelcontextprotocol/sdk/client/sse.js');
        transport = new SSEClientTransport(new URL(effectiveUrl));
      } else {
        // HTTP Streaming transport (most common for remote servers)
        const { HttpClientTransport } = require('@modelcontextprotocol/sdk/client/http.js');
        transport = new HttpClientTransport(new URL(effectiveUrl));
      }

      // Create MCP client
      client = new Client(
        {
          name: 'mcp-security-scanner-remote',
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

      // Connect and perform MCP handshake
      console.log(`🤝 Establishing MCP connection to ${config.serverName} via ${transportType.toUpperCase()}...`);
      await client.connect(transport);

      // Discovery-only operations (no LLM, no tool execution)
      console.log(`🔍 Discovering remote server capabilities...`);

      const [toolsResult, resourcesResult, promptsResult] = await Promise.allSettled([
        client.listTools(),
        client.listResources(),
        client.listPrompts()
      ]);

      // Extract discovered capabilities
      const tools = toolsResult.status === 'fulfilled' ? toolsResult.value.tools || [] : [];
      const resources = resourcesResult.status === 'fulfilled' ? resourcesResult.value.resources || [] : [];
      const prompts = promptsResult.status === 'fulfilled' ? promptsResult.value.prompts || [] : [];

      console.log(`✅ Remote discovery complete: ${tools.length} tools, ${resources.length} resources, ${prompts.length} prompts`);

      // Get server info if available
      let serverInfo: any;
      try {
        serverInfo = await client.getServerInfo?.() || { name: config.serverName, url: config.url };
      } catch {
        serverInfo = { name: config.serverName, url: config.url };
      }

      return {
        serverInfo,
        tools,
        resources,
        prompts,
        executionLogs: [`MCP client connected successfully to remote server ${config.serverName}`],
        networkActivity: [{ method: 'MCP', url: effectiveUrl, timestamp: Date.now() }],
        fileSystemActivity: [] // Remote servers don't have direct filesystem access
      };

    } catch (error) {
      throw new Error(`Remote MCP connection failed: ${error}`);

    } finally {
      // Cleanup
      try {
        if (client) {
          await client.close();
        }
      } catch (error) {
        console.warn('Error closing remote MCP client:', error);
      }
    }
  }

  /**
   * Check if remote server requires authentication
   */
  private requiresAuthentication(config: RemoteServerConfig): boolean {
    // Check for authentication indicators in headers or config
    const hasAuthHeaders = config.headers && (
      Object.keys(config.headers).some(key =>
        key.toLowerCase().includes('authorization') ||
        key.toLowerCase().includes('auth') ||
        key.toLowerCase().includes('token')
      )
    );

    // Most remote MCP servers require authentication
    // Only skip auth for explicitly public servers
    const isPublicServer = config.config.public === true;

    return !isPublicServer || !!hasAuthHeaders;
  }

  /**
   * Determine transport type from config
   */
  private determineTransportType(config: RemoteServerConfig): 'http' | 'sse' {
    // Check explicit type in config
    if (config.type === 'sse' || config.type === 'server-sent-events') {
      return 'sse';
    }

    if (config.type === 'http' || config.type === 'streamableHttp') {
      return 'http';
    }

    // Check headers for SSE indicators
    const acceptHeader = config.headers?.['Accept'] || config.headers?.['accept'];
    if (acceptHeader && acceptHeader.includes('text/event-stream')) {
      return 'sse';
    }

    // Default to HTTP streaming (most common)
    return 'http';
  }

  /**
   * Perform security analysis on remote server data
   */
  private async performSecurityAnalysis(
    serverName: string,
    protocolData: MCPProtocolData
  ): Promise<RemoteMCPAnalysisResult['securityAnalysis']> {
    // Reuse existing AI analyzer logic
    const { AIAnalyzer } = require('./ai-analyzer');

    // Create a mock MCP configuration for AI analysis
    const mockMCPConfig = {
      name: serverName,
      tools: protocolData.tools || []
    };

    try {
      // Note: This assumes we have access to an AIAnalyzer instance
      // In practice, this would be passed in or properly instantiated
      const aiAnalyzer = new AIAnalyzer({});
      const analysis = await aiAnalyzer.analyzeMCPPromptSecurity(mockMCPConfig);

      // Enhance with remote-specific security insights
      const enhancedRisks = [...analysis.risks];

      // Add remote-specific security checks
      if (protocolData.networkActivity && protocolData.networkActivity.length > 0) {
        enhancedRisks.push({
          type: 'remote_data_access',
          severity: 'medium',
          description: `Remote MCP server "${serverName}" requires network access for operation`,
          evidence: protocolData.networkActivity.map(activity => `${activity.method} ${activity.url}`),
          context: 'remote_analysis',
          confidence: 0.9
        });
      }

      return {
        risks: enhancedRisks,
        summary: `Remote security analysis of MCP server "${serverName}": ${analysis.summary}`,
        recommendations: [
          'Verify remote server trustworthiness and data handling policies',
          'Monitor network requests in production environments',
          'Implement proper authentication and authorization controls',
          'Consider data privacy implications of remote MCP server usage'
        ]
      };

    } catch (error) {
      console.error('Remote security analysis failed:', error);

      return {
        risks: [{
          type: 'ANALYSIS_FAILED',
          severity: 'medium',
          description: `Security analysis failed for remote server "${serverName}"`,
          evidence: [error instanceof Error ? error.message : String(error)],
          context: 'analysis_error',
          confidence: 0.0
        }],
        summary: `Analysis failed for remote server "${serverName}" - manual review required`,
        recommendations: ['Manual security review required due to analysis failure']
      };
    }
  }

  /**
   * Cleanup OAuth handlers and connections
   */
  async cleanup(): Promise<void> {
    await this.oauthHandler.cleanup();
  }
}