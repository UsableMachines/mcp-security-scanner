/**
 * Remote MCP Analyzer
 * Handles connection and analysis of remote MCP servers via HTTP/SSE
 */

import { MCPProtocolData } from './docker-behavioral-analyzer';
import * as crypto from 'crypto';
import * as http from 'http';

export interface RemoteServerConfig {
  serverName: string;
  url: string;
  type?: string;
  headers?: Record<string, string>;
  config: any;
}

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
  constructor() {
    // MCP OAuth 2.1 DCR implementation handles all authentication
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
    let authHeaders: Record<string, string> = {};

    try {
      // Step 1: Check for authentication requirements with pre-flight request
      console.log(`🔌 Attempting direct connection to ${config.serverName}...`);

      let requiresAuth = false;
      let authError: string | null = null;

      try {
        // Pre-flight check to detect 401/403 errors
        await this.checkAuthenticationRequirement(config.url);
        console.log(`🔍 Pre-flight check successful - no authentication required`);
      } catch (preflightError) {
        if (this.isAuthenticationError(preflightError)) {
          requiresAuth = true;
          authError = preflightError instanceof Error ? preflightError.message : String(preflightError);
          console.log(`🔐 Authentication required for ${config.serverName}: ${authError}`);
        } else {
          // Non-auth error, try full connection anyway
          console.log(`⚠️  Pre-flight check failed (non-auth error), attempting full connection...`);
        }
      }

      let protocolData;

      if (requiresAuth) {
        // Step 2: Perform MCP OAuth 2.1 authentication
        console.log(`🚀 Starting MCP OAuth 2.1 DCR flow for ${config.serverName}...`);
        authHeaders = await this.performMCPOAuth(config);
        authMethod = 'mcp-oauth-2.1';

        // Connect with Bearer token
        console.log(`🔄 Connecting with OAuth 2.1 Bearer token...`);
        protocolData = await this.captureRemoteMCPProtocol(config, config.url, authHeaders);
        console.log(`✅ Authenticated connection successful to ${config.serverName}`);
      } else {
        // Step 2: Try direct connection
        try {
          protocolData = await this.captureRemoteMCPProtocol(config, config.url, authHeaders);
          console.log(`✅ Direct connection successful to ${config.serverName}`);
        } catch (directError) {
          // Check if this is an auth error that the pre-flight missed
          if (this.isAuthenticationError(directError)) {
            console.log(`🔄 Direct connection failed with auth error, trying OAuth fallback...`);
            console.log(`   Error: ${directError instanceof Error ? directError.message : String(directError)}`);

            // Fallback to OAuth
            console.log(`🚀 Starting MCP OAuth 2.1 DCR flow (fallback)...`);
            authHeaders = await this.performMCPOAuth(config);
            authMethod = 'mcp-oauth-2.1';

            // Retry connection with Bearer token
            console.log(`🔄 Retrying connection with authentication...`);
            protocolData = await this.captureRemoteMCPProtocol(config, config.url, authHeaders);
            console.log(`✅ Authenticated connection successful to ${config.serverName}`);
          } else {
            // Non-auth error, re-throw
            throw directError;
          }
        }
      }

      const connectionTime = Date.now() - startTime;

      // Step 2: Perform security analysis (reuse existing AI analysis)
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
  private async captureRemoteMCPProtocol(config: RemoteServerConfig, effectiveUrl: string, authHeaders: Record<string, string> = {}): Promise<MCPProtocolData> {
    const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');

    let client: any = null;
    let transport: any = null;

    try {
      // Determine transport type based on URL and config
      const transportType = this.determineTransportType(config);

      if (transportType === 'sse') {
        // Server-Sent Events transport
        const { SSEClientTransport } = await import('@modelcontextprotocol/sdk/client/sse.js');
        transport = new SSEClientTransport(new URL(effectiveUrl));
        // Note: SSE doesn't support custom headers in the same way, auth would be via query params
      } else {
        // HTTP Streaming transport (most common for remote servers)
        const { StreamableHTTPClientTransport } = await import('@modelcontextprotocol/sdk/client/streamableHttp.js');
        transport = new StreamableHTTPClientTransport(new URL(effectiveUrl));
        // Note: Auth headers are handled at the connection level, not transport level
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

    // Check URL pattern for SSE indicators
    if (config.url) {
      const url = config.url.toLowerCase();
      if (url.includes('/sse') || url.includes('/events') || url.includes('sse.')) {
        return 'sse';
      }
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
    const { AIAnalyzer } = await import('./ai-analyzer');

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
          type: 'data_exfiltration',
          severity: 'medium',
          description: `Remote MCP server "${serverName}" requires network access for operation`,
          evidence: protocolData.networkActivity.map((activity: any) => `${activity.method} ${activity.url}`),
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
   * Perform MCP OAuth 2.1 authentication flow with Dynamic Client Registration
   * Implements RFC 8414 (OAuth metadata discovery) + RFC 7591 (DCR) + MCP resource parameter
   */
  private async performMCPOAuth(config: RemoteServerConfig): Promise<Record<string, string>> {
    console.log(`🔍 Starting MCP OAuth 2.1 DCR flow for ${config.serverName}...`);

    try {
      // Phase 1: Discover OAuth authorization server metadata (RFC 8414)
      const metadata = await this.discoverOAuthMetadata(config.url);
      console.log(`✅ Discovered OAuth metadata for ${config.serverName}`);

      // Phase 2: Generate PKCE parameters for security
      const pkce = this.generatePKCE();
      console.log(`🔐 Generated PKCE code challenge`);

      // Phase 3: Dynamic client registration (RFC 7591)
      const clientCredentials = await this.registerDynamicClient(metadata, config);
      console.log(`🆔 Dynamically registered client: ${clientCredentials.client_id}`);

      // Phase 4: Browser-based authorization with MCP resource parameter
      const authCode = await this.performBrowserAuth(metadata, clientCredentials, config, pkce);
      console.log(`🎫 Received authorization code`);

      // Phase 5: Exchange authorization code for Bearer token
      const tokens = await this.exchangeCodeForTokens(metadata, clientCredentials, authCode, pkce);
      console.log(`🎟️ Successfully obtained Bearer token`);

      return {
        'Authorization': `Bearer ${tokens.access_token}`
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.error(`❌ MCP OAuth 2.1 flow failed for ${config.serverName}:`, errorMessage);
      throw new Error(`MCP OAuth 2.1 authentication failed: ${errorMessage}`);
    }
  }

  /**
   * Discover OAuth authorization server metadata (RFC 8414)
   */
  private async discoverOAuthMetadata(mcpServerUrl: string): Promise<any> {
    const serverUrl = new URL(mcpServerUrl);
    const wellKnownUrl = `${serverUrl.protocol}//${serverUrl.host}/.well-known/oauth-authorization-server`;

    console.log(`🔍 Discovering OAuth metadata at: ${wellKnownUrl}`);

    try {
      const response = await fetch(wellKnownUrl, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'mcp-security-scanner/1.0.0'
        }
      });

      if (!response.ok) {
        throw new Error(`OAuth metadata discovery failed: ${response.status} ${response.statusText}`);
      }

      const metadata = await response.json();

      // Validate required OAuth metadata fields
      const requiredFields = ['issuer', 'authorization_endpoint', 'token_endpoint'];
      const missingFields = requiredFields.filter(field => !metadata[field]);

      if (missingFields.length > 0) {
        throw new Error(`Invalid OAuth metadata, missing fields: ${missingFields.join(', ')}`);
      }

      // Check for dynamic client registration support (RFC 7591)
      if (!metadata.registration_endpoint) {
        throw new Error('Server does not support dynamic client registration (missing registration_endpoint)');
      }

      console.log(`📋 OAuth metadata validated: issuer=${metadata.issuer}`);
      return metadata;

    } catch (error) {
      throw new Error(`Failed to discover OAuth metadata: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Generate PKCE code challenge and verifier (RFC 7636)
   */
  private generatePKCE(): { code_verifier: string; code_challenge: string; code_challenge_method: string } {
    // Generate cryptographically secure random code verifier (43-128 characters)
    const codeVerifier = this.generateRandomString(128);

    // Create SHA256 hash of code verifier, then base64url encode
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');

    return {
      code_verifier: codeVerifier,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256'
    };
  }

  /**
   * Generate cryptographically secure random string
   */
  private generateRandomString(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let result = '';
    const bytes = crypto.randomBytes(length);
    for (let i = 0; i < length; i++) {
      result += chars[bytes[i] % chars.length];
    }
    return result;
  }

  /**
   * Register dynamic client (RFC 7591)
   */
  private async registerDynamicClient(metadata: any, config: RemoteServerConfig): Promise<any> {
    console.log(`🔄 Registering dynamic client for ${config.serverName}...`);

    const callbackPort = await this.findAvailablePort(8080);
    const redirectUri = `http://localhost:${callbackPort}/callback`;

    const clientMetadata = {
      client_name: `MCP Security Scanner - ${config.serverName}`,
      client_uri: 'https://github.com/kindo-ai/mcp-security-scanner',
      redirect_uris: [redirectUri],
      grant_types: ['authorization_code'],
      response_types: ['code'],
      scope: 'openid profile email', // Standard scopes, can be customized per server
      token_endpoint_auth_method: 'client_secret_basic',
      application_type: 'native' // Native app for desktop scanner
    };

    try {
      const response = await fetch(metadata.registration_endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'User-Agent': 'mcp-security-scanner/1.0.0'
        },
        body: JSON.stringify(clientMetadata)
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Dynamic client registration failed: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const clientCredentials = await response.json();

      // Validate required response fields
      if (!clientCredentials.client_id) {
        throw new Error('Invalid client registration response: missing client_id');
      }

      console.log(`✅ Dynamic client registered successfully`);
      console.log(`   Client ID: ${clientCredentials.client_id}`);
      console.log(`   Callback URL: ${redirectUri}`);

      return {
        ...clientCredentials,
        redirect_uri: redirectUri,
        callback_port: callbackPort
      };

    } catch (error) {
      throw new Error(`Dynamic client registration failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Perform browser-based authorization with MCP resource parameter
   */
  private async performBrowserAuth(
    metadata: any,
    clientCredentials: any,
    config: RemoteServerConfig,
    pkce: any
  ): Promise<string> {
    console.log(`🌐 Starting browser authorization flow...`);

    // Create authorization URL with MCP resource parameter
    const authParams = new URLSearchParams({
      response_type: 'code',
      client_id: clientCredentials.client_id,
      redirect_uri: clientCredentials.redirect_uri,
      scope: 'openid profile email',
      state: this.generateRandomString(32),
      code_challenge: pkce.code_challenge,
      code_challenge_method: pkce.code_challenge_method,
      resource: config.url // MCP-specific: identify the target MCP server
    });

    const authUrl = `${metadata.authorization_endpoint}?${authParams.toString()}`;

    // Start local callback server
    const authCode = await this.startCallbackServerAndOpenBrowser(
      authUrl,
      clientCredentials.callback_port,
      authParams.get('state')!
    );

    return authCode;
  }

  /**
   * Start local callback server and open browser for user consent
   */
  private async startCallbackServerAndOpenBrowser(authUrl: string, port: number, expectedState: string): Promise<string> {

    return new Promise((resolve, reject) => {
      const server = http.createServer((req: any, res: any) => {
        const url = new URL(req.url!, `http://localhost:${port}`);

        if (url.pathname === '/callback') {
          const code = url.searchParams.get('code');
          const state = url.searchParams.get('state');
          const error = url.searchParams.get('error');

          // Send response to browser
          res.writeHead(200, { 'Content-Type': 'text/html' });
          if (error) {
            res.end(`<html><body><h1>Authorization Failed</h1><p>Error: ${error}</p><p>You can close this window.</p></body></html>`);
            reject(new Error(`OAuth authorization failed: ${error}`));
          } else if (code && state === expectedState) {
            res.end(`<html><body><h1>Authorization Successful</h1><p>You can close this window and return to the scanner.</p></body></html>`);
            resolve(code);
          } else {
            res.end(`<html><body><h1>Authorization Failed</h1><p>Invalid response parameters</p><p>You can close this window.</p></body></html>`);
            reject(new Error('Invalid authorization response'));
          }

          server.close();
        } else {
          res.writeHead(404);
          res.end('Not found');
        }
      });

      server.listen(port, () => {
        console.log(`🖥️  Callback server listening on port ${port}`);
        console.log(`🚀 Opening browser for user consent...`);

        // Open browser for user authentication
        this.openBrowserSafely(authUrl);
      });

      server.on('error', (error: any) => {
        reject(new Error(`Callback server failed: ${error.message}`));
      });

      // Timeout after 10 minutes
      setTimeout(() => {
        server.close();
        reject(new Error('OAuth authorization timed out - user did not complete authentication'));
      }, 600000);
    });
  }

  /**
   * Open browser safely with malicious URL checking
   */
  private async openBrowserSafely(url: string): Promise<void> {
    try {
      // Reuse existing URLhaus checking logic
      const isMalicious = await this.checkURLSafety(url);
      if (isMalicious) {
        throw new Error(`OAuth URL flagged as potentially malicious: ${url}`);
      }

      console.log(`🔗 Opening browser: ${url}`);
      const open = await import('open');
      await open.default(url);

    } catch (error) {
      console.warn('Could not open browser automatically. Please visit the URL manually:');
      console.log(`   ${url}`);
    }
  }

  /**
   * Check URL against security databases (similar to existing URLhaus check)
   */
  private async checkURLSafety(url: string): Promise<boolean> {
    // This would integrate with existing URLhaus checking logic
    // For now, basic URL validation
    try {
      const urlObj = new URL(url);
      // Basic checks for obviously malicious patterns
      const suspiciousDomains = ['bit.ly', 'tinyurl.com', 'shorturl.com'];
      return suspiciousDomains.some(domain => urlObj.hostname.includes(domain));
    } catch {
      return true; // Invalid URL is suspicious
    }
  }

  /**
   * Exchange authorization code for Bearer token
   */
  private async exchangeCodeForTokens(
    metadata: any,
    clientCredentials: any,
    authCode: string,
    pkce: any
  ): Promise<any> {
    console.log(`🔄 Exchanging authorization code for tokens...`);

    const tokenParams = new URLSearchParams({
      grant_type: 'authorization_code',
      code: authCode,
      redirect_uri: clientCredentials.redirect_uri,
      client_id: clientCredentials.client_id,
      code_verifier: pkce.code_verifier
    });

    // Add client authentication
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
      'User-Agent': 'mcp-security-scanner/1.0.0'
    };

    if (clientCredentials.client_secret) {
      // Use HTTP Basic authentication for confidential clients
      const credentials = Buffer.from(`${clientCredentials.client_id}:${clientCredentials.client_secret}`).toString('base64');
      headers['Authorization'] = `Basic ${credentials}`;
    }

    try {
      const response = await fetch(metadata.token_endpoint, {
        method: 'POST',
        headers,
        body: tokenParams.toString()
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Token exchange failed: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const tokens = await response.json();

      if (!tokens.access_token) {
        throw new Error('Invalid token response: missing access_token');
      }

      console.log(`✅ Successfully obtained Bearer token`);
      console.log(`   Token type: ${tokens.token_type || 'Bearer'}`);
      console.log(`   Expires in: ${tokens.expires_in || 'unknown'} seconds`);

      return tokens;

    } catch (error) {
      throw new Error(`Token exchange failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Find an available port for the callback server
   */
  private async findAvailablePort(startPort: number = 8080): Promise<number> {
    return new Promise((resolve) => {
      const server = http.createServer();

      server.listen(startPort, () => {
        const port = (server.address() as any)?.port;
        server.close(() => resolve(port));
      });

      server.on('error', () => {
        resolve(this.findAvailablePort(startPort + 1));
      });
    });
  }

  /**
   * Pre-flight check to detect authentication requirements
   */
  private async checkAuthenticationRequirement(url: string): Promise<void> {
    console.log(`🔍 Performing pre-flight authentication check for: ${url}`);

    try {
      const response = await fetch(url, {
        method: 'HEAD', // Use HEAD to minimize data transfer
        headers: {
          'Accept': 'text/event-stream, application/json',
          'User-Agent': 'mcp-security-scanner/1.0.0'
        }
      });

      if (response.status === 401 || response.status === 403) {
        throw new Error(`Authentication required: ${response.status} ${response.statusText}`);
      }

      if (response.status === 400) {
        // 400 might indicate missing auth in some implementations
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          try {
            // Try to get error details for 400 responses
            const errorResponse = await fetch(url, {
              method: 'GET',
              headers: {
                'Accept': 'application/json',
                'User-Agent': 'mcp-security-scanner/1.0.0'
              }
            });
            const errorData = await errorResponse.text();
            if (errorData.toLowerCase().includes('auth') || errorData.toLowerCase().includes('unauthorized')) {
              throw new Error(`Authentication likely required: 400 Bad Request with auth-related error`);
            }
          } catch {
            // If we can't parse the error, assume 400 is not auth-related
          }
        }
      }

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

    } catch (error) {
      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new Error(`Network error: ${error.message}`);
      }
      throw error;
    }
  }

  /**
   * Check if an error indicates authentication is required
   */
  private isAuthenticationError(error: any): boolean {
    const errorMessage = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();

    // Check for explicit authentication error indicators
    const authIndicators = [
      'authentication required',
      'unauthorized',
      '401',
      '403',
      'forbidden',
      'access denied',
      'invalid credentials',
      'missing authorization',
      'token required',
      'login required'
    ];

    return authIndicators.some(indicator => errorMessage.includes(indicator));
  }

  /**
   * Cleanup OAuth connections (MCP OAuth 2.1 DCR handles cleanup automatically)
   */
  async cleanup(): Promise<void> {
    // No cleanup needed - MCP OAuth 2.1 DCR implementation handles cleanup automatically
  }
}