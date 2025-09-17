/**
 * Docker Behavioral Analyzer
 * Executes Docker-based MCP servers in sandbox and analyzes their runtime behavior
 */

import { z } from 'zod';
import { SandboxManager } from '../sandbox/sandbox-manager';
import { AIAnalyzer } from './ai-analyzer';
import { configManager } from '../config';

// Schema for Docker MCP server configuration
const DockerMCPConfigSchema = z.object({
  serverName: z.string(),
  dockerImage: z.string(),
  dockerArgs: z.array(z.string()).optional(),
  environment: z.record(z.string(), z.string()).optional(),
  timeout: z.number().optional().default(60)
});

export type DockerMCPConfig = z.infer<typeof DockerMCPConfigSchema>;

// Schema for captured MCP protocol data
export const MCPProtocolDataSchema = z.object({
  serverInfo: z.object({
    name: z.string(),
    version: z.string().optional()
  }).optional(),
  tools: z.array(z.object({
    name: z.string(),
    description: z.string().optional(),
    inputSchema: z.any().optional()
  })).optional(),
  resources: z.array(z.object({
    uri: z.string(),
    name: z.string().optional(),
    description: z.string().optional()
  })).optional(),
  prompts: z.array(z.object({
    name: z.string(),
    description: z.string().optional(),
    arguments: z.any().optional()
  })).optional(),
  executionLogs: z.array(z.string()).optional(),
  networkActivity: z.array(z.object({
    method: z.string(),
    url: z.string(),
    timestamp: z.number()
  })).optional(),
  fileSystemActivity: z.array(z.object({
    operation: z.string(),
    path: z.string(),
    timestamp: z.number()
  })).optional()
});

export type MCPProtocolData = z.infer<typeof MCPProtocolDataSchema>;

export interface DockerBehavioralAnalysisResult {
  serverName: string;
  dockerImage: string;
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
      confidence: number;
    }>;
    summary: string;
    recommendations: string[];
  };
  executionMetrics: {
    startupTime: number;
    responseTime: number;
    memoryUsage?: number;
    networkConnections: number;
    fileOperations: number;
  };
}

export class DockerBehavioralAnalyzer {
  private sandboxManager: SandboxManager;
  private aiAnalyzer: AIAnalyzer;

  constructor(sandboxManager: SandboxManager, aiAnalyzer: AIAnalyzer) {
    this.sandboxManager = sandboxManager;
    this.aiAnalyzer = aiAnalyzer;
  }

  /**
   * Analyze multiple Docker MCP servers in parallel
   */
  async analyzeDockerMCPServersInParallel(
    dockerConfigs: DockerMCPConfig[]
  ): Promise<DockerBehavioralAnalysisResult[]> {
    console.log(`🐳 Starting parallel Docker behavioral analysis for ${dockerConfigs.length} servers...`);

    const analysisPromises = dockerConfigs.map(config =>
      this.analyzeDockerMCPServer(config)
    );

    const results = await Promise.allSettled(analysisPromises);
    const successfulResults: DockerBehavioralAnalysisResult[] = [];
    const failedAnalyses: string[] = [];

    for (const [index, result] of results.entries()) {
      if (result.status === 'fulfilled') {
        successfulResults.push(result.value);
        console.log(`✅ Docker analysis completed for: ${dockerConfigs[index].serverName}`);
      } else {
        const serverName = dockerConfigs[index].serverName;
        failedAnalyses.push(serverName);
        console.error(`❌ Docker analysis failed for ${serverName}:`, result.reason);
      }
    }

    if (failedAnalyses.length > 0) {
      console.warn(`⚠️ Failed to analyze ${failedAnalyses.length} Docker servers: ${failedAnalyses.join(', ')}`);
    }

    console.log(`🐳 Parallel Docker analysis complete: ${successfulResults.length}/${dockerConfigs.length} successful`);

    return successfulResults;
  }

  /**
   * Analyze a single Docker MCP server
   */
  async analyzeDockerMCPServer(config: DockerMCPConfig): Promise<DockerBehavioralAnalysisResult> {
    console.log(`🔍 Analyzing Docker MCP server: ${config.serverName} (${config.dockerImage})`);

    const startTime = Date.now();

    // Step 1: Execute Docker MCP server in sandbox and capture protocol data
    const protocolData = await this.captureDockerMCPProtocol(config);

    const executionTime = Date.now() - startTime;

    // Step 2: Perform AI security analysis on the captured protocol data
    console.log(`🤖 Running AI analysis on protocol data for ${config.serverName}...`);
    const securityAnalysis = await this.performAISecurityAnalysis(config.serverName, protocolData);

    // Step 3: Calculate execution metrics
    const executionMetrics = this.calculateExecutionMetrics(protocolData, executionTime);

    return {
      serverName: config.serverName,
      dockerImage: config.dockerImage,
      executionSuccess: true,
      protocolData,
      securityAnalysis,
      executionMetrics
    };
  }

  /**
   * Execute Docker MCP server and capture protocol interactions using proper MCP client
   */
  private async captureDockerMCPProtocol(config: DockerMCPConfig): Promise<MCPProtocolData> {
    const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
    const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');

    console.log(`🚀 Starting Docker MCP server: ${config.dockerImage}`);

    // Build Docker command for MCP server
    const dockerArgs = this.buildDockerMCPArgs(config);
    console.log(`🔍 Docker command: docker ${dockerArgs.join(' ')}`);

    let client: any = null;

    try {
      // Step 1: Create MCP client with stdio transport that will spawn the Docker process
      const transport = new StdioClientTransport({
        command: 'docker',
        args: dockerArgs,
        env: { ...process.env, ...config.environment }
      });

      client = new Client(
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

      // Step 2: Connect and perform MCP handshake
      console.log(`🤝 Establishing MCP connection to ${config.serverName}...`);
      await client.connect(transport);

      // Step 3: Discovery-only operations (no LLM, no tool execution)
      console.log(`🔍 Discovering server capabilities...`);

      const [toolsResult, resourcesResult, promptsResult] = await Promise.allSettled([
        client.listTools(),
        client.listResources(),
        client.listPrompts()
      ]);

      // Step 4: Extract discovered capabilities
      const tools = toolsResult.status === 'fulfilled' ? toolsResult.value.tools || [] : [];
      const resources = resourcesResult.status === 'fulfilled' ? resourcesResult.value.resources || [] : [];
      const prompts = promptsResult.status === 'fulfilled' ? promptsResult.value.prompts || [] : [];

      console.log(`✅ Discovery complete: ${tools.length} tools, ${resources.length} resources, ${prompts.length} prompts`);

      // Step 5: Get server info if available
      let serverInfo: any;
      try {
        serverInfo = await client.getServerInfo?.() || { name: config.serverName };
      } catch {
        serverInfo = { name: config.serverName };
      }

      return {
        serverInfo,
        tools,
        resources,
        prompts,
        executionLogs: [`MCP client connected successfully to ${config.serverName}`],
        networkActivity: [], // Could be enhanced with network monitoring
        fileSystemActivity: [] // Could be enhanced with filesystem monitoring
      };

    } catch (error) {
      console.warn(`❌ MCP connection failed for ${config.serverName}:`, error);

      // Return minimal protocol data for failed connection
      return {
        serverInfo: { name: config.serverName },
        tools: [],
        resources: [],
        prompts: [],
        executionLogs: [
          `MCP connection failed: ${error instanceof Error ? error.message : String(error)}`
        ],
        networkActivity: [],
        fileSystemActivity: []
      };

    } finally {
      // Step 6: Cleanup - close client connection
      try {
        if (client) {
          await client.close();
        }
      } catch (error) {
        console.warn('Error closing MCP client:', error);
      }
    }
  }

  /**
   * Detect authentication requirements and method for MCP server
   */
  private detectAuthRequirement(config: DockerMCPConfig): {
    requiresAuth: boolean;
    authMethod: 'api_key' | 'bearer_token' | 'oauth' | 'basic_auth' | 'unknown';
    authContext: {
      serviceName?: string;
      isObfuscated: boolean;
      supportsHeadlessAuth: boolean;
      authUrl?: string;
      envVarPatterns: string[];
    };
  } {
    const serverNameLower = config.serverName.toLowerCase();
    const envVars = Object.keys(config.environment || {});

    // Extract proxy package and URL information
    const mcpArgs = config.environment?.MCP_ARGS ? JSON.parse(config.environment.MCP_ARGS) : [];
    const remoteUrl = mcpArgs.find((arg: string) => arg.match(/^https?:\/\//));
    const proxyPackage = config.environment?.MCP_PROXY_PACKAGE;

    // Detect service-specific patterns
    const serviceDetection = this.detectServiceAuthMethod(serverNameLower, remoteUrl, proxyPackage);

    // Detect auth method from environment variables
    const envAuthMethod = this.detectAuthMethodFromEnv(envVars);

    // Check for auth obfuscation (proxy packages that hide auth flow)
    const isObfuscated = this.isAuthObfuscated(proxyPackage);

    // Determine if headless auth is supported
    const supportsHeadlessAuth = serviceDetection.authMethod !== 'oauth' || serviceDetection.hasApiKeyFallback;

    return {
      requiresAuth: serviceDetection.requiresAuth || envAuthMethod.requiresAuth,
      authMethod: serviceDetection.authMethod || envAuthMethod.authMethod,
      authContext: {
        serviceName: serviceDetection.serviceName,
        isObfuscated,
        supportsHeadlessAuth,
        authUrl: serviceDetection.authUrl,
        envVarPatterns: envAuthMethod.patterns
      }
    };
  }

  /**
   * Detect authentication requirements using pattern-based approach
   */
  private detectServiceAuthMethod(serverName: string, remoteUrl?: string, proxyPackage?: string): {
    requiresAuth: boolean;
    authMethod: 'api_key' | 'bearer_token' | 'oauth' | 'basic_auth' | 'unknown';
    serviceName?: string;
    authUrl?: string;
    hasApiKeyFallback: boolean;
  } {
    // Pattern-based detection - no hardcoding
    // If we have a remote URL, it likely needs authentication
    if (remoteUrl && remoteUrl.startsWith('https://')) {
      return {
        requiresAuth: true,
        authMethod: 'unknown', // Will be determined by env var analysis
        hasApiKeyFallback: true
      };
    }

    // Any proxy package suggests remote authentication
    if (proxyPackage) {
      return {
        requiresAuth: true,
        authMethod: 'unknown', // Will be determined by env var analysis
        hasApiKeyFallback: true
      };
    }

    return {
      requiresAuth: false,
      authMethod: 'unknown',
      hasApiKeyFallback: false
    };
  }

  /**
   * Detect authentication method from environment variable patterns
   */
  private detectAuthMethodFromEnv(envVars: string[]): {
    requiresAuth: boolean;
    authMethod: 'api_key' | 'bearer_token' | 'oauth' | 'basic_auth' | 'unknown';
    patterns: string[];
  } {
    const apiKeyPatterns = ['API_KEY', 'KEY', 'SECRET'];
    const bearerPatterns = ['TOKEN', 'ACCESS_TOKEN', 'BEARER'];
    const oauthPatterns = ['OAUTH', 'CLIENT_ID', 'CLIENT_SECRET'];
    const basicAuthPatterns = ['USERNAME', 'PASSWORD', 'USER', 'PASS'];

    const matchingPatterns: string[] = [];

    // Check for API key patterns
    const hasApiKey = envVars.some(envVar =>
      apiKeyPatterns.some(pattern => {
        if (envVar.toUpperCase().includes(pattern)) {
          matchingPatterns.push(`${envVar} (API_KEY pattern)`);
          return true;
        }
        return false;
      })
    );

    // Check for bearer token patterns
    const hasBearerToken = envVars.some(envVar =>
      bearerPatterns.some(pattern => {
        if (envVar.toUpperCase().includes(pattern)) {
          matchingPatterns.push(`${envVar} (BEARER_TOKEN pattern)`);
          return true;
        }
        return false;
      })
    );

    // Check for OAuth patterns
    const hasOAuth = envVars.some(envVar =>
      oauthPatterns.some(pattern => {
        if (envVar.toUpperCase().includes(pattern)) {
          matchingPatterns.push(`${envVar} (OAUTH pattern)`);
          return true;
        }
        return false;
      })
    );

    // Check for basic auth patterns
    const hasBasicAuth = envVars.some(envVar =>
      basicAuthPatterns.some(pattern => {
        if (envVar.toUpperCase().includes(pattern)) {
          matchingPatterns.push(`${envVar} (BASIC_AUTH pattern)`);
          return true;
        }
        return false;
      })
    );

    // Determine primary auth method
    let authMethod: 'api_key' | 'bearer_token' | 'oauth' | 'basic_auth' | 'unknown' = 'unknown';
    if (hasOAuth) authMethod = 'oauth';
    else if (hasBearerToken) authMethod = 'bearer_token';
    else if (hasApiKey) authMethod = 'api_key';
    else if (hasBasicAuth) authMethod = 'basic_auth';

    return {
      requiresAuth: matchingPatterns.length > 0,
      authMethod,
      patterns: matchingPatterns
    };
  }

  /**
   * Check if authentication flow is obfuscated by proxy package
   */
  private isAuthObfuscated(proxyPackage?: string): boolean {
    const obfuscatingPackages = [
      'mcp-remote', // Linear's obfuscating bridge
      // Add other packages known to completely hide auth flow
    ];

    const alteringButVisiblePackages = [
      'mcp-proxy',     // Sparfenyuk's proxy - alters but doesn't hide
      'fastmcp-proxy', // FastMCP proxy - transparent
      '@sparfenyuk/mcp-proxy'
    ];

    return obfuscatingPackages.some(pkg => proxyPackage?.includes(pkg));
  }

  /**
   * Handle authentication for MCP server based on detected method and context
   */
  private async handleAuthentication(config: DockerMCPConfig, authInfo: ReturnType<typeof this.detectAuthRequirement>): Promise<void> {
    // Special case: Linear's mcp-remote is fundamentally broken
    if (authInfo.authContext.serviceName === 'linear' && authInfo.authContext.isObfuscated) {
      await this.handleLinearMcpRemoteRejection(config);
      return;
    }

    // Handle auth obfuscation warning
    if (authInfo.authContext.isObfuscated) {
      console.log(`\n⚠️  AUTH OBFUSCATION WARNING`);
      console.log(`   Proxy package "${config.environment?.MCP_PROXY_PACKAGE}" completely hides authentication flow`);
      console.log(`   You cannot see what permissions are requested or how tokens are handled`);
      console.log(`   This poses significant security risks for credential theft and data exfiltration`);
    }

    // Handle OAuth challenge problem
    if (authInfo.authMethod === 'oauth' && !authInfo.authContext.supportsHeadlessAuth) {
      await this.handleUnsupportedOAuth(config, authInfo);
      return;
    }

    // Proceed with supported authentication
    await this.promptForAuthentication(config, authInfo);
  }

  /**
   * Handle Linear's mcp-remote - warn about broken OAuth but proceed with analysis
   */
  private async handleLinearMcpRemoteRejection(config: DockerMCPConfig): Promise<void> {
    console.log(`\n🚨 CRITICAL: Linear mcp-remote Bridge Detected`);
    console.log(`   This specific bridge is fundamentally broken and should be avoided.`);
    console.log(`\n❌ Known Issues with Linear's mcp-remote:`);
    console.log(`   • OAuth approval process is massively delayed`);
    console.log(`   • False positive connections without completing auth`);
    console.log(`   • Complete obfuscation of permission scopes`);
    console.log(`   • No visibility into token handling or storage`);
    console.log(`\n✅ RECOMMENDED ALTERNATIVES:`);
    console.log(`   • Use Linear's direct API with API keys: https://linear.app/settings/api`);
    console.log(`   • Use transparent proxy packages like mcp-proxy instead of mcp-remote`);
    console.log(`   • Implement direct Linear GraphQL integration`);

    console.log(`\n⚠️  WARNING: Proceeding with analysis of fundamentally flawed authentication bridge`);
    console.log(`   • Analysis will likely fail due to Linear's broken OAuth implementation`);
    console.log(`   • Security risks will be documented in final report`);
    console.log(`   • Consider this bridge unsuitable for production use`);
  }

  /**
   * Handle OAuth that cannot be performed headlessly
   */
  private async handleUnsupportedOAuth(config: DockerMCPConfig, authInfo: ReturnType<typeof this.detectAuthRequirement>): Promise<void> {
    console.log(`\n🔐 OAuth Authentication Challenge`);
    console.log(`   Service: ${authInfo.authContext.serviceName}`);
    console.log(`   Issue: OAuth requires web browser for authorization flow`);
    console.log(`   Sandbox: Cannot open web browser in containerized environment`);
    console.log(`\n💡 SOLUTIONS:`);
    console.log(`   1. Use API key instead of OAuth (if service supports it)`);
    console.log(`   2. Complete OAuth flow manually outside sandbox and provide tokens`);
    console.log(`   3. Skip authentication and analyze unauthenticated behavior`);

    const readline = require('readline');
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    const question = (prompt: string): Promise<string> => {
      return new Promise((resolve) => {
        rl.question(prompt, resolve);
      });
    };

    try {
      const choice = await question('\nChoose option (1=API key, 2=Manual tokens, 3=Skip auth): ');

      if (choice === '1' && authInfo.authContext.authUrl) {
        console.log(`\n🔑 API Key Authentication`);
        console.log(`   Get your API key from: ${authInfo.authContext.authUrl}`);
        const apiKey = await question('Enter API key: ');
        if (apiKey.trim()) {
          const keyName = `${authInfo.authContext.serviceName?.toUpperCase()}_API_KEY`;
          config.environment = config.environment || {};
          config.environment[keyName] = apiKey.trim();
          console.log(`✅ API key configured`);
        }
      } else if (choice === '2') {
        console.log(`\n🎫 Manual Token Entry`);
        console.log(`   Please complete OAuth flow manually and provide the resulting tokens`);
        const accessToken = await question('Access token: ');
        const refreshToken = await question('Refresh token (optional): ');

        if (accessToken.trim()) {
          config.environment = config.environment || {};
          config.environment['ACCESS_TOKEN'] = accessToken.trim();
          if (refreshToken.trim()) {
            config.environment['REFRESH_TOKEN'] = refreshToken.trim();
          }
          console.log(`✅ OAuth tokens configured`);
        }
      } else {
        console.log(`⚠️  Skipping authentication - analyzing unauthenticated behavior`);
      }
    } finally {
      rl.close();
    }
  }

  /**
   * Generic authentication prompting based on detected method
   */
  private async promptForAuthentication(config: DockerMCPConfig, authInfo: ReturnType<typeof this.detectAuthRequirement>): Promise<void> {
    const readline = require('readline');
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    const question = (prompt: string): Promise<string> => {
      return new Promise((resolve) => {
        rl.question(prompt, resolve);
      });
    };

    try {
      console.log(`\n🔐 Authentication Required`);
      console.log(`   Server: ${config.serverName}`);
      console.log(`   Service: ${authInfo.authContext.serviceName || 'Unknown'}`);
      console.log(`   Method: ${authInfo.authMethod.toUpperCase()}`);
      if (authInfo.authContext.authUrl) {
        console.log(`   Auth URL: ${authInfo.authContext.authUrl}`);
      }
      console.log(`   The server will run in an isolated sandbox environment for security.`);

      // Handle different authentication methods
      switch (authInfo.authMethod) {
        case 'api_key':
          await this.promptApiKey(config, authInfo, question);
          break;

        case 'bearer_token':
          await this.promptBearerToken(config, authInfo, question);
          break;

        case 'basic_auth':
          await this.promptBasicAuth(config, authInfo, question);
          break;

        case 'oauth':
          // OAuth with API key fallback (already handled in handleAuthentication)
          await this.promptApiKey(config, authInfo, question);
          break;

        default:
          await this.promptGenericAuth(config, authInfo, question);
          break;
      }

      console.log(`\n🚀 Proceeding with MCP server analysis in secure sandbox...`);

    } catch (error) {
      console.warn('Authentication prompting failed:', error);
    } finally {
      rl.close();
    }
  }

  private async promptApiKey(config: DockerMCPConfig, authInfo: ReturnType<typeof this.detectAuthRequirement>, question: (prompt: string) => Promise<string>): Promise<void> {
    console.log(`\n🔑 API Key Required`);
    if (authInfo.authContext.authUrl) {
      console.log(`   Get your API key from: ${authInfo.authContext.authUrl}`);
    }

    // Find the environment variable that needs the API key
    const envVars = Object.keys(config.environment || {});
    const apiKeyVar = envVars.find(varName =>
      varName.toUpperCase().includes('API') && varName.toUpperCase().includes('KEY')
    );

    const keyName = apiKeyVar || 'API_KEY';
    console.log(`   Variable: ${keyName}`);

    const apiKey = await question('Enter API key: ');

    if (apiKey.trim()) {
      config.environment = config.environment || {};
      config.environment[keyName] = apiKey.trim();
      console.log(`✅ API key configured`);
    } else {
      console.log(`⚠️  No API key provided - running without authentication`);
    }
  }

  private async promptBearerToken(config: DockerMCPConfig, authInfo: ReturnType<typeof this.detectAuthRequirement>, question: (prompt: string) => Promise<string>): Promise<void> {
    console.log(`\n🎫 Bearer Token Authentication`);
    const token = await question('Enter bearer token (or press Enter to skip): ');

    if (token.trim()) {
      const tokenName = authInfo.authContext.serviceName ?
        `${authInfo.authContext.serviceName.toUpperCase()}_TOKEN` : 'BEARER_TOKEN';
      config.environment = config.environment || {};
      config.environment[tokenName] = token.trim();
      console.log(`✅ Bearer token configured as ${tokenName}`);
    } else {
      console.log(`⚠️  Running without authentication - server may fail to connect`);
    }
  }

  private async promptBasicAuth(config: DockerMCPConfig, authInfo: ReturnType<typeof this.detectAuthRequirement>, question: (prompt: string) => Promise<string>): Promise<void> {
    console.log(`\n👤 Basic Authentication`);
    const username = await question('Enter username: ');
    const password = await question('Enter password: ');

    if (username.trim() && password.trim()) {
      config.environment = config.environment || {};
      config.environment['AUTH_USERNAME'] = username.trim();
      config.environment['AUTH_PASSWORD'] = password.trim();
      console.log(`✅ Basic auth credentials configured`);
    } else {
      console.log(`⚠️  Running without authentication - server may fail to connect`);
    }
  }

  private async promptGenericAuth(config: DockerMCPConfig, authInfo: ReturnType<typeof this.detectAuthRequirement>, question: (prompt: string) => Promise<string>): Promise<void> {
    console.log(`\n🔧 Authentication Required`);
    console.log(`   Detected patterns: ${authInfo.authContext.envVarPatterns.join(', ')}`);

    const keyName = await question('Environment variable name: ');
    const keyValue = await question('Value: ');

    if (keyName.trim() && keyValue.trim()) {
      config.environment = config.environment || {};
      config.environment[keyName.trim()] = keyValue.trim();
      console.log(`✅ Credential configured as ${keyName.trim()}`);
    } else {
      console.log(`⚠️  No credentials provided - running without authentication`);
    }
  }

  /**
   * Build Docker args array for MCP server execution (used with spawn)
   */
  private buildDockerMCPArgs(config: DockerMCPConfig): string[] {
    const args = ['run', '--rm', '-i'];

    // Add environment variables
    Object.entries(config.environment || {}).forEach(([key, value]) => {
      args.push('-e', `${key}=${value}`);
    });

    // Add the docker image
    args.push(config.dockerImage);

    return args;
  }

  /**
   * Build Docker run command for MCP server execution (legacy - for sandbox manager)
   */
  private buildDockerMCPCommand(config: DockerMCPConfig): string {
    const dockerArgs = config.dockerArgs || [];
    const envVars = config.environment || {};

    // Start with base docker run command
    let command = 'docker';

    // Check if this is a proxy server sandbox (generated by our system)
    const isProxySandbox = config.serverName.includes('-proxy-sandbox');

    if (isProxySandbox) {
      // For proxy servers, build a custom Docker command to execute the proxy package
      command = this.buildProxyServerDockerCommand(config);
    } else {
      // Original logic for native Docker MCP servers
      const runIndex = dockerArgs.findIndex(arg => arg === 'run');
      if (runIndex !== -1) {
        // Take all args from 'run' up to (but not including) the docker image
        const argsAfterRun = dockerArgs.slice(runIndex);

        // Remove the docker image from the args (it should be the last non-flag argument)
        const cleanArgs = [];
        const flagsWithValues = ['-e', '--env', '-v', '--volume', '-p', '--port', '--name', '--network', '--workdir', '-w', '--user', '-u'];

        for (let i = 0; i < argsAfterRun.length; i++) {
          const arg = argsAfterRun[i];

          // If this is the docker image, stop adding args
          if (!arg.startsWith('-') && arg !== 'run') {
            // Check if this might be a flag value
            if (i > 0) {
              const prevArg = argsAfterRun[i - 1];
              if (flagsWithValues.includes(prevArg)) {
                // This is a flag value, add it
                cleanArgs.push(arg);
                continue;
              }
            }
            // This is likely the docker image, stop here
            break;
          }

          cleanArgs.push(arg);

          // If this flag takes a value, also add the next argument
          if (flagsWithValues.includes(arg) && i + 1 < argsAfterRun.length) {
            i++; // Skip to the value
            const value = argsAfterRun[i];
            // Replace environment variable references with actual values
            if (arg === '-e' || arg === '--env') {
              const envValue = envVars[value] || value;
              cleanArgs.push(`${value}="${envValue}"`);
            } else {
              cleanArgs.push(value);
            }
          }
        }

        command += ' ' + cleanArgs.join(' ');
      } else {
        // Fallback: build basic docker run command
        command += ' run --rm';

        // Add environment variables
        Object.entries(envVars).forEach(([key, value]) => {
          command += ` -e ${key}="${value}"`;
        });
      }

      // Add the docker image
      command += ` ${config.dockerImage}`;
    }

    return command;
  }

  /**
   * Build Docker command specifically for proxy server execution
   */
  private buildProxyServerDockerCommand(config: DockerMCPConfig): string {
    const envVars = config.environment || {};

    // Extract the original MCP args from environment
    const mcpArgs = envVars.MCP_ARGS ? JSON.parse(envVars.MCP_ARGS) : [];
    const packageName = envVars.MCP_PROXY_PACKAGE || 'unknown';

    // Build Docker command to execute the proxy package in isolation
    let command = `docker run --rm --name mcp-${config.serverName}-${Date.now()}`;

    // Add environment variables
    Object.entries(envVars).forEach(([key, value]) => {
      command += ` -e "${key}=${value}"`;
    });

    // Enable networking for proxy servers (they need to connect to remote services)
    // But use custom network for monitoring
    command += ` --network bridge`;

    // Add volume for logging and monitoring
    command += ` -v /tmp/mcp-logs:/var/log/mcp`;

    // Use the appropriate base image
    command += ` ${config.dockerImage}`;

    // Execute the proxy command inside the container
    if (config.dockerImage.includes('node')) {
      // For Node.js containers, run npx command
      const argsString = mcpArgs.join(' ');
      command += ` sh -c "npx ${argsString} 2>&1 | tee /var/log/mcp/execution.log"`;
    } else if (config.dockerImage.includes('python')) {
      // For Python containers, run uvx command
      const argsString = mcpArgs.join(' ');
      command += ` sh -c "pip install uv && uvx ${argsString} 2>&1 | tee /var/log/mcp/execution.log"`;
    } else {
      // Fallback
      command += ` sh -c "echo 'Unknown proxy server type' && sleep 5"`;
    }

    console.log(`🔗 Proxy server Docker command: ${command}`);
    return command;
  }

  /**
   * Parse MCP protocol data from sandbox execution result
   */
  private parseMCPProtocolFromSandboxResult(sandboxResult: any): MCPProtocolData {
    const protocolData: MCPProtocolData = {
      serverInfo: undefined,
      tools: [],
      resources: [],
      prompts: [],
      executionLogs: [],
      networkActivity: [],
      fileSystemActivity: []
    };

    try {
      // Extract server info from stdout
      if (sandboxResult.stdout) {
        protocolData.executionLogs = sandboxResult.stdout.split('\n').filter((line: string) => line.trim());

        // Try to parse MCP server info and tools list from stdout
        const mcpData = this.extractMCPDataFromLogs(sandboxResult.stdout);
        protocolData.serverInfo = mcpData.serverInfo;
        protocolData.tools = mcpData.tools;
        protocolData.resources = mcpData.resources;
        protocolData.prompts = mcpData.prompts;
      }

      // Extract network activity from sandbox monitoring
      if (sandboxResult.networkActivity) {
        protocolData.networkActivity = sandboxResult.networkActivity;
      }

      // Extract file system activity from sandbox monitoring
      if (sandboxResult.fileSystemActivity) {
        protocolData.fileSystemActivity = sandboxResult.fileSystemActivity;
      }

    } catch (error) {
      console.warn('Failed to parse MCP protocol data:', error);
    }

    return protocolData;
  }

  /**
   * Extract MCP data from execution logs
   */
  private extractMCPDataFromLogs(logs: string): {
    serverInfo?: { name: string; version?: string };
    tools: Array<{ name: string; description?: string; inputSchema?: any }>;
    resources: Array<{ uri: string; name?: string; description?: string }>;
    prompts: Array<{ name: string; description?: string; arguments?: any }>;
  } {
    const result = {
      serverInfo: undefined as { name: string; version?: string } | undefined,
      tools: [] as Array<{ name: string; description?: string; inputSchema?: any }>,
      resources: [] as Array<{ uri: string; name?: string; description?: string }>,
      prompts: [] as Array<{ name: string; description?: string; arguments?: any }>
    };

    try {
      // Look for JSON-RPC MCP protocol messages in logs
      const lines = logs.split('\n');

      for (const line of lines) {
        try {
          // Try to parse each line as JSON (MCP protocol uses JSON-RPC)
          const json = JSON.parse(line);

          // Handle MCP protocol messages
          if (json.method === 'tools/list' && json.result) {
            result.tools = json.result.tools || [];
          } else if (json.method === 'resources/list' && json.result) {
            result.resources = json.result.resources || [];
          } else if (json.method === 'prompts/list' && json.result) {
            result.prompts = json.result.prompts || [];
          } else if (json.result && json.result.serverInfo) {
            result.serverInfo = json.result.serverInfo;
          }
        } catch {
          // Skip lines that aren't valid JSON
          continue;
        }
      }
    } catch (error) {
      console.warn('Error parsing MCP data from logs:', error);
    }

    return result;
  }

  /**
   * Perform AI security analysis on captured protocol data
   */
  private async performAISecurityAnalysis(
    serverName: string,
    protocolData: MCPProtocolData
  ): Promise<{
    risks: Array<{
      type: string;
      severity: 'critical' | 'high' | 'medium' | 'low';
      description: string;
      evidence: string[];
      toolName?: string;
      context: string;
      confidence: number;
    }>;
    summary: string;
    recommendations: string[];
  }> {
    // Create a mock MCP configuration from the protocol data for AI analysis
    const mockMCPConfig = {
      name: serverName,
      tools: protocolData.tools || []
    };

    try {
      // Use the existing MCP prompt security analysis from AIAnalyzer
      const analysis = await this.aiAnalyzer.analyzeMCPPromptSecurity(mockMCPConfig);

      // Enhance the analysis with Docker-specific behavioral insights
      const enhancedRisks = [...analysis.risks];

      // Add behavioral analysis based on network and file system activity
      if (protocolData.networkActivity && protocolData.networkActivity.length > 0) {
        enhancedRisks.push({
          type: 'data_exfiltration',
          severity: 'medium',
          description: `Docker MCP server "${serverName}" made ${protocolData.networkActivity.length} network connections during execution`,
          evidence: protocolData.networkActivity.slice(0, 5).map(activity => `${activity.method} ${activity.url}`),
          context: 'behavioral_analysis',
          confidence: 0.9
        });
      }

      if (protocolData.fileSystemActivity && protocolData.fileSystemActivity.length > 0) {
        const writeOperations = protocolData.fileSystemActivity.filter(activity =>
          activity.operation.includes('write') || activity.operation.includes('create')
        );

        if (writeOperations.length > 0) {
          enhancedRisks.push({
            type: 'sensitive_file_access',
            severity: 'high',
            description: `Docker MCP server "${serverName}" performed ${writeOperations.length} file system write operations`,
            evidence: writeOperations.slice(0, 3).map(activity => `${activity.operation}: ${activity.path}`),
            context: 'behavioral_analysis',
            confidence: 0.85
          });
        }
      }

      return {
        risks: enhancedRisks,
        summary: `Behavioral analysis of Docker MCP server "${serverName}": ${analysis.summary}`,
        recommendations: [
          'Monitor Docker container network activity in production',
          'Implement file system access controls for Docker MCP containers',
          'Consider running Docker containers in read-only mode where possible'
        ]
      };

    } catch (error) {
      console.error('AI security analysis failed:', error);

      return {
        risks: [{
          type: 'ANALYSIS_FAILED',
          severity: 'medium',
          description: `AI analysis failed for Docker server "${serverName}"`,
          evidence: [error instanceof Error ? error.message : String(error)],
          context: 'analysis_error',
          confidence: 0.0
        }],
        summary: `Analysis failed for "${serverName}" - manual review required`,
        recommendations: ['Manual security review required due to analysis failure']
      };
    }
  }

  /**
   * Calculate execution metrics from protocol data
   */
  private calculateExecutionMetrics(
    protocolData: MCPProtocolData,
    executionTime: number
  ): {
    startupTime: number;
    responseTime: number;
    memoryUsage?: number;
    networkConnections: number;
    fileOperations: number;
  } {
    return {
      startupTime: executionTime,
      responseTime: executionTime, // For now, same as startup time
      networkConnections: protocolData.networkActivity?.length || 0,
      fileOperations: protocolData.fileSystemActivity?.length || 0
    };
  }
}