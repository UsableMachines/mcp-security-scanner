/**
 * Parallel Analysis Orchestrator
 * Manages concurrent execution of multiple security analysis components
 */

import { z } from 'zod';
import { configManager } from '../config';
import { SandboxManager } from '../sandbox/sandbox-manager';
import { AIAnalyzer, type SecurityAnalysis } from './ai-analyzer';
import { DependencyAnalyzer, type DependencyAnalysisResult } from './dependency-analyzer';
import { MCPJsonAnalyzer, type MCPJsonAnalysis } from './mcp-json-analyzer';
import { getServersFromConfig } from './mcp-config-schema';
import { DockerBehavioralAnalyzer, type DockerBehavioralAnalysisResult, type DockerMCPConfig } from './docker-behavioral-analyzer';
import { OSVService } from '../services/osv-service';

// Analysis task types for parallel execution
export interface AnalysisTask {
  name: string;
  type: 'dependency' | 'source_code' | 'mcp_prompt' | 'behavioral' | 'mcp_json';
  priority: number; // Lower number = higher priority
  estimatedDuration: number; // Estimated duration in ms
}

export interface ParallelAnalysisResult {
  dependencyAnalysis?: DependencyAnalysisResult;
  sourceCodeAnalysis?: {
    vulnerabilities: Array<{
      type: string;
      severity: string;
      line: number;
      description: string;
      code: string;
    }>;
    suggestions: string[];
  };
  mcpPromptSecurityAnalysis?: {
    serverName: string;
    totalTools: number;
    risks: Array<{
      type: string;
      severity: string;
      description: string;
      evidence: string[];
      toolName?: string;
      context: string;
      confidence?: number; // TODO: Confidence calculation feature requires investigation
    }>;
    summary: string;
  };
  behavioralAnalysis?: SecurityAnalysis;
  mcpJsonAnalysis?: MCPJsonAnalysis;
  dockerBehavioralAnalysis?: DockerBehavioralAnalysisResult[];
  executionMetrics: {
    totalDuration: number;
    parallelSavings: number; // Time saved vs sequential execution
    taskDurations: Record<string, number>;
    concurrencyLevel: number;
  };
}

export class ParallelAnalysisOrchestrator {
  private sandboxManager: SandboxManager;
  private aiAnalyzer: AIAnalyzer;
  private dependencyAnalyzer: DependencyAnalyzer;
  private mcpJsonAnalyzer: MCPJsonAnalyzer;
  private dockerBehavioralAnalyzer: DockerBehavioralAnalyzer;
  private osvService: OSVService;

  constructor(
    sandboxManager: SandboxManager,
    aiAnalyzer: AIAnalyzer,
    dependencyAnalyzer: DependencyAnalyzer,
    mcpJsonAnalyzer: MCPJsonAnalyzer,
    osvService: OSVService
  ) {
    this.sandboxManager = sandboxManager;
    this.aiAnalyzer = aiAnalyzer;
    this.dependencyAnalyzer = dependencyAnalyzer;
    this.mcpJsonAnalyzer = mcpJsonAnalyzer;
    this.dockerBehavioralAnalyzer = new DockerBehavioralAnalyzer(sandboxManager, aiAnalyzer);
    this.osvService = osvService;
  }

  /**
   * Execute static analysis tasks in parallel after repository clone
   */
  async executeParallelStaticAnalysis(
    sourceCodeUrl: string,
    options: {
      skipDependencyAnalysis?: boolean;
      timeout?: number;
    } = {}
  ): Promise<ParallelAnalysisResult> {
    const startTime = Date.now();
    console.log('🚀 Starting parallel static analysis...');

    // First, ensure repository is cloned and volume is ready
    const sandboxProvider = await this.sandboxManager.getProvider();
    if (!sandboxProvider) {
      throw new Error('No sandbox provider available for parallel analysis');
    }

    // Clone repository once for all static analysis tasks
    console.log('📦 Cloning repository for parallel analysis...');
    const cloneStart = Date.now();

    // Use dependency analyzer to handle the clone since it already has the logic
    if (!options.skipDependencyAnalysis) {
      await this.dependencyAnalyzer.analyzeRemoteRepository(sourceCodeUrl, sandboxProvider);
    } else {
      // If skipping dependency analysis, we still need to clone the repo
      await this.cloneRepositoryForAnalysis(sourceCodeUrl, sandboxProvider);
    }

    const cloneTime = Date.now() - cloneStart;
    console.log(`📦 Repository clone completed in ${cloneTime}ms`);

    // Get the volume name for parallel tasks
    const volumeName = (sandboxProvider as any)._currentVolume;
    if (!volumeName) {
      throw new Error('No Docker volume available after repository clone');
    }

    // Define parallel tasks
    const tasks: Promise<{ type: string; result: any; duration: number }>[] = [];
    const taskStartTimes: Record<string, number> = {};

    // Task 1: Dependency Analysis (if not already done during clone)
    if (!options.skipDependencyAnalysis) {
      tasks.push(this.executeTask('dependency', async () => {
        console.log('🔍 [Parallel] Running OSV dependency scan...');
        // The dependency analysis was already done during clone, so we can reuse the result
        // This task is essentially a no-op since clone already includes OSV scan
        return null; // Will be populated from clone result
      }));
    }

    // Task 2: Source Code Analysis
    tasks.push(this.executeTask('source_code', async () => {
      console.log('🔍 [Parallel] Running AI source code analysis...');
      return await this.performParallelSourceCodeAnalysis(volumeName);
    }));

    // Task 3: MCP Prompt Security Analysis
    tasks.push(this.executeTask('mcp_prompt', async () => {
      console.log('🔍 [Parallel] Running MCP prompt security analysis...');
      return await this.performParallelMCPPromptAnalysis(volumeName);
    }));

    // Execute all tasks in parallel
    console.log(`🔄 Executing ${tasks.length} analysis tasks in parallel...`);
    const parallelStart = Date.now();

    const results = await Promise.allSettled(tasks);

    const parallelTime = Date.now() - parallelStart;
    console.log(`✅ Parallel execution completed in ${parallelTime}ms`);

    // Process results and handle any failures
    const analysisResults: Partial<ParallelAnalysisResult> = {};
    const taskDurations: Record<string, number> = {};
    let failedTasks: string[] = [];

    for (const [index, result] of results.entries()) {
      if (result.status === 'fulfilled') {
        const { type, result: taskResult, duration } = result.value;
        taskDurations[type] = duration;

        switch (type) {
          case 'source_code':
            analysisResults.sourceCodeAnalysis = taskResult;
            break;
          case 'mcp_prompt':
            analysisResults.mcpPromptSecurityAnalysis = taskResult;
            break;
        }

        console.log(`✅ ${type} analysis completed in ${duration}ms`);
      } else {
        const taskType = `task_${index}`;
        failedTasks.push(taskType);
        console.error(`❌ Task ${taskType} failed:`, result.reason);
      }
    }

    // Get dependency analysis result from the clone operation if it was performed
    if (!options.skipDependencyAnalysis) {
      // The dependency analysis result should be available from the initial clone
      // We need to extract it from the dependency analyzer's last result
      try {
        analysisResults.dependencyAnalysis = (this.dependencyAnalyzer as any)._lastResult;
        if (analysisResults.dependencyAnalysis) {
          taskDurations['dependency'] = cloneTime; // Use clone time as proxy
          console.log(`✅ dependency analysis from clone in ${cloneTime}ms`);
        }
      } catch (error) {
        console.warn('Could not retrieve dependency analysis result:', error);
      }
    }

    // Calculate performance metrics
    const totalDuration = Date.now() - startTime;
    const estimatedSequentialTime = Object.values(taskDurations).reduce((sum, duration) => sum + duration, 0);
    const parallelSavings = estimatedSequentialTime - parallelTime;

    // Clean up Docker volume
    try {
      if (typeof (sandboxProvider as any).cleanupCurrentVolume === 'function') {
        await (sandboxProvider as any).cleanupCurrentVolume();
        console.log('🧹 Docker volume cleanup complete');
      }
    } catch (error) {
      console.warn('Docker volume cleanup failed:', error);
    }

    console.log(`📊 Parallel analysis metrics:`);
    console.log(`   Total time: ${totalDuration}ms`);
    console.log(`   Parallel execution: ${parallelTime}ms`);
    console.log(`   Estimated sequential: ${estimatedSequentialTime}ms`);
    console.log(`   Time savings: ${parallelSavings}ms (${Math.round(parallelSavings / estimatedSequentialTime * 100)}%)`);

    if (failedTasks.length > 0) {
      console.warn(`⚠️  Failed tasks: ${failedTasks.join(', ')}`);
    }

    return {
      ...analysisResults,
      executionMetrics: {
        totalDuration,
        parallelSavings,
        taskDurations,
        concurrencyLevel: tasks.length
      }
    } as ParallelAnalysisResult;
  }

  /**
   * Execute behavioral analysis separately (requires MCP server execution)
   */
  async executeBehavioralAnalysis(
    mcpServerPath: string,
    options: { timeout?: number } = {}
  ): Promise<SecurityAnalysis | undefined> {
    console.log('🔍 Running behavioral analysis (sandbox execution)...');
    const startTime = Date.now();

    try {
      // Validate MCP server path
      if (mcpServerPath === 'static-analysis-only') {
        console.log('⚠️  Behavioral analysis skipped: Static-only analysis mode');
        return undefined;
      }

      const timeout = options.timeout || configManager.config.SCANNER_TIMEOUT;

      // Execute MCP server in sandbox
      const sandboxResult = await this.sandboxManager.executeMCPServer(
        mcpServerPath,
        undefined,
        { timeout: timeout / 1000 }
      );

      if (sandboxResult.exitCode !== 0) {
        throw new Error(`MCP server execution failed with exit code ${sandboxResult.exitCode}`);
      }

      // Analyze results with AI
      const analysis = await this.aiAnalyzer.analyzeMCPSecurity(
        sandboxResult,
        undefined,
        undefined
      );

      const duration = Date.now() - startTime;
      console.log(`✅ Behavioral analysis completed in ${duration}ms`);

      return analysis;

    } catch (error) {
      console.error('❌ Behavioral analysis failed:', error);
      throw error;
    }
  }

  /**
   * Execute enhanced MCP JSON analysis with parallel Docker behavioral analysis
   */
  async executeMCPJsonAnalysis(mcpJsonConfig: any, options: { apiKey?: string; allowMcpRemote?: boolean } = {}): Promise<MCPJsonAnalysis & { dockerBehavioralAnalysis?: DockerBehavioralAnalysisResult[] }> {
    // Removed chatty debug message
    const startTime = Date.now();

    try {
      // Step 1: Categorize servers by type
      const { dockerConfigs, remoteConfigs } = this.categorizeServers(mcpJsonConfig);

      // Step 1.5: Inject API key if provided via CLI
      if (options.apiKey && dockerConfigs.length > 0) {
        const updatedDockerConfigs = this.injectApiKeyIntoConfigs(dockerConfigs, options.apiKey);
        dockerConfigs.splice(0, dockerConfigs.length, ...updatedDockerConfigs);
      }

      // Step 2: Run analyses in parallel
      const tasks = [];

      // Traditional JSON analysis
      tasks.push(this.executeTask('json_analysis', async () => {
        return await this.mcpJsonAnalyzer.analyzeMCPConfiguration(mcpJsonConfig);
      }));

      // Docker behavioral analysis (if Docker servers or proxy servers found)
      if (dockerConfigs.length > 0) {
        tasks.push(this.executeTask('docker_behavioral', async () => {
          const nativeDockerCount = dockerConfigs.filter(config => !config.serverName.includes('-proxy-sandbox')).length;
          const proxyServerCount = dockerConfigs.filter(config => config.serverName.includes('-proxy-sandbox')).length;

          if (nativeDockerCount > 0 && proxyServerCount > 0) {
            console.log(`🐳 Found ${nativeDockerCount} Docker MCP servers + ${proxyServerCount} proxy servers for behavioral analysis`);
          } else if (nativeDockerCount > 0) {
            console.log(`🐳 Found ${nativeDockerCount} Docker MCP servers for behavioral analysis`);
          } else {
            console.log(`🔗 Created ${proxyServerCount} Docker sandboxes for proxy server behavioral analysis`);
          }

          return await this.dockerBehavioralAnalyzer.analyzeDockerMCPServersInParallel(dockerConfigs, { allowMcpRemote: options.allowMcpRemote });
        }));
      }

      // Remote MCP server analysis (if remote servers found)
      if (remoteConfigs.length > 0) {
        tasks.push(this.executeTask('remote_mcp_analysis', async () => {
          console.log(`🌐 Found ${remoteConfigs.length} remote MCP servers for behavioral analysis`);
          const { RemoteMCPAnalyzer } = require('./remote-mcp-analyzer');
          const remoteAnalyzer = new RemoteMCPAnalyzer();
          return await remoteAnalyzer.analyzeRemoteMCPServersInParallel(remoteConfigs);
        }));
      }

      // Removed chatty debug message
      const results = await Promise.allSettled(tasks);

      // Process results
      let jsonAnalysis: MCPJsonAnalysis | undefined;
      let dockerBehavioralResults: DockerBehavioralAnalysisResult[] | undefined;
      let remoteMCPResults: any[] | undefined;

      for (const result of results) {
        if (result.status === 'fulfilled') {
          const { type, result: taskResult } = result.value;

          if (type === 'json_analysis') {
            jsonAnalysis = taskResult as MCPJsonAnalysis;
          } else if (type === 'docker_behavioral') {
            dockerBehavioralResults = taskResult as DockerBehavioralAnalysisResult[];
          } else if (type === 'remote_mcp_analysis') {
            remoteMCPResults = taskResult as any[];
          }
        } else {
          console.error('❌ Analysis task failed:', result.reason);
        }
      }

      if (!jsonAnalysis) {
        throw new Error('JSON analysis failed');
      }

      const duration = Date.now() - startTime;
      console.log(`✅ Enhanced MCP JSON analysis completed in ${duration}ms`);

      if (dockerBehavioralResults) {
        console.log(`🐳 Docker behavioral analysis: ${dockerBehavioralResults.length} servers analyzed`);
      }

      if (remoteMCPResults) {
        console.log(`🌐 Remote MCP analysis: ${remoteMCPResults.length} servers analyzed`);
      }

      // Extract prompt security analysis from Docker behavioral results
      let mcpPromptSecurityAnalysis = undefined;
      if (dockerBehavioralResults && dockerBehavioralResults.length > 0) {
        // Find the first server with prompt security analysis results
        const serverWithPrompts = dockerBehavioralResults.find(server =>
          server.protocolData?.tools && server.protocolData.tools.length > 0
        );

        if (serverWithPrompts) {
          // Extract prompt security risks from behavioral analysis
          const promptRisks = serverWithPrompts.securityAnalysis.risks.filter((risk: any) =>
            ['tool_poisoning', 'tool_shadowing', 'data_exfiltration', 'cross_origin_violation', 'sensitive_file_access'].includes(risk.type)
          );

          mcpPromptSecurityAnalysis = {
            serverName: serverWithPrompts.serverName,
            totalTools: serverWithPrompts.protocolData?.tools?.length || 0,
            risks: promptRisks,
            summary: `Analyzed ${serverWithPrompts.protocolData?.tools?.length || 0} tools, found ${promptRisks.length} prompt security risks`
          };
        }
      }

      // Merge results - add remote analysis and prompt security analysis

      const result = {
        ...jsonAnalysis,
        dockerBehavioralAnalysis: dockerBehavioralResults,
        mcpPromptSecurityAnalysis
      } as any;

      if (remoteMCPResults) {
        result.remoteMCPAnalysis = remoteMCPResults;
      }

      return result;

    } catch (error) {
      if (error instanceof Error && error.message === 'LOCAL_EXECUTION_REDIRECT') {
        throw error;
      }
      console.error('❌ Enhanced MCP JSON analysis failed:', error);
      throw new Error(`Enhanced MCP JSON analysis failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Categorize MCP servers by type: Docker vs Remote
   */
  private categorizeServers(mcpJsonConfig: any): {
    dockerConfigs: DockerMCPConfig[],
    remoteConfigs: any[]
  } {
    const dockerConfigs: DockerMCPConfig[] = [];
    const remoteConfigs: any[] = [];

    try {
      const servers = getServersFromConfig(mcpJsonConfig);
      if (!servers || Object.keys(servers).length === 0) {
        return { dockerConfigs, remoteConfigs };
      }

      for (const [serverName, serverConfig] of Object.entries(servers)) {
        const config = serverConfig as any;

        // Use simplified remote detection logic
        const isRemote = this.isRemoteServer(config);

        if (isRemote) {
          console.log(`🌐 Detected remote MCP server: ${serverName}`);
          // Extract URL from config fields or from args (for mcp-remote style servers)
          let url = config.url || config.serverUrl || config.httpUrl;

          // If no direct URL found, check args for HTTP/HTTPS URLs (mcp-remote pattern)
          if (!url && config.args) {
            url = config.args.find((arg: string) =>
              arg.includes('http://') || arg.includes('https://')
            );
          }

          const detectedType = this.detectTransportType(config.type, url);
          remoteConfigs.push({
            serverName,
            config,
            url,
            type: detectedType,
            headers: config.headers || {}
          });
        }
        // Local execution servers (command-based)
        else if (config.command) {
          // Check if this is a native Docker-based MCP server
          if (config.command === 'docker' && config.args && config.args.length > 0) {
            const dockerImage = this.extractDockerImage(config.args);

            if (dockerImage) {
              dockerConfigs.push({
                serverName,
                dockerImage,
                dockerArgs: config.args.filter((arg: string) => arg !== dockerImage),
                environment: config.env || {},
                timeout: 60
              });
            }
          }
          // Handle known proxy/bridge packages (like mcp-remote) by wrapping in Docker
          else if (config.args && config.command && this.isKnownProxyPackage(config.args)) {
            console.log(`🔗 Creating Docker wrapper for proxy server: ${serverName}`);
            const proxyDockerConfig = this.createProxyServerDockerConfig(serverName, config);
            if (proxyDockerConfig) {
              dockerConfigs.push(proxyDockerConfig);
            }
          }
        }
      }
    } catch (error) {
      console.warn('Failed to categorize servers:', error);
    }

    // Only log relevant server types that were found
    if (dockerConfigs.length > 0) {
      // Removed chatty debug message
    }
    if (remoteConfigs.length > 0) {
      console.log(`🌐 Detected ${remoteConfigs.length} remote MCP servers`);
    }
    return { dockerConfigs, remoteConfigs };
  }

  /**
   * Extract Docker MCP configurations from JSON config
   * Includes both native Docker servers AND proxy/bridge servers that need sandbox execution
   */
  private extractDockerConfigurations(mcpJsonConfig: any): DockerMCPConfig[] {
    const dockerConfigs: DockerMCPConfig[] = [];

    try {
      const servers = getServersFromConfig(mcpJsonConfig);
      if (!servers || Object.keys(servers).length === 0) {
        return dockerConfigs;
      }

      for (const [serverName, serverConfig] of Object.entries(servers)) {
        const config = serverConfig as any;

        // Check if this is a native Docker-based MCP server
        if (config.command === 'docker' && config.args && config.args.length > 0) {
          // Parse Docker arguments to extract image and configuration
          const dockerImage = this.extractDockerImage(config.args);

          if (dockerImage) {
            dockerConfigs.push({
              serverName,
              dockerImage,
              dockerArgs: config.args.filter((arg: string) => arg !== dockerImage),
              environment: config.env || {},
              timeout: 60 // Default timeout
            });
          }
        }
        // NEW: Handle known proxy/bridge packages (like mcp-remote) by wrapping them in Docker
        else if (config.command && config.args && this.isKnownProxyPackage(config.args)) {
          console.log(`🔗 Creating Docker wrapper for proxy server: ${serverName}`);

          // Create a Docker config that will run the proxy server in a Node.js container
          const proxyDockerConfig = this.createProxyServerDockerConfig(serverName, config);
          if (proxyDockerConfig) {
            dockerConfigs.push(proxyDockerConfig);
          }
        }
      }
    } catch (error) {
      console.warn('Failed to extract Docker configurations:', error);
    }

    // Removed chatty debug message
    return dockerConfigs;
  }

  /**
   * Detect transport type from config and URL patterns
   */
  private detectTransportType(explicitType: string | undefined, url: string | undefined): string {
    // Check explicit type first
    if (explicitType === 'sse' || explicitType === 'server-sent-events') {
      return 'sse';
    }
    if (explicitType === 'http' || explicitType === 'streamableHttp') {
      return 'http';
    }

    // Auto-detect from URL patterns
    if (url) {
      const urlLower = url.toLowerCase();
      if (urlLower.includes('/sse') || urlLower.includes('/events') || urlLower.includes('sse.')) {
        return 'sse';
      }
    }

    // Default to HTTP streaming
    return 'http';
  }

  /**
   * Check if server configuration represents a remote MCP server
   * Simple logic: either has direct URL fields OR command with URL in args
   */
  private isRemoteServer(config: any): boolean {
    // Scenario 1: Direct URL fields (from remote_client_types.md)
    const hasDirectUrl = !!(
      config.url ||
      config.serverUrl ||
      config.httpUrl ||
      config.type === 'http' ||
      config.type === 'sse' ||
      config.type === 'streamableHttp'
    );

    // Scenario 2: Command with URL in args (npx/uvx/uv + http/https URL)
    const hasUrlInArgs = config.args?.some((arg: string) =>
      arg.includes('http://') || arg.includes('https://')
    );

    return hasDirectUrl || hasUrlInArgs;
  }

  /**
   * Check if server is a known proxy/bridge package (for mcp-remote detection)
   */
  private isKnownProxyPackage(args: string[]): boolean {
    const proxyPackagePatterns = [
      'mcp-remote', 'mcp-proxy', '@sparfenyuk/mcp-proxy', 'fastmcp-proxy',
      'mcp-bridge', 'mcp-connector', 'mcp-gateway', 'mcp-tunnel'
    ];

    return args.some(arg =>
      proxyPackagePatterns.some(pattern => arg.includes(pattern))
    );
  }

  /**
   * Create Docker configuration for proxy/bridge server execution
   */
  private createProxyServerDockerConfig(serverName: string, serverConfig: any): DockerMCPConfig | null {
    try {
      // For NPX proxy servers, use Node.js container
      if (serverConfig.command === 'npx') {
        const args = Array.isArray(serverConfig.args) ? serverConfig.args : [];
        const packageName = this.extractPackageNameFromArgs(args);

        return {
          serverName: `${serverName}-proxy-sandbox`,
          dockerImage: 'node:18-alpine', // Lightweight Node.js image
          dockerArgs: [
            'run', '--rm', '--network', 'none', // Isolated network initially
            '-e', 'NODE_ENV=sandbox',
            '-w', '/app'
          ],
          environment: {
            MCP_SERVER_NAME: serverName,
            MCP_PROXY_PACKAGE: packageName,
            MCP_ARGS: JSON.stringify(args),
            SANDBOX_MODE: 'true',
            ...serverConfig.env
          },
          timeout: 120 // Longer timeout for proxy connections
        };
      }

      // For UVX Python proxy servers, use Python container
      if (serverConfig.command === 'uvx') {
        const args = Array.isArray(serverConfig.args) ? serverConfig.args : [];

        return {
          serverName: `${serverName}-proxy-sandbox`,
          dockerImage: 'python:3.11-alpine',
          dockerArgs: [
            'run', '--rm', '--network', 'none',
            '-e', 'PYTHONPATH=/app',
            '-w', '/app'
          ],
          environment: {
            MCP_SERVER_NAME: serverName,
            MCP_ARGS: JSON.stringify(args),
            SANDBOX_MODE: 'true',
            ...serverConfig.env
          },
          timeout: 120
        };
      }

      return null;
    } catch (error) {
      console.warn(`Failed to create Docker config for proxy server ${serverName}:`, error);
      return null;
    }
  }

  /**
   * Extract package name from npx/uvx arguments
   */
  private extractPackageNameFromArgs(args: string[]): string {
    // Look for package name after -y flag
    const yIndex = args.findIndex(arg => arg === '-y' || arg === '--yes');
    if (yIndex !== -1 && yIndex < args.length - 1) {
      return args[yIndex + 1];
    }

    // Fallback: first non-flag argument
    const nonFlagArg = args.find(arg => !arg.startsWith('-'));
    return nonFlagArg || 'unknown';
  }

  /**
   * Inject CLI-provided API key into Docker configurations using pattern-based detection
   */
  private injectApiKeyIntoConfigs(dockerConfigs: DockerMCPConfig[], apiKey: string): DockerMCPConfig[] {
    // Removed chatty debug message

    return dockerConfigs.map(config => {
      if (!config.environment) {
        return config;
      }

      const updatedEnvironment = { ...config.environment };
      let keyInjected = false;
      let injectionCount = 0;

      // Check each environment variable for patterns
      Object.entries(updatedEnvironment).forEach(([envKey, envValue]) => {
        const authType = this.detectAuthType(envKey, String(envValue || ''));

        if (authType.needsReplacement) {
          console.log(`🔑 Detected ${authType.type} pattern: ${envKey} (was: "${envValue}")`);

          if (authType.type === 'api_key' || authType.type === 'generic_token') {
            updatedEnvironment[envKey] = apiKey;
            injectionCount++;
            keyInjected = true;
          } else {
            console.log(`⚠️  Skipping ${envKey}: detected as ${authType.type} (requires different auth method)`);
          }
        }
      });

      if (keyInjected) {
        // Removed chatty debug message
        return {
          ...config,
          environment: updatedEnvironment
        };
      } else {
        console.log(`ℹ️  No API key injection needed for: ${config.serverName}`);
      }

      return config;
    });
  }

  /**
   * Detect authentication type and whether it needs replacement
   */
  private detectAuthType(envKey: string, envValue: string): {
    type: 'api_key' | 'bearer_token' | 'jwt_token' | 'oauth_token' | 'enterprise_auth' | 'generic_token' | 'unknown';
    needsReplacement: boolean;
    confidence?: number; // TODO: Confidence calculation feature requires investigation
  } {
    const key = envKey.toLowerCase();
    const value = envValue?.toLowerCase() || '';

    // Define authentication patterns
    const patterns = {
      api_key: {
        keyPatterns: [
          /(?:api[_-]?key|[a-z]+[_-]?(?:api[_-]?)?key|secret)/i,
          /(?:access[_-]?key|service[_-]?key)/i
        ],
        excludePatterns: [
          /bearer/i, /oauth/i, /jwt/i, /saml/i, /ldap/i
        ]
      },
      bearer_token: {
        keyPatterns: [
          /bearer[_-]?token/i,
          /authorization/i,
          /auth[_-]?token/i
        ],
        excludePatterns: [
          /api[_-]?key/i, /secret/i
        ]
      },
      jwt_token: {
        keyPatterns: [
          /jwt[_-]?token/i,
          /id[_-]?token/i,
          /refresh[_-]?token/i
        ],
        excludePatterns: []
      },
      oauth_token: {
        keyPatterns: [
          /oauth[_-]?token/i,
          /access[_-]?token/i,
          /client[_-]?(?:id|secret)/i
        ],
        excludePatterns: [
          /api[_-]?key/i, /jwt/i
        ]
      },
      enterprise_auth: {
        keyPatterns: [
          /saml[_-]?token/i,
          /ldap/i,
          /ad[_-]?(?:token|auth)/i,
          /sso[_-]?token/i,
          /kerberos/i
        ],
        excludePatterns: []
      },
      generic_token: {
        keyPatterns: [
          /token/i
        ],
        excludePatterns: [
          /bearer/i, /oauth/i, /jwt/i, /saml/i, /refresh/i, /id[_-]?token/i
        ]
      }
    };

    // Placeholder patterns that indicate replacement is needed
    const placeholderPatterns = [
      'your_api_key_here',
      'your_key_here',
      'api_key_here',
      'replace_with_api_key',
      'insert_api_key',
      '<api_key>',
      '{{api_key}}',
      '${api_key}',
      'todo',
      'changeme',
      'placeholder',
      'example',
      'xxx',
      '',  // Empty string
      null,
      undefined
    ];

    const needsReplacement = placeholderPatterns.includes(value) ||
                           value.length === 0 ||
                           /^(your|insert|replace|todo|change|example|xxx|placeholder)/i.test(value);

    // Detect auth type with confidence scoring
    for (const [authType, { keyPatterns, excludePatterns }] of Object.entries(patterns)) {
      // Check if key matches any exclude patterns first
      if (excludePatterns.some(pattern => pattern.test(key))) {
        continue;
      }

      // Check if key matches any key patterns
      const matchCount = keyPatterns.reduce((count, pattern) =>
        count + (pattern.test(key) ? 1 : 0), 0
      );

      if (matchCount > 0) {
        const confidence = Math.min(matchCount / keyPatterns.length, 1.0);
        return {
          type: authType as any,
          needsReplacement,
          confidence
        };
      }
    }

    return {
      type: 'unknown',
      needsReplacement,
      confidence: 0
    };
  }

  /**
   * Extract Docker image name from Docker arguments
   */
  private extractDockerImage(args: string[]): string | null {
    try {
      // Look for the Docker image (usually after 'run' and all flags)
      const runIndex = args.findIndex(arg => arg === 'run');
      if (runIndex !== -1 && runIndex < args.length - 1) {

        // Docker flags that take values (need to skip both flag and value)
        const flagsWithValues = ['-e', '--env', '-v', '--volume', '-p', '--port', '--name', '--network', '--workdir', '-w', '--user', '-u'];

        // Parse arguments after 'run' to find the Docker image
        for (let i = runIndex + 1; i < args.length; i++) {
          const arg = args[i];

          // Skip flags that start with '-'
          if (arg.startsWith('-')) {
            // Check if this flag takes a value
            if (flagsWithValues.includes(arg)) {
              // Skip this flag and its value
              i++; // Skip the next argument (the value)
              continue;
            }
            // Skip standalone flags like --rm, --privileged
            continue;
          }

          // First non-flag argument should be the Docker image
          return arg;
        }
      }

      // Fallback: look for an argument that looks like a Docker image
      // This handles cases where 'run' isn't the first argument
      for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (!arg.startsWith('-') &&
            !arg.includes('=') &&
            (arg.includes('/') || arg.includes(':') || arg.match(/^[a-zA-Z0-9]+(:[a-zA-Z0-9.-]+)?$/))) {

          // Make sure this isn't a value for a previous flag
          if (i > 0) {
            const prevArg = args[i - 1];
            const flagsWithValues = ['-e', '--env', '-v', '--volume', '-p', '--port', '--name', '--network', '--workdir', '-w', '--user', '-u'];
            if (flagsWithValues.includes(prevArg)) {
              continue; // This is a flag value, not the Docker image
            }
          }

          return arg;
        }
      }
    } catch (error) {
      console.warn('Failed to extract Docker image from args:', error);
    }

    return null;
  }

  private async executeTask<T>(
    type: string,
    task: () => Promise<T>
  ): Promise<{ type: string; result: T; duration: number }> {
    const startTime = Date.now();
    const result = await task();
    const duration = Date.now() - startTime;

    return { type, result, duration };
  }

  private async cloneRepositoryForAnalysis(sourceCodeUrl: string, sandboxProvider: any): Promise<void> {
    // Basic repository clone for when we skip dependency analysis but need source code
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);

    const volumeName = `mcp-git-${Date.now()}`;

    try {
      await execAsync(`docker volume create ${volumeName}`);

      await execAsync([
        'docker run --rm',
        `-v ${volumeName}:/workspace`,
        'alpine/git:latest',
        'clone',
        sourceCodeUrl,
        '/workspace'
      ].join(' '));

      // Store volume name for later use
      (sandboxProvider as any)._currentVolume = volumeName;

    } catch (error) {
      // Clean up on failure
      try {
        await execAsync(`docker volume rm ${volumeName}`);
      } catch { /* ignore cleanup errors */ }
      throw error;
    }
  }

  private async performParallelSourceCodeAnalysis(volumeName: string): Promise<{
    vulnerabilities: Array<{
      type: string;
      severity: string;
      line: number;
      description: string;
      code: string;
    }>;
    suggestions: string[];
  }> {
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);

    // Use the same AI analysis approach but without Docker volume cleanup
    const response = await this.aiAnalyzer.createCompletionWithProvider('anthropic', [
      {
        role: 'system',
        content: `You are an expert MCP (Model Context Protocol) security analyzer conducting a security assessment for deployment in the Kindo platform. Follow this systematic methodology:

## ANALYSIS METHODOLOGY:

### 1. REPOSITORY STRUCTURE ANALYSIS
- Identify main entry points (package.json, index files)
- Map MCP server architecture and dependencies
- Locate configuration files and environment setups

### 2. MCP TOOL SECURITY ANALYSIS
For each MCP tool implementation, examine:
- Parameter injection vulnerabilities (command, path, code injection)
- Input validation and sanitization patterns
- External command execution with user data
- Unsafe deserialization of tool parameters
- File system access and path traversal risks

### 3. MCP RESOURCE HANDLER ANALYSIS
Check resource handlers for:
- Path traversal vulnerabilities (../, absolute paths)
- Unauthorized file system access
- Directory listing exposure
- Sensitive file access patterns

### 4. AUTHENTICATION & AUTHORIZATION
Verify security controls:
- MCP session validation mechanisms
- API key handling and storage security
- Authentication bypass possibilities
- Authorization enforcement for tools/resources

### 5. KINDO PLATFORM INTEGRATION RISKS
Assess deployment-specific concerns:
- Hardcoded secrets in configuration files
- Network access patterns and external dependencies
- Resource consumption and DoS potential
- Multi-tenant isolation considerations
- Environment variable security

### 6. PRODUCTION SECURITY PATTERNS
Check for:
- Error handling that exposes sensitive information
- Logging of sensitive data
- CORS and HTTP security headers
- Input validation bypass patterns

## SEVERITY RATING (Production Impact for Kindo):
- CRITICAL: Remote code execution, credential theft, data breach potential
- HIGH: Authentication bypass, privilege escalation, system compromise
- MEDIUM: Information disclosure, DoS potential, configuration weaknesses
- LOW: Best practice improvements, hardening recommendations

## OUTPUT REQUIREMENTS:
- Provide specific file paths and line numbers
- Include actual vulnerable code snippets
- Focus on MCP-specific attack vectors
- Prioritize findings by production deployment risk

The repository is available in a Docker volume "${volumeName}" mounted at /src. Use your tools systematically to conduct this analysis.`
      },
      {
        role: 'user',
        content: 'Conduct a comprehensive MCP security analysis following the systematic methodology provided. Begin with repository structure analysis, then proceed through each phase: MCP tools, resource handlers, authentication, Kindo platform risks, and production security patterns. Provide detailed findings with specific file paths, line numbers, and code snippets for each vulnerability discovered.'
      }
    ], {
      tools: [
        {
          name: 'list_directory',
          description: 'List contents of a directory in the repository',
          parameters: {
            type: 'object',
            properties: {
              path: {
                type: 'string',
                description: 'Directory path relative to /src (e.g., "." for root, "src/tools" for subdirectory)'
              }
            },
            required: ['path']
          },
          handler: async ({ path }: { path: string }) => {
            try {
              const { stdout } = await execAsync(
                `docker run --rm -v ${volumeName}:/src alpine:latest ls -la /src/${path}`
              );
              return { success: true, contents: stdout };
            } catch (error) {
              return { success: false, error: error instanceof Error ? error.message : String(error) };
            }
          }
        },
        {
          name: 'read_file',
          description: 'Read the contents of a file in the repository',
          parameters: {
            type: 'object',
            properties: {
              path: {
                type: 'string',
                description: 'File path relative to /src (e.g., "package.json", "src/index.ts")'
              }
            },
            required: ['path']
          },
          handler: async ({ path }: { path: string }) => {
            try {
              const { stdout } = await execAsync(
                `docker run --rm -v ${volumeName}:/src alpine:latest cat /src/${path}`
              );
              return { success: true, contents: stdout };
            } catch (error) {
              return { success: false, error: error instanceof Error ? error.message : String(error) };
            }
          }
        },
        {
          name: 'search_files',
          description: 'Search for patterns across files in the repository',
          parameters: {
            type: 'object',
            properties: {
              pattern: {
                type: 'string',
                description: 'Pattern to search for (supports basic regex)'
              },
              file_pattern: {
                type: 'string',
                description: 'File pattern to search in (e.g., "*.js", "*.ts", "*.json")',
                default: '*'
              }
            },
            required: ['pattern']
          },
          handler: async ({ pattern, file_pattern = '*' }: { pattern: string; file_pattern?: string }) => {
            try {
              const { stdout } = await execAsync(
                `docker run --rm -v ${volumeName}:/src alpine:latest sh -c "find /src -name '${file_pattern}' -type f -exec grep -l '${pattern}' {} \\;"`
              );
              return { success: true, matches: stdout.trim().split('\n').filter(Boolean) };
            } catch (error) {
              return { success: false, error: error instanceof Error ? error.message : String(error) };
            }
          }
        }
      ]
    });

    // Get source code for structured analysis
    let sourceCodeContent = '';
    try {
      const { stdout: jsFiles } = await execAsync(`docker run --rm -v ${volumeName}:/src alpine:latest find /src -name "*.js" -o -name "*.ts" -o -name "*.mjs" | head -10`);

      if (jsFiles.trim()) {
        const files = jsFiles.trim().split('\n').slice(0, 3);
        for (const file of files) {
          try {
            const { stdout: content } = await execAsync(`docker run --rm -v ${volumeName}:/src alpine:latest cat "${file}"`);
            sourceCodeContent += `\n// === ${file} ===\n${content}\n`;
          } catch (error) {
            console.warn(`Could not read ${file}:`, error);
          }
        }
      }
    } catch (error) {
      console.warn('Could not analyze source files:', error);
    }

    // Use structured analysis
    const structuredAnalysis = await this.aiAnalyzer.analyzeSourceCodeSecurity(sourceCodeContent || response.content);

    return {
      vulnerabilities: structuredAnalysis.vulnerabilities,
      suggestions: structuredAnalysis.suggestions
    };
  }

  private async performParallelMCPPromptAnalysis(volumeName: string): Promise<{
    serverName: string;
    totalTools: number;
    risks: Array<{
      type: string;
      severity: string;
      description: string;
      evidence: string[];
      toolName?: string;
      context: string;
      confidence?: number; // TODO: Confidence calculation feature requires investigation
    }>;
    summary: string;
  } | undefined> {
    try {
      // Discover MCP configuration in the repository
      const mcpConfig = await this.discoverMCPConfiguration(volumeName);

      if (!mcpConfig) {
        console.log('No MCP server configuration found for prompt analysis');
        return undefined;
      }

      console.log(`Found MCP server configuration with ${mcpConfig.tools?.length || 0} tools for prompt analysis`);

      // Analyze for prompt-level vulnerabilities
      const promptAnalysis = await this.aiAnalyzer.analyzeMCPPromptSecurity(mcpConfig);

      return {
        serverName: promptAnalysis.serverName,
        totalTools: promptAnalysis.totalTools,
        risks: promptAnalysis.risks.map(risk => ({
          type: risk.type,
          severity: risk.severity,
          description: risk.description,
          evidence: risk.evidence,
          toolName: risk.toolName,
          context: risk.context,
          confidence: risk.confidence
        })),
        summary: promptAnalysis.summary
      };

    } catch (error) {
      console.warn('MCP prompt security analysis failed:', error);
      return undefined;
    }
  }

  private async discoverMCPConfiguration(volumeName: string): Promise<{
    name: string;
    tools?: Array<{
      name: string;
      description?: string;
      inputSchema?: any;
    }>;
  } | null> {
    const { exec } = require('child_process');
    const { promisify } = require('util');
    const execAsync = promisify(exec);

    try {
      let projectName = 'unknown-mcp-server';
      const tools: Array<{ name: string; description?: string; inputSchema?: any }> = [];

      // Get project name
      try {
        const { stdout: packageJson } = await execAsync(`docker run --rm -v ${volumeName}:/src alpine:latest cat /src/package.json`);
        const pkg = JSON.parse(packageJson);
        projectName = pkg.name || 'unknown-mcp-server';
      } catch {
        // package.json not found or invalid
      }

      // Search for MCP tool definitions
      const searchPatterns = [
        'server\\.setRequestHandler.*tools/list',
        'tools\\.set\\(',
        'name:.*description:',
        'inputSchema:',
        '@server\\.list_tools',
        'def.*tool.*\\(',
        'Tool\\(',
        'mcp.*server',
        'tool.*handler',
        'resource.*handler'
      ];

      for (const pattern of searchPatterns) {
        try {
          const { stdout } = await execAsync(
            `docker run --rm -v ${volumeName}:/src alpine:latest sh -c "find /src -type f \\( -name '*.js' -o -name '*.ts' -o -name '*.py' \\) -exec grep -l '${pattern}' {} \\; | head -5"`
          );

          if (stdout.trim()) {
            const files = stdout.trim().split('\n');

            for (const file of files.slice(0, 2)) {
              try {
                const { stdout: content } = await execAsync(
                  `docker run --rm -v ${volumeName}:/src alpine:latest cat "${file}"`
                );

                const toolMatches = content.match(/name\s*:\s*["'`]([^"'`]+)["'`][\s\S]*?description\s*:\s*["'`]([^"'`]*)["'`]/g);

                if (toolMatches) {
                  for (const match of toolMatches.slice(0, 10)) {
                    const nameMatch = match.match(/name\s*:\s*["'`]([^"'`]+)["'`]/);
                    const descMatch = match.match(/description\s*:\s*["'`]([^"'`]*)["'`]/);

                    if (nameMatch) {
                      tools.push({
                        name: nameMatch[1],
                        description: descMatch ? descMatch[1] : 'No description provided',
                        inputSchema: { type: 'object', properties: {} }
                      });
                    }
                  }
                }
              } catch {
                continue;
              }
            }

            break;
          }
        } catch {
          continue;
        }
      }

      if (tools.length > 0) {
        return { name: projectName, tools };
      }

      // Check for general MCP server patterns
      try {
        const { stdout } = await execAsync(
          `docker run --rm -v ${volumeName}:/src alpine:latest sh -c "find /src -name '*.js' -o -name '*.ts' -o -name '*.py' | xargs grep -l 'mcp.*server\\|Model Context Protocol' | head -1"`
        );

        if (stdout.trim()) {
          return {
            name: projectName,
            tools: [{
              name: 'unknown-tool',
              description: 'MCP server detected but specific tool definitions not found',
              inputSchema: { type: 'object', properties: {} }
            }]
          };
        }
      } catch {
        // No MCP patterns found
      }

      return null;

    } catch (error) {
      throw new Error(`Failed to discover MCP configuration: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}