/**
 * AI-powered black box analysis of MCP JSON configurations
 * Detects security risks in MCP server configurations without source code access
 */

import { z } from 'zod';
import { promisify } from 'util';
import { exec } from 'child_process';
import { AIRouter } from '../services/ai-router';
import { SandboxManager } from '../sandbox/sandbox-manager';
import {
  parseAndValidateMCPConfig,
  getServersFromConfig,
  DockerCommandParser,
  type MCPConfiguration,
  type MCPServerConfig
} from './mcp-config-schema';

const execAsync = promisify(exec);

// MCP JSON risk schema
const MCPRiskSchema = z.object({
  type: z.enum([
    'HIDDEN_AUTHENTICATION',
    'CREDENTIAL_INTERCEPTION',
    'AUTH_BRIDGE_DETECTED',
    'AUTH_OBFUSCATION',
    'PROXY_BRIDGE_DETECTED',
    'REMOTE_CODE_EXECUTION_RISK',
    'UNTRUSTED_NPX_DOWNLOAD',
    'UNVERIFIED_PACKAGE',
    'TYPOSQUATTING_RISK',
    'PRIVILEGED_CONTAINER',
    'HOST_FILESYSTEM_ACCESS',
    'NETWORK_EXPOSURE',
    'INSECURE_TRANSPORT',
    'SSE_SESSION_HIJACKING',
    'CORS_MISCONFIGURATION',
    'COMMAND_INJECTION',
    'SUPPLY_CHAIN_ATTACK',
    'MISSING_AUTHENTICATION',
    'RESOURCE_EXHAUSTION',
    'ANALYSIS_FAILED',
    'DATA_EXFILTRATION',
    'FILE_SYSTEM_MODIFICATION'
  ]),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  description: z.string(),
  evidence: z.array(z.string()),
  mitigation: z.string(),
  aiConfidence: z.number().min(0).max(1).optional()
});

const MCPJsonAnalysisSchema = z.object({
  overallRisk: z.enum(['critical', 'high', 'medium', 'low']),
  risks: z.array(MCPRiskSchema),
  packageAnalysis: z.object({
    suspiciousPackages: z.array(z.string()),
    bridgePackages: z.array(z.string()),
    untrustedDownloads: z.array(z.string())
  }),
  networkAnalysis: z.object({
    remoteEndpoints: z.array(z.string()),
    insecureProtocols: z.array(z.string()),
    authenticationGaps: z.array(z.string())
  }),
  recommendations: z.array(z.string()),
  summary: z.string(),
  repositoryDiscovery: z.object({
    repositories: z.array(z.string()),
    suggestions: z.array(z.string())
  }).optional()
});

export type MCPJsonAnalysis = z.infer<typeof MCPJsonAnalysisSchema>;
export type MCPRisk = z.infer<typeof MCPRiskSchema>;

export interface PackageResearchResult {
  packageInfo: any;
  sourceAnalysis: any;
  securityFlags: string[];
  bridgeDetected: boolean;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  trustScore: number;
}

export interface MCPDeploymentResult {
  sandboxId: string;
  deploymentSuccess: boolean;
  executionResults: any;
  networkActivity: any[];
  processActivity: any[];
  authTokensDetected: string[];
  bridgeProcesses: any[];
  authFlowDetected: boolean;
}

export interface NetworkAnalysisResult {
  connections: Array<{
    destination: string;
    protocol: string;
    authHeaders: string[];
    suspiciousActivity: string[];
  }>;
  credentialFlows: any[];
  hiddenAuthentication: boolean;
}

export class MCPJsonAnalyzer {
  private aiRouter: AIRouter;
  private sandboxManager: SandboxManager;

  constructor(aiRouter: AIRouter, sandboxManager: SandboxManager) {
    this.aiRouter = aiRouter;
    this.sandboxManager = sandboxManager;
  }

  /**
   * Categorize servers into proxy/bridge vs true local execution
   * This is critical for handling edge cases like Linear's mcp-remote pattern
   */
  private categorizeServers(mcpConfig: MCPConfiguration): {
    proxyServers: [string, MCPServerConfig][];
    localExecutionServers: [string, MCPServerConfig][];
  } {
    const proxyServers: [string, MCPServerConfig][] = [];
    const localExecutionServers: [string, MCPServerConfig][] = [];

    for (const [serverName, serverConfig] of Object.entries(getServersFromConfig(mcpConfig))) {
      // Skip Docker and URL-based configs (already handled correctly)
      if (!serverConfig.command || serverConfig.command === 'docker' || !serverConfig.args) {
        continue;
      }

      const args = Array.isArray(serverConfig.args) ? serverConfig.args : [];

      // 1. Check for known proxy/bridge package names
      const detectedProxyPackage = this.detectProxyBridgePackage(args);

      // 2. Check for remote URLs in arguments
      const hasRemoteUrl = this.hasRemoteUrlInArgs(args);

      // 3. Check for transport/bridge keywords
      const hasBridgeKeywords = this.hasBridgeTransportKeywords(args);

      if (detectedProxyPackage || hasRemoteUrl || hasBridgeKeywords) {
        const proxyName = detectedProxyPackage || 'remote-bridge';
        console.log(`🔗 Detected proxy/bridge server: ${proxyName} (serving ${serverName})`);
        console.log(`   Package: ${detectedProxyPackage ? detectedProxyPackage : 'NO'} | URL: ${hasRemoteUrl ? 'YES' : 'NO'} | Transport: ${hasBridgeKeywords ? 'YES' : 'NO'}`);
        console.log(`   Command: ${serverConfig.command} ${args.join(' ')}`);
        proxyServers.push([serverName, serverConfig]);
      } else if (serverConfig.command && serverConfig.command !== 'docker') {
        console.log(`📦 Local execution server: ${serverName} (${serverConfig.command})`);
        localExecutionServers.push([serverName, serverConfig]);
      }
    }

    return { proxyServers, localExecutionServers };
  }

  /**
   * Check if args contain known proxy/bridge package names
   */
  private detectProxyBridgePackage(args: string[]): string | null {
    // TODO: TEMPORARY HARDCODED LIST - This should be refactored to pattern matching in the future
    // Currently hardcoded because:
    // 1. Only handful of proxy/bridge methods exist today (STDIO, Docker, Remote)
    // 2. Each has specific implementation that needs to be tracked
    // 3. Pattern matching would miss cases like "fastMCP" (no mcp- prefix)
    // 4. Need to account for all current proxy/bridge implementations
    // FUTURE: Engineer proper pattern matching system that can detect proxy behavior
    const proxyPackagePatterns = [
      'mcp-remote',           // Generic remote bridge pattern
      'mcp-proxy',            // Generic proxy
      '@sparfenyuk/mcp-proxy', // Specific proxy package
      'fastmcp-proxy',        // FastMCP proxy (proves naming inconsistency)
      'mcp-bridge',           // Bridge patterns
      'mcp-connector',        // Connector patterns
      'mcp-gateway',          // Gateway patterns
      'mcp-tunnel',           // Tunnel patterns
      'remote-mcp',           // Alternative naming
      'bridge-mcp',           // Alternative naming
      'proxy-mcp'             // Alternative naming
    ];

    for (const arg of args) {
      for (const pattern of proxyPackagePatterns) {
        if (arg.includes(pattern) || arg === pattern) {
          return pattern;
        }
      }
    }
    return null;
  }

  /**
   * Check if args contain remote URLs (HTTP/HTTPS/WebSocket)
   */
  private hasRemoteUrlInArgs(args: string[]): boolean {
    const urlPatterns = [
      /^https?:\/\//,         // HTTP/HTTPS URLs
      /^wss?:\/\//,           // WebSocket URLs
      /\/sse$/,               // Server-Sent Events endpoints
      /\/events$/,            // Events endpoints
      /\/api\/mcp/,           // MCP API endpoints
      /\.linear\.app/,        // Linear specific
      /\.anthropic\.com/,     // Anthropic hosted
      /\.openai\.com/         // OpenAI hosted
    ];

    return args.some(arg =>
      urlPatterns.some(pattern => pattern.test(arg))
    );
  }

  /**
   * Check if args contain transport/bridge keywords
   */
  private hasBridgeTransportKeywords(args: string[]): boolean {
    const bridgeKeywords = [
      'transport',
      'bridge',
      'proxy',
      'remote',
      'tunnel',
      'gateway',
      'connector',
      'relay',
      'forward',
      'stdio',
      '--transport',
      '--bridge',
      '--proxy',
      '--remote'
    ];

    return args.some(arg =>
      bridgeKeywords.some(keyword =>
        arg.toLowerCase().includes(keyword.toLowerCase())
      )
    );
  }

  private async analyzeServerConfiguration(serverName: string, serverConfig: MCPServerConfig): Promise<{
    risks: MCPRisk[];
    packageAnalysis: {
      suspiciousPackages: string[];
      bridgePackages: string[];
      untrustedDownloads: string[];
    };
    networkAnalysis: {
      remoteEndpoints: string[];
      insecureProtocols: string[];
      authenticationGaps: string[];
    };
  }> {
    const risks: MCPRisk[] = [];
    const packageAnalysis = { suspiciousPackages: [], bridgePackages: [], untrustedDownloads: [] };
    const networkAnalysis = { remoteEndpoints: [], insecureProtocols: [], authenticationGaps: [] };

    // Check if this is a local execution configuration (has 'args')
    if (!serverConfig.args) {
      // This is likely a remote configuration (URL-based) - skip for now
      console.log(`Skipping remote configuration: ${serverName} (no args found)`);
      return { risks, packageAnalysis, networkAnalysis };
    }

    console.log(`Analyzing local execution configuration: ${serverName}`);

    // Analyze command and arguments for security risks
    const command = serverConfig.command || '';
    const args = Array.isArray(serverConfig.args) ? serverConfig.args : [];

    console.log(`DEBUG: Command="${command}", Args=${JSON.stringify(args)}`);

    // 1. Package Manager Analysis
    if (command === 'npx') {
      risks.push(...this.analyzeNpxExecution(serverName, args));
      this.extractPackageInfo(args, packageAnalysis);
    } else if (command === 'uvx') {
      risks.push(...this.analyzeUvxExecution(serverName, args));
    } else if (command === 'pip') {
      risks.push(...this.analyzePipExecution(serverName, args));
    } else if (command === 'docker') {
      risks.push(...await this.analyzeDockerExecution(serverName, args));
      this.extractDockerImageInfo(args, packageAnalysis);
    }

    // 2. Command Injection Analysis
    risks.push(...this.analyzeCommandInjectionRisks(serverName, args));

    // 3. Credential Exposure Analysis
    risks.push(...this.analyzeCredentialExposure(serverName, args, serverConfig.env));

    // 4. Network Endpoint Analysis
    this.extractNetworkEndpoints(args, networkAnalysis);

    return { risks, packageAnalysis, networkAnalysis };
  }

  /**
   * Repository discovery - only suggest --repo for TRUE local execution (not proxy/bridge)
   */
  async discoverRepositoryFromJSON(mcpConfig: MCPConfiguration): Promise<{ repositories: string[]; suggestions: string[] }> {
    // Use the same categorization logic to avoid suggesting --repo for proxy servers
    const { proxyServers, localExecutionServers } = this.categorizeServers(mcpConfig);

    // Only suggest --repo analysis for TRUE local execution servers (not proxies)
    if (localExecutionServers.length === 0) {
      return { repositories: [], suggestions: [] };
    }

    const serverNames = localExecutionServers.map(([name]) => name);
    const commands = localExecutionServers.map(([_, config]: [string, MCPServerConfig]) => config.command);

    return {
      repositories: [],
      suggestions: [
        `⚠️  Local execution patterns detected: "${commands.join('", "')}" commands require source code access`,
        '',
        '🔧 RECOMMENDED ACTION:',
        `   Use repository analysis instead of JSON-only analysis:`,
        `   yarn node mcp_scan_cli.js --repo <github_repository_url>`,
        '',
        '💡 WHY:',
        `   Servers "${serverNames.join('", "')}" use local script execution`,
        `   Source code analysis provides comprehensive security assessment`,
        `   JSON-only analysis has limited visibility into actual implementation risks`
      ]
    };
  }

  async analyzeMCPConfiguration(mcpConfigInput: any): Promise<MCPJsonAnalysis> {
    console.log('Starting static pattern analysis of MCP configuration...');

    // Validate configuration using Zod schema
    let mcpConfig: MCPConfiguration;
    try {
      mcpConfig = parseAndValidateMCPConfig(mcpConfigInput);
    } catch (error) {
      console.error('MCP configuration validation failed:', error);
      throw new Error(`Invalid MCP configuration: ${error instanceof Error ? error.message : String(error)}`);
    }

    // Enhanced proxy/bridge detection BEFORE local execution redirect
    const { proxyServers, localExecutionServers } = this.categorizeServers(mcpConfig);

    // Only redirect to --repo if we have LOCAL servers (not proxy/bridge servers)
    if (localExecutionServers.length > 0) {
      const serverNames = localExecutionServers.map(([name]) => name);
      const commands = localExecutionServers.map(([_, config]: [string, MCPServerConfig]) => config.command);

      const message = `\n❌ LOCAL EXECUTION DETECTED\nServers "${serverNames.join('", "')}" use "${commands.join('", "')}" commands.\n\nUse repository analysis instead:\nyarn node mcp_scan_cli.js --repo <github_repository_url>`;
      console.log(message);
      throw new Error('LOCAL_EXECUTION_REDIRECT');
    }

    // Log detected proxy/bridge servers
    if (proxyServers.length > 0) {
      const proxyNames = proxyServers.map(([name]) => name);
      console.log(`🔗 Detected ${proxyServers.length} proxy/bridge servers: ${proxyNames.join(', ')}`);
      console.log(`   These will be analyzed as remote servers in sandbox environment`);
    }

    // Perform comprehensive static analysis
    const risks: MCPRisk[] = [];
    const packageAnalysis = {
      suspiciousPackages: [] as string[],
      bridgePackages: [] as string[],
      untrustedDownloads: [] as string[]
    };
    const networkAnalysis = {
      remoteEndpoints: [] as string[],
      insecureProtocols: [] as string[],
      authenticationGaps: [] as string[]
    };

    // Analyze each MCP server configuration
    for (const [serverName, serverConfig] of Object.entries(getServersFromConfig(mcpConfig))) {
      console.log(`Analyzing server: ${serverName}`);
      const serverRisks = await this.analyzeServerConfiguration(serverName, serverConfig);
      risks.push(...serverRisks.risks);

      packageAnalysis.suspiciousPackages.push(...serverRisks.packageAnalysis.suspiciousPackages);
      packageAnalysis.bridgePackages.push(...serverRisks.packageAnalysis.bridgePackages);
      packageAnalysis.untrustedDownloads.push(...serverRisks.packageAnalysis.untrustedDownloads);

      networkAnalysis.remoteEndpoints.push(...serverRisks.networkAnalysis.remoteEndpoints);
      networkAnalysis.insecureProtocols.push(...serverRisks.networkAnalysis.insecureProtocols);
      networkAnalysis.authenticationGaps.push(...serverRisks.networkAnalysis.authenticationGaps);
    }

    // Determine overall risk level
    const overallRisk = this.calculateOverallRiskLevel(risks);

    // Generate recommendations
    const recommendations = this.generateRecommendations(risks, packageAnalysis, networkAnalysis);

    // Generate summary
    const summary = this.generateAnalysisSummary(risks.length, packageAnalysis, networkAnalysis, overallRisk);

    // Discover repositories for local execution patterns
    const repositoryDiscovery = await this.discoverRepositoryFromJSON(mcpConfig);

    return {
      overallRisk,
      risks,
      packageAnalysis,
      networkAnalysis,
      recommendations,
      summary,
      repositoryDiscovery
    };
  }

  private async researchPackage(packageName: string, deepAnalysis: boolean): Promise<PackageResearchResult> {
    try {
      // Research npm package
      const npmInfo = await this.fetchNPMInfo(packageName);

      // Analyze for bridge patterns
      const isBridge = this.detectBridgePattern(packageName, npmInfo);

      // Calculate trust score
      const trustScore = this.calculateTrustScore(npmInfo);

      return {
        packageInfo: npmInfo,
        sourceAnalysis: deepAnalysis ? await this.fetchGitHubInfo(npmInfo.repository) : null,
        securityFlags: this.generateSecurityFlags(npmInfo, isBridge),
        bridgeDetected: isBridge,
        riskLevel: this.assessPackageRisk(npmInfo, isBridge, trustScore),
        trustScore
      };
    } catch (error) {
      return {
        packageInfo: null,
        sourceAnalysis: null,
        securityFlags: ['Package research failed', `Error: ${error instanceof Error ? error.message : String(error)}`],
        bridgeDetected: false,
        riskLevel: 'medium',
        trustScore: 0.1
      };
    }
  }

  private async deploySandboxMCP(mcpConfig: any, duration: number): Promise<MCPDeploymentResult> {
    const sandboxId = await this.sandboxManager.createIsolatedEnvironment();

    try {
      // Deploy the MCP configuration
      const result = await this.sandboxManager.deployMCPConfiguration(mcpConfig);

      // Monitor execution
      const monitoringResult = await this.monitorExecution(sandboxId, duration);

      return {
        sandboxId,
        deploymentSuccess: result.deploymentSuccess,
        executionResults: result,
        networkActivity: result.networkActivity || [],
        processActivity: result.processActivity || [],
        authTokensDetected: this.extractTokens(result),
        bridgeProcesses: this.detectBridges(result),
        authFlowDetected: this.detectAuthFlow(result)
      };
    } catch (error) {
      return {
        sandboxId,
        deploymentSuccess: false,
        executionResults: { error: error instanceof Error ? error.message : String(error) },
        networkActivity: [],
        processActivity: [],
        authTokensDetected: [],
        bridgeProcesses: [],
        authFlowDetected: false
      };
    }
  }

  private async monitorNetworkTraffic(sandboxId: string, captureCredentials: boolean): Promise<NetworkAnalysisResult> {
    const trafficLog = await this.sandboxManager.captureTraffic(sandboxId);

    return {
      connections: trafficLog.connections || [],
      credentialFlows: this.analyzeCredentialFlows(trafficLog),
      hiddenAuthentication: this.detectHiddenAuth(trafficLog)
    };
  }

  private async analyzePackageSource(packageName: string, repositoryUrl?: string): Promise<any> {
    // Analyze package source code for security issues
    // This could integrate with GitHub API or direct repository analysis
    return {
      sourceCodeSecurity: 'analysis_placeholder',
      maliciousPatterns: [],
      bridgeImplementation: false
    };
  }

  // Static analysis methods for args-based configurations
  private analyzeNpxExecution(serverName: string, args: string[]): MCPRisk[] {
    const risks: MCPRisk[] = [];

    // Check for proxy/bridge packages with authentication obfuscation
    const detectedProxy = this.detectProxyBridgePackage(args);
    if (detectedProxy) {
      const packageName = this.extractPackageName(args);
      const hasRemoteUrl = this.hasRemoteUrlInArgs(args);

      risks.push({
        type: 'PROXY_BRIDGE_DETECTED',
        severity: 'high',
        description: `Server "${serverName}" uses proxy/bridge package "${packageName}" which may obfuscate authentication and enable remote code execution`,
        evidence: [
          `Proxy package: ${packageName}`,
          `Remote URL detected: ${hasRemoteUrl ? 'YES' : 'NO'}`,
          `Full command: npx ${args.join(' ')}`
        ],
        mitigation: 'Review proxy package source code, verify authentication mechanisms, consider direct server connection instead',
        aiConfidence: 0.95
      });

      // Specific risk for Linear's mcp-remote pattern
      if (packageName === 'mcp-remote') {
        risks.push({
          type: 'AUTH_OBFUSCATION',
          severity: 'critical',
          description: `Server "${serverName}" uses Linear's mcp-remote package which completely obfuscates authentication flow and could enable data exfiltration`,
          evidence: [
            'mcp-remote package detected',
            'Authentication flow hidden from inspection',
            'Potential for arbitrary code execution through remote bridge',
            'No visibility into actual credentials or tokens used'
          ],
          mitigation: 'Consider direct Linear API integration instead of mcp-remote bridge, implement audit logging for all remote MCP communications',
          aiConfidence: 1.0
        });
      }
    }

    // Check for auto-install flag (-y or --yes)
    if (args.includes('-y') || args.includes('--yes')) {
      risks.push({
        type: 'UNTRUSTED_NPX_DOWNLOAD',
        severity: 'high',
        description: `Server "${serverName}" uses npx -y for automatic package installation without user confirmation, enabling supply chain attacks`,
        evidence: ['npx command with -y flag', `Args: ${args.join(' ')}`],
        mitigation: 'Remove -y flag and pre-install packages, or use package version pinning',
        aiConfidence: 0.9
      });
    }

    return risks;
  }

  /**
   * Extract package name from npx/uvx arguments
   */
  private extractPackageName(args: string[]): string {
    // Look for package name after -y flag
    const yIndex = args.findIndex(arg => arg === '-y' || arg === '--yes');
    if (yIndex !== -1 && yIndex < args.length - 1) {
      return args[yIndex + 1];
    }

    // Fallback: first non-flag argument
    const nonFlagArg = args.find(arg => !arg.startsWith('-'));
    return nonFlagArg || 'unknown';
  }

  private analyzeUvxExecution(serverName: string, args: string[]): MCPRisk[] {
    const risks: MCPRisk[] = [];

    // Similar risks for uvx (Python package runner)
    risks.push({
      type: 'UNVERIFIED_PACKAGE',
      severity: 'medium',
      description: `Server "${serverName}" uses uvx for Python package execution without version pinning`,
      evidence: ['uvx command detected', `Args: ${args.join(' ')}`],
      mitigation: 'Use specific package versions and verify package integrity',
      aiConfidence: 0.8
    });

    return risks;
  }

  private analyzePipExecution(serverName: string, args: string[]): MCPRisk[] {
    const risks: MCPRisk[] = [];

    risks.push({
      type: 'SUPPLY_CHAIN_ATTACK',
      severity: 'medium',
      description: `Server "${serverName}" uses pip for package installation, potential supply chain risk`,
      evidence: ['pip command detected', `Args: ${args.join(' ')}`],
      mitigation: 'Use requirements.txt with pinned versions and verify package hashes',
      aiConfidence: 0.7
    });

    return risks;
  }

  private async analyzeDockerExecution(serverName: string, args: string[]): Promise<MCPRisk[]> {
    const risks: MCPRisk[] = [];

    // Use the proper Docker command parser
    const dockerConfig = DockerCommandParser.parseDockerRun(args);
    const dockerImage = dockerConfig.image;

    console.log(`DEBUG: Docker parsing result for ${serverName}:`, {
      image: dockerImage,
      isPrivileged: dockerConfig.isPrivileged,
      volumes: dockerConfig.volumes,
      networkMode: dockerConfig.networkMode
    });

    if (!dockerImage) {
      risks.push({
        type: 'UNVERIFIED_PACKAGE',
        severity: 'medium',
        description: `Server "${serverName}" has Docker command but no identifiable image`,
        evidence: ['Could not identify Docker image', `Args: ${args.join(' ')}`],
        mitigation: 'Ensure Docker image is properly specified',
        aiConfidence: 0.8
      });
      return risks;
    }

    // Check for privileged mode
    if (dockerConfig.isPrivileged) {
      risks.push({
        type: 'PRIVILEGED_CONTAINER',
        severity: 'critical',
        description: `Server "${serverName}" runs Docker container "${dockerImage}" in privileged mode, granting full system access`,
        evidence: ['--privileged flag detected', `Docker image: ${dockerImage}`],
        mitigation: 'Remove --privileged flag and use specific capabilities instead',
        aiConfidence: 0.95
      });
    }

    // Check for dangerous volume mounts
    const dangerousVolumes = dockerConfig.volumes.filter(mount =>
      mount.includes('/:/') || mount.includes('/var/run/docker.sock') ||
      mount.includes('/etc:/') || mount.includes('/usr:/') || mount.includes('/bin:/')
    );

    if (dangerousVolumes.length > 0) {
      risks.push({
        type: 'HOST_FILESYSTEM_ACCESS',
        severity: 'high',
        description: `Server "${serverName}" mounts sensitive host directories into Docker container`,
        evidence: dangerousVolumes.map(vol => `Dangerous mount: ${vol}`),
        mitigation: 'Restrict volume mounts to specific application directories only',
        aiConfidence: 0.9
      });
    }

    // Check for host networking
    if (dockerConfig.networkMode === 'host') {
      risks.push({
        type: 'NETWORK_EXPOSURE',
        severity: 'high',
        description: `Server "${serverName}" uses host networking, bypassing Docker network isolation`,
        evidence: ['Host networking mode detected', `Docker image: ${dockerImage}`],
        mitigation: 'Use bridge networking or specific port mappings instead of host networking',
        aiConfidence: 0.9
      });
    }

    // Perform actual OSV vulnerability scanning of the Docker image
    try {
      const osvResults = await this.sandboxManager.scanDockerImageWithOSV(dockerImage);

      if (osvResults.totalVulnerabilities > 0) {
        const { critical, high, medium, low } = osvResults.severityBreakdown;

        if (critical > 0) {
          risks.push({
            type: 'PRIVILEGED_CONTAINER', // Reusing enum for critical vulns
            severity: 'critical',
            description: `Server "${serverName}" uses Docker image "${dockerImage}" with ${critical} CRITICAL vulnerabilities`,
            evidence: osvResults.vulnerabilities
              .filter(v => v.severity === 'critical')
              .slice(0, 3)
              .map(v => `${v.id}: ${v.summary}`),
            mitigation: 'Update Docker image to a version without critical vulnerabilities',
            aiConfidence: 1.0
          });
        }

        if (high > 0) {
          risks.push({
            type: 'HOST_FILESYSTEM_ACCESS', // Reusing enum for high vulns
            severity: 'high',
            description: `Server "${serverName}" uses Docker image "${dockerImage}" with ${high} HIGH severity vulnerabilities`,
            evidence: osvResults.vulnerabilities
              .filter(v => v.severity === 'high')
              .slice(0, 3)
              .map(v => `${v.id}: ${v.summary}`),
            mitigation: 'Update Docker image or apply security patches',
            aiConfidence: 0.95
          });
        }

        if (medium > 0 && critical === 0 && high === 0) {
          risks.push({
            type: 'UNVERIFIED_PACKAGE',
            severity: 'medium',
            description: `Server "${serverName}" uses Docker image "${dockerImage}" with ${medium} MEDIUM severity vulnerabilities`,
            evidence: [`Total vulnerabilities: ${osvResults.totalVulnerabilities}`, `Medium: ${medium}, Low: ${low}`],
            mitigation: 'Consider updating Docker image for improved security',
            aiConfidence: 0.8
          });
        }
      } else {
        console.log(`✅ Docker image "${dockerImage}" - No vulnerabilities found`);
      }
    } catch (error) {
      // If OSV scanning fails, don't flag the image as insecure - just log the issue
      console.warn(`OSV scanning failed for Docker image "${dockerImage}": ${error instanceof Error ? error.message : String(error)}`);
      risks.push({
        type: 'UNVERIFIED_PACKAGE',
        severity: 'medium',
        description: `Server "${serverName}" uses Docker image "${dockerImage}" - vulnerability scanning failed`,
        evidence: ['OSV Scanner could not analyze image', `Error: ${error instanceof Error ? error.message : String(error)}`],
        mitigation: 'Manually verify Docker image security or check OSV Scanner configuration',
        aiConfidence: 0.5
      });
    }

    return risks;
  }

  private analyzeCommandInjectionRisks(serverName: string, args: string[]): MCPRisk[] {
    const risks: MCPRisk[] = [];

    // Check for suspicious patterns in arguments
    const suspiciousPatterns = [';', '&&', '||', '`', '$', '|'];
    const dangerousArgs = args.filter(arg =>
      suspiciousPatterns.some(pattern => arg.includes(pattern))
    );

    if (dangerousArgs.length > 0) {
      risks.push({
        type: 'COMMAND_INJECTION',
        severity: 'critical',
        description: `Server "${serverName}" has arguments containing shell metacharacters that could enable command injection`,
        evidence: dangerousArgs.map(arg => `Dangerous arg: "${arg}"`),
        mitigation: 'Sanitize or remove shell metacharacters from arguments',
        aiConfidence: 0.95
      });
    }

    return risks;
  }

  private analyzeCredentialExposure(serverName: string, args: string[], env?: any): MCPRisk[] {
    const risks: MCPRisk[] = [];

    // Check for credentials in arguments
    const credentialPatterns = ['--api-key', '--password', '--token', '--secret'];
    const exposedCredentials = [];

    for (let i = 0; i < args.length; i++) {
      const arg = args[i].toLowerCase();
      if (credentialPatterns.some(pattern => arg.includes(pattern))) {
        const nextArg = args[i + 1];
        if (nextArg && !nextArg.startsWith('--')) {
          // Check if it's a plaintext credential (not an env var)
          if (!nextArg.startsWith('$') && !nextArg.includes('YOUR_') && nextArg.length > 10) {
            exposedCredentials.push(`${args[i]}: ${nextArg.substring(0, 10)}...`);
          }
        }
      }
    }

    if (exposedCredentials.length > 0) {
      risks.push({
        type: 'CREDENTIAL_INTERCEPTION',
        severity: 'critical',
        description: `Server "${serverName}" exposes credentials in command line arguments, visible in process lists`,
        evidence: exposedCredentials,
        mitigation: 'Use environment variables or configuration files for credentials',
        aiConfidence: 0.9
      });
    }

    return risks;
  }

  private extractPackageInfo(args: string[], packageAnalysis: any): void {
    // Look for package names in args (typically after -y flag for npx)
    let yIndex = args.findIndex(arg => arg === '-y');
    if (yIndex !== -1 && yIndex < args.length - 1) {
      const packageName = args[yIndex + 1];

      // Check for bridge/proxy patterns
      const bridgeKeywords = ['remote', 'bridge', 'proxy', 'tunnel', 'connector'];
      if (bridgeKeywords.some(keyword => packageName.toLowerCase().includes(keyword))) {
        packageAnalysis.bridgePackages.push(packageName);
      }

      // TODO: TEMPORARY HARDCODED LIST - Should be refactored to pattern matching
      // Check for legitimate MCP package patterns to filter out false positives
      const legitimateMcpPatterns = ['mcp-', '@modelcontextprotocol/'];
      // Pattern-based detection instead of hardcoded company names
      const hasLegitimatePattern = legitimateMcpPatterns.some(pattern => packageName.includes(pattern)) ||
                                 /^@[a-z]+\/mcp-/.test(packageName); // Scoped MCP packages
      if (hasLegitimatePattern) {
        // This is expected, but we track it
      } else {
        // Unusual package name
        packageAnalysis.suspiciousPackages.push(packageName);
      }

      packageAnalysis.untrustedDownloads.push(packageName);
    }
  }

  private extractNetworkEndpoints(args: string[], networkAnalysis: any): void {
    // Look for URLs in arguments
    const urlPattern = /https?:\/\/[^\s]+/g;

    for (const arg of args) {
      const urls = arg.match(urlPattern);
      if (urls) {
        urls.forEach(url => {
          networkAnalysis.remoteEndpoints.push(url);

          // Check for insecure protocols
          if (url.startsWith('http://')) {
            networkAnalysis.insecureProtocols.push(url);
          }

          // Check for authentication gaps (no obvious auth in URL)
          if (!url.includes('token=') && !url.includes('key=') && !url.includes('auth=')) {
            networkAnalysis.authenticationGaps.push(url);
          }
        });
      }
    }
  }

  private extractDockerImageInfo(args: string[], packageAnalysis: any): void {
    // Find Docker image in args
    let dockerImage = '';

    // Look for 'run' command and extract image
    for (let i = 0; i < args.length; i++) {
      if (args[i] === 'run') {
        // Find the image name (first non-flag argument after run)
        for (let j = i + 1; j < args.length; j++) {
          if (!args[j].startsWith('-')) {
            dockerImage = args[j];
            break;
          }
        }
        break;
      }
    }

    if (!dockerImage && args.length > 0 && !args[0].startsWith('-')) {
      dockerImage = args[0];
    }

    if (dockerImage) {
      // Check for bridge/proxy patterns in image names
      const bridgeKeywords = ['remote', 'bridge', 'proxy', 'tunnel', 'connector', 'gateway'];
      if (bridgeKeywords.some(keyword => dockerImage.toLowerCase().includes(keyword))) {
        packageAnalysis.bridgePackages.push(dockerImage);
      }

      // TODO: TEMPORARY HARDCODED LIST - Should be refactored to pattern matching
      // Check for legitimate MCP Docker image patterns
      const legitimateMcpPatterns = ['mcp-', 'mcp/'];
      // Pattern-based detection instead of hardcoded company names
      const hasLegitimatePattern = legitimateMcpPatterns.some(pattern => dockerImage.includes(pattern)) ||
                                 /\/mcp-/.test(dockerImage); // Images with mcp- in path
      if (!hasLegitimatePattern) {
        // Unusual Docker image name for MCP context
        packageAnalysis.suspiciousPackages.push(dockerImage);
      }

      packageAnalysis.untrustedDownloads.push(dockerImage);
    }
  }

  private isTrustedDockerHubImage(imageName: string): boolean {
    // List of commonly trusted base images and official images
    const trustedImages = [
      'node', 'python', 'alpine', 'ubuntu', 'debian', 'nginx', 'redis',
      'postgres', 'mysql', 'mongo', 'elasticsearch', 'rabbitmq',
      'httpd', 'tomcat', 'openjdk', 'golang', 'rust', 'php'
    ];

    const imageBase = imageName.split(':')[0].split('/').pop() || '';
    return trustedImages.includes(imageBase);
  }

  private calculateOverallRiskLevel(risks: MCPRisk[]): 'critical' | 'high' | 'medium' | 'low' {
    if (risks.some(r => r.severity === 'critical')) return 'critical';
    if (risks.some(r => r.severity === 'high')) return 'high';
    if (risks.some(r => r.severity === 'medium')) return 'medium';
    return 'low';
  }

  private generateRecommendations(risks: MCPRisk[], packageAnalysis: any, networkAnalysis: any): string[] {
    const recommendations = new Set<string>();

    // Add recommendations based on found risks
    risks.forEach(risk => {
      recommendations.add(risk.mitigation);
    });

    // Add specific recommendations based on analysis
    if (packageAnalysis.untrustedDownloads.length > 0) {
      recommendations.add('Pre-install and verify all MCP packages before deployment');
      recommendations.add('Use package version pinning to prevent supply chain attacks');
    }

    if (networkAnalysis.insecureProtocols.length > 0) {
      recommendations.add('Replace HTTP endpoints with HTTPS for secure communication');
    }

    if (networkAnalysis.authenticationGaps.length > 0) {
      recommendations.add('Implement proper authentication for remote endpoints');
    }

    return Array.from(recommendations);
  }

  private generateAnalysisSummary(riskCount: number, packageAnalysis: any, networkAnalysis: any, overallRisk: string): string {
    const summary = `MCP JSON configuration analysis completed. Found ${riskCount} security risks. ` +
      `Detected ${packageAnalysis.untrustedDownloads.length} package downloads, ` +
      `${packageAnalysis.bridgePackages.length} potential bridge packages, ` +
      `${networkAnalysis.remoteEndpoints.length} remote endpoints. ` +
      `Overall risk level: ${overallRisk.toUpperCase()}.`;

    return summary;
  }

  // Helper methods
  private async fetchNPMInfo(packageName: string): Promise<any> {
    try {
      const { stdout } = await execAsync(`npm view ${packageName} --json`);
      return JSON.parse(stdout);
    } catch (error) {
      throw new Error(`Failed to fetch npm info for ${packageName}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async fetchGitHubInfo(repository: any): Promise<any> {
    // GitHub API integration would go here
    return { placeholder: 'github_analysis' };
  }

  private detectBridgePattern(packageName: string, npmInfo: any): boolean {
    const bridgeKeywords = ['bridge', 'proxy', 'remote', 'connector', 'wrapper'];
    const nameMatches = bridgeKeywords.some(keyword => packageName.toLowerCase().includes(keyword));

    const descriptionMatches = npmInfo?.description ?
      bridgeKeywords.some(keyword => npmInfo.description.toLowerCase().includes(keyword)) : false;

    return nameMatches || descriptionMatches;
  }

  private calculateTrustScore(npmInfo: any): number {
    let score = 0.5; // Base score

    if (npmInfo?.downloads?.weekly > 1000) score += 0.2;
    if (npmInfo?.downloads?.weekly > 10000) score += 0.1;
    if (npmInfo?.maintainers?.length > 1) score += 0.1;
    if (npmInfo?.time?.created && new Date(npmInfo.time.created) < new Date('2023-01-01')) score += 0.1;

    return Math.min(1.0, score);
  }

  private generateSecurityFlags(npmInfo: any, isBridge: boolean): string[] {
    const flags: string[] = [];

    if (isBridge) flags.push('Potential auth bridge package');
    if (npmInfo?.downloads?.weekly < 100) flags.push('Low download count');
    if (npmInfo?.maintainers?.length === 1) flags.push('Single maintainer');
    if (!npmInfo?.repository) flags.push('No repository link');

    return flags;
  }

  private assessPackageRisk(npmInfo: any, isBridge: boolean, trustScore: number): 'critical' | 'high' | 'medium' | 'low' {
    if (isBridge && trustScore < 0.3) return 'critical';
    if (isBridge && trustScore < 0.6) return 'high';
    if (trustScore < 0.3) return 'high';
    if (trustScore < 0.6) return 'medium';
    return 'low';
  }

  private async monitorExecution(sandboxId: string, duration: number): Promise<any> {
    // Monitor sandbox execution for specified duration
    return { monitored: true, duration };
  }

  private extractTokens(result: any): string[] {
    // Extract authentication tokens from network traffic
    return [];
  }

  private detectBridges(result: any): any[] {
    // Detect bridge processes in execution
    return [];
  }

  private detectAuthFlow(result: any): boolean {
    // Detect authentication flows
    return false;
  }

  private analyzeCredentialFlows(trafficLog: any): any[] {
    // Analyze credential flows in network traffic
    return [];
  }

  private detectHiddenAuth(trafficLog: any): boolean {
    // Detect hidden authentication patterns
    return false;
  }

  private parseAISecurityAnalysis(aiResponse: string): MCPJsonAnalysis {
    try {
      // Try to extract JSON from AI response
      const jsonMatch = aiResponse.match(/```json\n?([\s\S]*?)\n?```/) ||
                       aiResponse.match(/\{[\s\S]*\}/);

      if (jsonMatch) {
        const jsonStr = jsonMatch[1] || jsonMatch[0];
        const parsed = JSON.parse(jsonStr);
        return MCPJsonAnalysisSchema.parse(parsed);
      }

      // Fallback if no JSON found
      return this.generateFallbackAnalysis(aiResponse);
    } catch (error) {
      console.error('Failed to parse AI analysis:', error);
      return this.generateFallbackAnalysis(aiResponse);
    }
  }

  private generateFallbackAnalysis(aiResponse: string): MCPJsonAnalysis {
    return {
      overallRisk: 'medium',
      risks: [{
        type: 'MISSING_AUTHENTICATION',
        severity: 'medium',
        description: 'AI analysis failed to parse structured output',
        evidence: ['Analysis parsing error'],
        mitigation: 'Manual review required'
      }],
      packageAnalysis: {
        suspiciousPackages: [],
        bridgePackages: [],
        untrustedDownloads: []
      },
      networkAnalysis: {
        remoteEndpoints: [],
        insecureProtocols: [],
        authenticationGaps: []
      },
      recommendations: ['Manual security review required due to analysis failure'],
      summary: 'AI analysis could not be parsed properly. Manual review recommended.'
    };
  }

}