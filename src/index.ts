/**
 * MCP Security Scanner
 * Dual-mode security analysis tool for MCP (Model Context Protocol) servers
 */

import { z } from 'zod';
import { configManager } from './config';
import { SandboxManager } from './sandbox/sandbox-manager';
import { AIAnalyzer, type SecurityAnalysis } from './analysis/ai-analyzer';
import { DependencyAnalyzer, type DependencyAnalysisResult } from './analysis/dependency-analyzer';
import { MCPJsonAnalyzer, type MCPJsonAnalysis } from './analysis/mcp-json-analyzer';
import { ParallelAnalysisOrchestrator, type ParallelAnalysisResult } from './analysis/parallel-orchestrator';
import { OSVService } from './services/osv-service';

export type ScanMode = 'static' | 'dynamic' | 'hybrid' | 'json';

export interface ScanOptions {
  mode?: ScanMode;
  sourceCodeUrl?: string; // GitHub/GitLab URL for static analysis
  mcpJsonConfig?: any; // MCP JSON configuration for black box analysis
  timeout?: number;
  skipDependencyAnalysis?: boolean;
  skipBehavioralAnalysis?: boolean;
  apiKey?: string; // API key for authenticated MCP servers
}

export interface ComprehensiveScanResult {
  scanMode: ScanMode;
  timestamp: Date;
  duration: number;

  // Static analysis results (when source code available)
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

  // Dynamic analysis results (when MCP server is available)
  behavioralAnalysis?: SecurityAnalysis;

  // Black box MCP JSON analysis results
  mcpJsonAnalysis?: MCPJsonAnalysis;

  // MCP prompt security analysis results (new)
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
      confidence: number;
    }>;
    summary: string;
  };

  // Combined assessment
  overallRisk: 'critical' | 'high' | 'medium' | 'low';
  summary: string;
  recommendations: string[];
}

export class MCPSecurityScanner {
  private sandboxManager: SandboxManager;
  private aiAnalyzer: AIAnalyzer;
  private dependencyAnalyzer: DependencyAnalyzer;
  private mcpJsonAnalyzer: MCPJsonAnalyzer;
  private parallelOrchestrator: ParallelAnalysisOrchestrator;
  private osvService: OSVService;
  private isInitialized = false;

  constructor() {

    this.sandboxManager = new SandboxManager(configManager.getSandboxConfig());
    this.aiAnalyzer = new AIAnalyzer(configManager.getAIAnalyzerConfig());
    this.osvService = new OSVService();
    this.dependencyAnalyzer = new DependencyAnalyzer(this.osvService);
    this.mcpJsonAnalyzer = new MCPJsonAnalyzer(this.aiAnalyzer['aiRouter'], this.sandboxManager);
    this.parallelOrchestrator = new ParallelAnalysisOrchestrator(
      this.sandboxManager,
      this.aiAnalyzer,
      this.dependencyAnalyzer,
      this.mcpJsonAnalyzer,
      this.osvService
    );

    console.log('MCP Security Scanner initialized');
  }

  async initialize(): Promise<void> {
    if (this.isInitialized) return;

    await this.sandboxManager.initialize();
    await this.aiAnalyzer.initialize();

    this.isInitialized = true;

    configManager.logConfig();
    console.log(`Scanner ready - Sandbox: ${this.sandboxManager.getCurrentProvider()}, AI: ${this.aiAnalyzer.getCurrentProvider()}`);
  }

  async scan(mcpServerPath: string, options: ScanOptions = {}): Promise<ComprehensiveScanResult> {
    await this.initialize();

    const startTime = Date.now();
    const scanMode = this.determineScanMode(options);

    console.log(`Starting ${scanMode.toUpperCase()} analysis of MCP server: ${mcpServerPath}`);

    let parallelResults: ParallelAnalysisResult | undefined;

    // Static Analysis with Parallel Execution (when source code is available)
    if ((scanMode === 'static' || scanMode === 'hybrid') && options.sourceCodeUrl) {
      console.log('🚀 Performing parallel static analysis...');

      try {
        parallelResults = await this.parallelOrchestrator.executeParallelStaticAnalysis(
          options.sourceCodeUrl,
          {
            skipDependencyAnalysis: options.skipDependencyAnalysis,
            timeout: options.timeout
          }
        );

        console.log(`📊 Parallel static analysis complete:`);
        console.log(`   Dependencies: ${parallelResults.dependencyAnalysis?.vulnerabilityReport.totalVulnerabilities || 0} vulnerabilities`);
        console.log(`   Source code: ${parallelResults.sourceCodeAnalysis?.vulnerabilities.length || 0} vulnerabilities`);
        console.log(`   MCP prompts: ${parallelResults.mcpPromptSecurityAnalysis?.risks.length || 0} risks`);
        console.log(`   ⚡ Time savings: ${parallelResults.executionMetrics.parallelSavings}ms`);

      } catch (error) {
        throw new Error(`Parallel static analysis failed: ${error}`);
      }
    }

    // Dynamic Analysis (when MCP server is available)
    let behavioralAnalysis: SecurityAnalysis | undefined;
    if (!options.skipBehavioralAnalysis && scanMode !== 'json') {
      try {
        behavioralAnalysis = await this.parallelOrchestrator.executeBehavioralAnalysis(mcpServerPath, {
          timeout: options.timeout
        });

        if (behavioralAnalysis) {
          console.log(`Behavioral analysis complete: ${behavioralAnalysis.risks.length} security risks identified`);
        }
      } catch (error) {
        // For static-only mode or when MCP server is not available, allow the scan to continue
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (mcpServerPath === 'static-analysis-only' || errorMessage.includes('Static-only analysis mode')) {
          console.log('⚠️  Behavioral analysis skipped: Static-only analysis mode');
          behavioralAnalysis = undefined;
        } else {
          throw new Error(`Behavioral analysis failed: ${error}`);
        }
      }
    } else if (scanMode === 'json') {
      console.log('⚠️  Behavioral analysis skipped: JSON-only analysis mode');
      behavioralAnalysis = undefined;
    }

    // Black Box MCP JSON Analysis with Docker Behavioral Analysis
    let mcpJsonAnalysis: MCPJsonAnalysis | undefined;
    let dockerBehavioralAnalysis: any[] | undefined;
    if (scanMode === 'json' && options.mcpJsonConfig) {
      try {
        // Check if API key is needed for Docker/remote servers before starting analysis
        if (!options.apiKey) {
          options.apiKey = await this.promptForApiKeyIfNeeded(options.mcpJsonConfig);
        }

        const enhancedAnalysis = await this.parallelOrchestrator.executeMCPJsonAnalysis(options.mcpJsonConfig, { apiKey: options.apiKey });
        mcpJsonAnalysis = enhancedAnalysis;
        dockerBehavioralAnalysis = (enhancedAnalysis as any).dockerBehavioralAnalysis;

        console.log(`MCP JSON analysis complete: ${mcpJsonAnalysis.risks.length} security risks identified`);
        if (dockerBehavioralAnalysis && dockerBehavioralAnalysis.length > 0) {
          const nativeDockerCount = dockerBehavioralAnalysis.filter((result: any) => !result.serverName.includes('-proxy-sandbox')).length;
          const proxyServerCount = dockerBehavioralAnalysis.filter((result: any) => result.serverName.includes('-proxy-sandbox')).length;

          if (nativeDockerCount > 0 && proxyServerCount > 0) {
            console.log(`🐳 Docker behavioral analysis: ${nativeDockerCount} Docker servers + ${proxyServerCount} proxy servers analyzed with runtime behavior`);
          } else if (nativeDockerCount > 0) {
            console.log(`🐳 Docker behavioral analysis: ${nativeDockerCount} Docker servers analyzed with runtime behavior`);
          } else {
            console.log(`🔗 Proxy behavioral analysis: ${proxyServerCount} proxy servers analyzed in Docker sandbox isolation`);
          }
        }
      } catch (error) {
        throw new Error(`MCP JSON analysis failed: ${error}`);
      }
    }

    // Combine results and generate comprehensive assessment
    const result = this.generateComprehensiveResult(
      scanMode,
      startTime,
      parallelResults?.dependencyAnalysis,
      parallelResults?.sourceCodeAnalysis,
      behavioralAnalysis,
      mcpJsonAnalysis,
      parallelResults?.mcpPromptSecurityAnalysis
    );

    // Add Docker behavioral analysis results to the result
    if (dockerBehavioralAnalysis && dockerBehavioralAnalysis.length > 0) {
      (result as any).dockerBehavioralAnalysis = dockerBehavioralAnalysis;
    }

    console.log(`Scan complete in ${result.duration}ms - Overall risk: ${result.overallRisk.toUpperCase()}`);

    return result;
  }

  async cleanup(): Promise<void> {
    await Promise.all([
      this.sandboxManager.cleanup(),
      this.aiAnalyzer.cleanup()
    ]);

    this.isInitialized = false;
    console.log('Scanner cleanup complete');
  }

  private determineScanMode(options: ScanOptions): ScanMode {
    if (options.mode) return options.mode;

    // Auto-determine based on available information
    return options.sourceCodeUrl ? 'hybrid' : 'dynamic';
  }


  private generateComprehensiveResult(
    scanMode: ScanMode,
    startTime: number,
    dependencyAnalysis?: DependencyAnalysisResult,
    sourceCodeAnalysis?: ComprehensiveScanResult['sourceCodeAnalysis'],
    behavioralAnalysis?: SecurityAnalysis,
    mcpJsonAnalysis?: MCPJsonAnalysis,
    mcpPromptSecurityAnalysis?: ComprehensiveScanResult['mcpPromptSecurityAnalysis']
  ): ComprehensiveScanResult {
    // For static-only mode, behavioral analysis is optional
    // For JSON mode, MCP JSON analysis is required
    if (!behavioralAnalysis && scanMode !== 'static' && scanMode !== 'json') {
      throw new Error('Behavioral analysis is required for comprehensive results in dynamic/hybrid modes');
    }

    if (!mcpJsonAnalysis && scanMode === 'json') {
      throw new Error('MCP JSON analysis is required for JSON mode');
    }

    // Determine overall risk by combining all analysis results
    const overallRisk = this.calculateOverallRisk(
      dependencyAnalysis,
      sourceCodeAnalysis,
      behavioralAnalysis,
      mcpJsonAnalysis,
      mcpPromptSecurityAnalysis
    );

    // Generate comprehensive summary
    const summary = this.generateComprehensiveSummary(
      scanMode,
      dependencyAnalysis,
      sourceCodeAnalysis,
      behavioralAnalysis,
      mcpJsonAnalysis,
      overallRisk
    );

    // Combine recommendations from all analyses
    const recommendations = this.combineRecommendations(
      dependencyAnalysis,
      sourceCodeAnalysis,
      behavioralAnalysis,
      mcpJsonAnalysis
    );

    return {
      scanMode,
      timestamp: new Date(),
      duration: Date.now() - startTime,
      dependencyAnalysis,
      sourceCodeAnalysis,
      behavioralAnalysis,
      mcpJsonAnalysis,
      mcpPromptSecurityAnalysis,
      overallRisk,
      summary,
      recommendations
    };
  }

  private calculateOverallRisk(
    dependencyAnalysis?: DependencyAnalysisResult,
    sourceCodeAnalysis?: ComprehensiveScanResult['sourceCodeAnalysis'],
    behavioralAnalysis?: SecurityAnalysis,
    mcpJsonAnalysis?: MCPJsonAnalysis,
    mcpPromptSecurityAnalysis?: ComprehensiveScanResult['mcpPromptSecurityAnalysis']
  ): 'critical' | 'high' | 'medium' | 'low' {
    const riskLevels: Array<'critical' | 'high' | 'medium' | 'low'> = [];

    // Behavioral analysis risk
    if (behavioralAnalysis) {
      riskLevels.push(behavioralAnalysis.overallRisk);
    }

    // MCP JSON analysis risk
    if (mcpJsonAnalysis) {
      riskLevels.push(mcpJsonAnalysis.overallRisk);
    }

    // Dependency analysis risk
    if (dependencyAnalysis) {
      const { critical, high, medium } = dependencyAnalysis.vulnerabilityReport.severityBreakdown;
      if (critical > 0) riskLevels.push('critical');
      else if (high > 0) riskLevels.push('high');
      else if (medium > 0) riskLevels.push('medium');
      else riskLevels.push('low');
    }

    // Source code analysis risk
    if (sourceCodeAnalysis) {
      const hasCritical = sourceCodeAnalysis.vulnerabilities.some(v => v.severity === 'critical');
      const hasHigh = sourceCodeAnalysis.vulnerabilities.some(v => v.severity === 'high');

      if (hasCritical) riskLevels.push('critical');
      else if (hasHigh) riskLevels.push('high');
      else if (sourceCodeAnalysis.vulnerabilities.length > 0) riskLevels.push('medium');
      else riskLevels.push('low');
    }

    // MCP prompt security analysis risk
    if (mcpPromptSecurityAnalysis) {
      const hasCritical = mcpPromptSecurityAnalysis.risks.some(r => r.severity === 'critical');
      const hasHigh = mcpPromptSecurityAnalysis.risks.some(r => r.severity === 'high');

      if (hasCritical) riskLevels.push('critical');
      else if (hasHigh) riskLevels.push('high');
      else if (mcpPromptSecurityAnalysis.risks.length > 0) riskLevels.push('medium');
      else riskLevels.push('low');
    }

    // Return the highest risk level found
    if (riskLevels.includes('critical')) return 'critical';
    if (riskLevels.includes('high')) return 'high';
    if (riskLevels.includes('medium')) return 'medium';
    return 'low';
  }

  private generateComprehensiveSummary(
    scanMode: ScanMode,
    dependencyAnalysis?: DependencyAnalysisResult,
    sourceCodeAnalysis?: ComprehensiveScanResult['sourceCodeAnalysis'],
    behavioralAnalysis?: SecurityAnalysis,
    mcpJsonAnalysis?: MCPJsonAnalysis,
    overallRisk?: string
  ): string {
    const analysisTypes = [];
    if (dependencyAnalysis) analysisTypes.push('dependency scanning');
    if (sourceCodeAnalysis) analysisTypes.push('source code analysis');
    if (behavioralAnalysis) analysisTypes.push('behavioral analysis');
    if (mcpJsonAnalysis) analysisTypes.push('MCP JSON configuration analysis');

    let summary = `${scanMode.toUpperCase()} security analysis completed using ${analysisTypes.join(', ')}. `;

    if (dependencyAnalysis) {
      const { totalVulnerabilities, vulnerablePackages } = dependencyAnalysis.vulnerabilityReport;
      summary += `Found ${totalVulnerabilities} dependency vulnerabilities across ${vulnerablePackages} packages. `;
    }

    if (sourceCodeAnalysis) {
      summary += `Identified ${sourceCodeAnalysis.vulnerabilities.length} code-level security issues. `;
    }

    if (behavioralAnalysis) {
      summary += `Detected ${behavioralAnalysis.risks.length} behavioral security risks during sandbox execution. `;
    }

    summary += `Overall security risk assessed as ${overallRisk?.toUpperCase()}. `;

    if (overallRisk === 'critical' || overallRisk === 'high') {
      summary += 'Immediate security review and remediation required before production deployment.';
    } else if (overallRisk === 'medium') {
      summary += 'Security issues identified that should be addressed in next development cycle.';
    } else {
      summary += 'No critical security issues identified, but continued monitoring recommended.';
    }

    return summary;
  }

  /**
   * Check if API key is needed for Docker/remote servers and prompt user
   */
  private async promptForApiKeyIfNeeded(mcpJsonConfig: any): Promise<string | undefined> {
    // Extract Docker configurations to check if any need authentication
    const servers = mcpJsonConfig.mcpServers || {};
    let needsApiKey = false;

    for (const [serverName, serverConfig] of Object.entries(servers)) {
      const config = serverConfig as any;
      const env = config.env || {};

      // Check if this server has environment variables that look like API keys with placeholder values
      const hasApiKeyPlaceholder = Object.entries(env).some(([key, value]) => {
        const keyUpper = key.toUpperCase();
        const valueStr = String(value);
        return (keyUpper.includes('API') && keyUpper.includes('KEY')) &&
               (valueStr.includes('YOUR_') || valueStr.includes('PLACEHOLDER') || valueStr.includes('HERE'));
      });

      if (hasApiKeyPlaceholder) {
        needsApiKey = true;
        break;
      }
    }

    if (!needsApiKey) {
      return undefined;
    }

    // Prompt for API key
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
      console.log('\n🔑 API Key Required');
      console.log('   Detected servers that need authentication');
      const apiKey = await question('Enter API key: ');

      if (apiKey.trim()) {
        console.log('✅ API key provided');
        return apiKey.trim();
      } else {
        console.log('⚠️  No API key provided - continuing without authentication');
        return undefined;
      }
    } finally {
      rl.close();
    }
  }

  private combineRecommendations(
    dependencyAnalysis?: DependencyAnalysisResult,
    sourceCodeAnalysis?: ComprehensiveScanResult['sourceCodeAnalysis'],
    behavioralAnalysis?: SecurityAnalysis,
    mcpJsonAnalysis?: MCPJsonAnalysis
  ): string[] {
    const recommendations = new Set<string>();

    if (behavioralAnalysis) {
      behavioralAnalysis.recommendations.forEach((rec: string) => recommendations.add(rec));
    }

    if (mcpJsonAnalysis) {
      mcpJsonAnalysis.recommendations.forEach((rec: string) => recommendations.add(rec));
    }

    if (sourceCodeAnalysis) {
      sourceCodeAnalysis.suggestions.forEach((rec: string) => recommendations.add(rec));
    }

    if (dependencyAnalysis) {
      const { critical, high, medium } = dependencyAnalysis.vulnerabilityReport.severityBreakdown;

      if (critical > 0) {
        recommendations.add('URGENT: Update dependencies with critical vulnerabilities immediately');
      }
      if (high > 0) {
        recommendations.add('Update dependencies with high-severity vulnerabilities');
      }
      if (medium > 0) {
        recommendations.add('Schedule updates for dependencies with medium-severity vulnerabilities');
      }
      if (dependencyAnalysis.vulnerabilityReport.totalVulnerabilities > 0) {
        recommendations.add('Implement automated dependency vulnerability monitoring');
        recommendations.add('Establish regular dependency update cycle');
      }
    }

    return Array.from(recommendations);
  }
}

// CLI entry point - commented out for ES module compatibility
// if (require.main === module) {
//   const scanner = new MCPSecurityScanner();
//   console.log('MCP Security Scanner v0.1.0');
// }