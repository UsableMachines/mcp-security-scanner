/**
 * MCP Security Scanner
 * Dual-mode security analysis tool for MCP (Model Context Protocol) servers
 */

import { z } from 'zod';
import { configManager } from './config';
import { SandboxManager } from './sandbox/sandbox-manager';
import { AIAnalyzer, type SecurityAnalysis } from './analysis/ai-analyzer';
import { DependencyAnalyzer, type DependencyAnalysisResult } from './analysis/dependency-analyzer';
import { OSVService } from './services/osv-service';

export type ScanMode = 'static' | 'dynamic' | 'hybrid';

export interface ScanOptions {
  mode?: ScanMode;
  sourceCodeUrl?: string; // GitHub/GitLab URL for static analysis
  timeout?: number;
  skipDependencyAnalysis?: boolean;
  skipBehavioralAnalysis?: boolean;
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

  // Dynamic analysis results (always performed)
  behavioralAnalysis: SecurityAnalysis;

  // Combined assessment
  overallRisk: 'critical' | 'high' | 'medium' | 'low';
  summary: string;
  recommendations: string[];
}

export class MCPSecurityScanner {
  private sandboxManager: SandboxManager;
  private aiAnalyzer: AIAnalyzer;
  private dependencyAnalyzer: DependencyAnalyzer;
  private osvService: OSVService;
  private isInitialized = false;

  constructor() {
    const config = configManager.config;

    this.sandboxManager = new SandboxManager(configManager.getSandboxConfig());
    this.aiAnalyzer = new AIAnalyzer(configManager.getAIAnalyzerConfig());
    this.osvService = new OSVService();
    this.dependencyAnalyzer = new DependencyAnalyzer(this.osvService);

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

    let dependencyAnalysis: DependencyAnalysisResult | undefined;
    let sourceCodeAnalysis: ComprehensiveScanResult['sourceCodeAnalysis'] | undefined;

    // Static Analysis (when source code is available)
    if ((scanMode === 'static' || scanMode === 'hybrid') && options.sourceCodeUrl) {
      console.log('Performing static analysis...');

      if (!options.skipDependencyAnalysis) {
        try {
          dependencyAnalysis = await this.performDependencyAnalysis(options.sourceCodeUrl);
          console.log(`Dependency analysis complete: ${dependencyAnalysis.vulnerabilityReport.totalVulnerabilities} vulnerabilities found`);
        } catch (error) {
          throw new Error(`Dependency analysis failed: ${error}`);
        }
      }

      try {
        sourceCodeAnalysis = await this.performSourceCodeAnalysis(options.sourceCodeUrl);
        console.log(`Source code analysis complete: ${sourceCodeAnalysis?.vulnerabilities.length || 0} code vulnerabilities found`);
      } catch (error) {
        throw new Error(`Source code analysis failed: ${error}`);
      }
    }

    // Dynamic Analysis (always performed)
    let behavioralAnalysis: SecurityAnalysis;
    if (!options.skipBehavioralAnalysis) {
      console.log('Performing behavioral analysis in sandbox...');
      try {
        behavioralAnalysis = await this.performBehavioralAnalysis(mcpServerPath, options);
        console.log(`Behavioral analysis complete: ${behavioralAnalysis.risks.length} security risks identified`);
      } catch (error) {
        throw new Error(`Behavioral analysis failed: ${error}`);
      }
    } else {
      throw new Error('Cannot skip behavioral analysis - it is required for comprehensive security assessment');
    }

    // Combine results and generate comprehensive assessment
    const result = this.generateComprehensiveResult(
      scanMode,
      startTime,
      dependencyAnalysis,
      sourceCodeAnalysis,
      behavioralAnalysis
    );

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

  private async performDependencyAnalysis(sourceCodeUrl: string): Promise<DependencyAnalysisResult> {
    // Check if it's a local path or remote URL
    if (sourceCodeUrl.startsWith('http://') || sourceCodeUrl.startsWith('https://')) {
      // Remote repository - use sandboxed analysis
      console.log(`Analyzing remote repository in sandbox: ${sourceCodeUrl}`);

      const sandboxProvider = await this.sandboxManager.getProvider();
      if (!sandboxProvider) {
        throw new Error('No sandbox provider available for repository cloning');
      }

      const result = await this.dependencyAnalyzer.analyzeRemoteRepository(
        sourceCodeUrl,
        sandboxProvider
      );

      console.log(`Repository cloned and analyzed in ${result.cloneResult.duration}ms (clone) + ${result.osvScanResult.duration}ms (scan)`);

      return result;
    } else {
      // Local path - use existing local analysis
      return await this.dependencyAnalyzer.analyzeMCPProject(sourceCodeUrl);
    }
  }

  private async performSourceCodeAnalysis(sourceCodeUrl: string): Promise<ComprehensiveScanResult['sourceCodeAnalysis']> {
    // For now, we expect the user to provide a local path or we clone the repo
    // This is a placeholder - in a real implementation, we'd clone the repo and analyze source
    throw new Error('Source code analysis from remote URLs not yet implemented - provide local project path');
  }

  private async performBehavioralAnalysis(
    mcpServerPath: string,
    options: ScanOptions
  ): Promise<SecurityAnalysis> {
    const timeout = options.timeout || configManager.config.SCANNER_TIMEOUT;

    // Execute MCP server in sandbox
    const sandboxResult = await this.sandboxManager.executeMCPServer(
      mcpServerPath,
      undefined, // MCP config - could be provided in options
      { timeout: timeout / 1000 } // Convert to seconds
    );

    // Analyze results with AI
    const analysis = await this.aiAnalyzer.analyzeMCPSecurity(
      sandboxResult,
      undefined, // Source code - not available in pure dynamic mode
      undefined  // MCP manifest - could be extracted from sandbox result
    );

    return analysis;
  }

  private generateComprehensiveResult(
    scanMode: ScanMode,
    startTime: number,
    dependencyAnalysis?: DependencyAnalysisResult,
    sourceCodeAnalysis?: ComprehensiveScanResult['sourceCodeAnalysis'],
    behavioralAnalysis?: SecurityAnalysis
  ): ComprehensiveScanResult {
    if (!behavioralAnalysis) {
      throw new Error('Behavioral analysis is required for comprehensive results');
    }

    // Determine overall risk by combining all analysis results
    const overallRisk = this.calculateOverallRisk(
      dependencyAnalysis,
      sourceCodeAnalysis,
      behavioralAnalysis
    );

    // Generate comprehensive summary
    const summary = this.generateComprehensiveSummary(
      scanMode,
      dependencyAnalysis,
      sourceCodeAnalysis,
      behavioralAnalysis,
      overallRisk
    );

    // Combine recommendations from all analyses
    const recommendations = this.combineRecommendations(
      dependencyAnalysis,
      sourceCodeAnalysis,
      behavioralAnalysis
    );

    return {
      scanMode,
      timestamp: new Date(),
      duration: Date.now() - startTime,
      dependencyAnalysis,
      sourceCodeAnalysis,
      behavioralAnalysis,
      overallRisk,
      summary,
      recommendations
    };
  }

  private calculateOverallRisk(
    dependencyAnalysis?: DependencyAnalysisResult,
    sourceCodeAnalysis?: ComprehensiveScanResult['sourceCodeAnalysis'],
    behavioralAnalysis?: SecurityAnalysis
  ): 'critical' | 'high' | 'medium' | 'low' {
    const riskLevels: Array<'critical' | 'high' | 'medium' | 'low'> = [];

    // Behavioral analysis risk (always present)
    if (behavioralAnalysis) {
      riskLevels.push(behavioralAnalysis.overallRisk);
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
    overallRisk?: string
  ): string {
    const analysisTypes = [];
    if (dependencyAnalysis) analysisTypes.push('dependency scanning');
    if (sourceCodeAnalysis) analysisTypes.push('source code analysis');
    if (behavioralAnalysis) analysisTypes.push('behavioral analysis');

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

  private combineRecommendations(
    dependencyAnalysis?: DependencyAnalysisResult,
    sourceCodeAnalysis?: ComprehensiveScanResult['sourceCodeAnalysis'],
    behavioralAnalysis?: SecurityAnalysis
  ): string[] {
    const recommendations = new Set<string>();

    if (behavioralAnalysis) {
      behavioralAnalysis.recommendations.forEach(rec => recommendations.add(rec));
    }

    if (sourceCodeAnalysis) {
      sourceCodeAnalysis.suggestions.forEach(rec => recommendations.add(rec));
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

// CLI entry point
if (require.main === module) {
  const scanner = new MCPSecurityScanner();
  console.log('MCP Security Scanner v0.1.0');
}