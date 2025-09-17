/**
 * MCP Security Scanner
 * Dual-mode security analysis tool for MCP (Model Context Protocol) servers
 */

import { z } from 'zod';
import { promisify } from 'util';
import { exec } from 'child_process';
import * as fs from 'fs';
import { configManager } from './config';
import { SandboxManager } from './sandbox/sandbox-manager';
import { AIAnalyzer, type SecurityAnalysis } from './analysis/ai-analyzer';
import { DependencyAnalyzer, type DependencyAnalysisResult } from './analysis/dependency-analyzer';
import { MCPJsonAnalyzer, type MCPJsonAnalysis } from './analysis/mcp-json-analyzer';
import { OSVService } from './services/osv-service';

export type ScanMode = 'static' | 'dynamic' | 'hybrid' | 'json';

export interface ScanOptions {
  mode?: ScanMode;
  sourceCodeUrl?: string; // GitHub/GitLab URL for static analysis
  mcpJsonConfig?: any; // MCP JSON configuration for black box analysis
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

  // Dynamic analysis results (when MCP server is available)
  behavioralAnalysis?: SecurityAnalysis;

  // Black box MCP JSON analysis results
  mcpJsonAnalysis?: MCPJsonAnalysis;

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
  private osvService: OSVService;
  private isInitialized = false;

  constructor() {
    const config = configManager.config;

    this.sandboxManager = new SandboxManager(configManager.getSandboxConfig());
    this.aiAnalyzer = new AIAnalyzer(configManager.getAIAnalyzerConfig());
    this.osvService = new OSVService();
    this.dependencyAnalyzer = new DependencyAnalyzer(this.osvService);
    this.mcpJsonAnalyzer = new MCPJsonAnalyzer(this.aiAnalyzer['aiRouter'], this.sandboxManager);

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

    // Dynamic Analysis (when MCP server is available)
    let behavioralAnalysis: SecurityAnalysis | undefined;
    if (!options.skipBehavioralAnalysis && scanMode !== 'json') {
      console.log('Performing behavioral analysis in sandbox...');
      try {
        behavioralAnalysis = await this.performBehavioralAnalysis(mcpServerPath, options);
        console.log(`Behavioral analysis complete: ${behavioralAnalysis.risks.length} security risks identified`);
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

    // Black Box MCP JSON Analysis
    let mcpJsonAnalysis: MCPJsonAnalysis | undefined;
    if (scanMode === 'json' && options.mcpJsonConfig) {
      console.log('Performing black box MCP JSON analysis...');
      try {
        mcpJsonAnalysis = await this.performMCPJsonAnalysis(options.mcpJsonConfig);
        console.log(`MCP JSON analysis complete: ${mcpJsonAnalysis.risks.length} security risks identified`);
      } catch (error) {
        throw new Error(`MCP JSON analysis failed: ${error}`);
      }
    }

    // Combine results and generate comprehensive assessment
    const result = this.generateComprehensiveResult(
      scanMode,
      startTime,
      dependencyAnalysis,
      sourceCodeAnalysis,
      behavioralAnalysis,
      mcpJsonAnalysis
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
    // Check if it's a local path or remote URL
    if (sourceCodeUrl.startsWith('http://') || sourceCodeUrl.startsWith('https://')) {
      // Remote repository - use Anthropic AI with tool calling to analyze the preserved Docker volume
      return await this.performRemoteSourceCodeAnalysis();
    } else {
      // Local path analysis - placeholder for now
      throw new Error('Local source code analysis not yet implemented');
    }
  }

  private async performRemoteSourceCodeAnalysis(): Promise<ComprehensiveScanResult['sourceCodeAnalysis']> {
    const sandboxProvider = await this.sandboxManager.getProvider();
    if (!sandboxProvider) {
      throw new Error('No sandbox provider available for source code analysis');
    }

    // Get the volume that was used for dependency analysis
    const volumeName = (sandboxProvider as any)._currentVolume;
    if (!volumeName) {
      throw new Error('No Docker volume available for source code analysis - dependency analysis must run first');
    }

    try {
      // Use Anthropic AI to intelligently analyze the repository
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
              const { exec } = require('child_process');
              const { promisify } = require('util');
              const execAsync = promisify(exec);

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
              const { exec } = require('child_process');
              const { promisify } = require('util');
              const execAsync = promisify(exec);

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
              const { exec } = require('child_process');
              const { promisify } = require('util');
              const execAsync = promisify(exec);

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

      // Use the structured source code analysis instead of dummy vulnerability creation
      // The AI analysis with tool calling has already been performed above
      // Now we need to extract structured vulnerability information

      // Get all source files from the Docker volume for analysis
      // volumeName is already available from earlier in this method

      // Read the main source files to get actual code content
      const execAsync = promisify(exec);

      let sourceCodeContent = '';
      try {
        // Get JavaScript/TypeScript files for structured analysis
        const { stdout: jsFiles } = await execAsync(`docker run --rm -v ${volumeName}:/src alpine:latest find /src -name "*.js" -o -name "*.ts" -o -name "*.mjs" | head -10`);

        if (jsFiles.trim()) {
          // Read the first few source files for structured analysis
          const files = jsFiles.trim().split('\n').slice(0, 3); // Limit to first 3 files
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

      // Use the AI Analyzer's structured analysis method
      const structuredAnalysis = await this.aiAnalyzer.analyzeSourceCodeSecurity(sourceCodeContent || response.content);

      // Return the structured results
      return {
        vulnerabilities: structuredAnalysis.vulnerabilities,
        suggestions: structuredAnalysis.suggestions
      };

    } finally {
      // Clean up the Docker volume now that we're done with all analysis
      if (typeof (sandboxProvider as any).cleanupCurrentVolume === 'function') {
        await (sandboxProvider as any).cleanupCurrentVolume();
      }
    }
  }

  private async performBehavioralAnalysis(
    mcpServerPath: string,
    options: ScanOptions
  ): Promise<SecurityAnalysis> {
    // Validate MCP server path for static-only mode
    if (mcpServerPath === 'static-analysis-only') {
      throw new Error('Behavioral analysis skipped: Static-only analysis mode (no MCP server to execute)');
    }

    // Check if MCP server path exists (for local paths)
    if (!mcpServerPath.startsWith('http://') && !mcpServerPath.startsWith('https://')) {
      // fs is already imported at the top
      if (!fs.existsSync(mcpServerPath)) {
        throw new Error(`Behavioral analysis failed: MCP server not found at path '${mcpServerPath}'`);
      }
    }

    const timeout = options.timeout || configManager.config.SCANNER_TIMEOUT;

    // Execute MCP server in sandbox
    const sandboxResult = await this.sandboxManager.executeMCPServer(
      mcpServerPath,
      undefined, // MCP config - could be provided in options
      { timeout: timeout / 1000 } // Convert to seconds
    );

    // Only proceed with AI analysis if execution was actually successful
    if (sandboxResult.exitCode !== 0) {
      throw new Error(`Behavioral analysis failed: MCP server execution failed with exit code ${sandboxResult.exitCode}. Stderr: ${sandboxResult.stderr}`);
    }

    // Analyze results with AI
    const analysis = await this.aiAnalyzer.analyzeMCPSecurity(
      sandboxResult,
      undefined, // Source code - not available in pure dynamic mode
      undefined  // MCP manifest - could be extracted from sandbox result
    );

    return analysis;
  }

  private async performMCPJsonAnalysis(mcpJsonConfig: any): Promise<MCPJsonAnalysis> {
    console.log('Starting AI-powered analysis of MCP JSON configuration...');

    try {
      const analysis = await this.mcpJsonAnalyzer.analyzeMCPConfiguration(mcpJsonConfig);

      console.log(`MCP JSON analysis findings:`);
      console.log(`- Security risks: ${analysis.risks.length}`);
      console.log(`- Suspicious packages: ${analysis.packageAnalysis.suspiciousPackages.length}`);
      console.log(`- Bridge packages detected: ${analysis.packageAnalysis.bridgePackages.length}`);
      console.log(`- Remote endpoints: ${analysis.networkAnalysis.remoteEndpoints.length}`);

      return analysis;
    } catch (error) {
      console.error('MCP JSON analysis failed:', error);
      throw new Error(`MCP JSON analysis failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private generateComprehensiveResult(
    scanMode: ScanMode,
    startTime: number,
    dependencyAnalysis?: DependencyAnalysisResult,
    sourceCodeAnalysis?: ComprehensiveScanResult['sourceCodeAnalysis'],
    behavioralAnalysis?: SecurityAnalysis,
    mcpJsonAnalysis?: MCPJsonAnalysis
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
      mcpJsonAnalysis
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
      overallRisk,
      summary,
      recommendations
    };
  }

  private calculateOverallRisk(
    dependencyAnalysis?: DependencyAnalysisResult,
    sourceCodeAnalysis?: ComprehensiveScanResult['sourceCodeAnalysis'],
    behavioralAnalysis?: SecurityAnalysis,
    mcpJsonAnalysis?: MCPJsonAnalysis
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