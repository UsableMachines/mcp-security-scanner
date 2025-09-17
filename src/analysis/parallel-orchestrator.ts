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
      confidence: number;
    }>;
    summary: string;
  };
  behavioralAnalysis?: SecurityAnalysis;
  mcpJsonAnalysis?: MCPJsonAnalysis;
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
   * Execute MCP JSON analysis for black-box configurations
   */
  async executeMCPJsonAnalysis(mcpJsonConfig: any): Promise<MCPJsonAnalysis> {
    console.log('🔍 Running MCP JSON configuration analysis...');
    const startTime = Date.now();

    try {
      const analysis = await this.mcpJsonAnalyzer.analyzeMCPConfiguration(mcpJsonConfig);

      const duration = Date.now() - startTime;
      console.log(`✅ MCP JSON analysis completed in ${duration}ms`);

      return analysis;

    } catch (error) {
      if (error instanceof Error && error.message === 'LOCAL_EXECUTION_REDIRECT') {
        throw error;
      }
      console.error('❌ MCP JSON analysis failed:', error);
      throw new Error(`MCP JSON analysis failed: ${error instanceof Error ? error.message : String(error)}`);
    }
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
      confidence: number;
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