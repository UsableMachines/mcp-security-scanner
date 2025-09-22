/**
 * AI-powered security analysis using abstracted AI router
 */

import { z } from 'zod';
import { AIRouter, AIMessage } from '../services/ai-router';
import type { SandboxResult } from '../sandbox/sandbox-provider';
import { MCPPromptSecurityAnalyzer, type PromptSecurityAnalysisResult, type MCPServer } from './mcp-prompt-security-analyzer';
import { configManager } from '../config';

// Security analysis schemas
const SecurityRiskSchema = z.object({
  type: z.enum([
    'command_injection',
    'credential_exposure',
    'privilege_escalation',
    'data_exfiltration',
    'network_abuse',
    'prompt_injection',
    'authentication_bypass',
    'tool_poisoning',
    'tool_shadowing',
    'cross_origin_violation',
    'sensitive_file_access'
  ]),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  description: z.string(),
  evidence: z.array(z.string()),
  mitigation: z.string(),
  confidence: z.number().min(0).max(1)
});

const MCPAnalysisSchema = z.object({
  overallRisk: z.enum(['critical', 'high', 'medium', 'low']),
  risks: z.array(SecurityRiskSchema),
  mcpCapabilities: z.object({
    tools: z.array(z.string()),
    resources: z.array(z.string()),
    prompts: z.array(z.string())
  }),
  recommendations: z.array(z.string()),
  summary: z.string()
});

export type SecurityAnalysis = z.infer<typeof MCPAnalysisSchema>;

export interface AIAnalyzerConfig {
  // Router configuration
  aiProvider?: 'external-kindo' | 'internal-kindo' | 'anthropic';

  // Provider-specific configs
  externalKindo?: {
    apiKey: string;
    baseUrl?: string;
    model?: string;
  };
  internalKindo?: {
    platformService?: any;
    defaultModel?: string;
  };
  anthropic?: {
    apiKey?: string;
  };
}

export class AIAnalyzer {
  private aiRouter: AIRouter;
  private promptSecurityAnalyzer: MCPPromptSecurityAnalyzer;
  private isInitialized = false;

  constructor(private config: AIAnalyzerConfig) {
    this.aiRouter = new AIRouter({
      preferredProvider: config.aiProvider || 'anthropic'
    });
    this.promptSecurityAnalyzer = new MCPPromptSecurityAnalyzer();
  }

  async initialize(): Promise<void> {
    if (this.isInitialized) return;

    const providerConfigs: any = {};
    
    if (this.config.externalKindo) {
      providerConfigs['external-kindo'] = this.config.externalKindo;
    }
    
    if (this.config.internalKindo) {
      providerConfigs['internal-kindo'] = this.config.internalKindo;
    }

    // Add Anthropic provider config (use environment variable if not provided)
    providerConfigs['anthropic'] = this.config.anthropic || {};

    await this.aiRouter.initialize(providerConfigs);
    this.isInitialized = true;
    
    if (configManager.isDebugMode()) {
      console.log(`AI Analyzer initialized with provider: ${this.aiRouter.getCurrentProvider()}`);
    }
  }

  async analyzeMCPSecurity(
    sandboxResult: SandboxResult,
    sourceCode?: string,
    mcpManifest?: any
  ): Promise<SecurityAnalysis> {
    await this.initialize();
    
    const analysisData = this.formatAnalysisData(sandboxResult, sourceCode, mcpManifest);
    
    try {
      return await this.aiRouter.analyzeSecurityWithStructuredOutput(
        analysisData,
        MCPAnalysisSchema.shape
      );
    } catch (error) {
      console.error('AI analysis failed:', error);
      return this.generateFallbackAnalysis(sandboxResult);
    }
  }

  async generateSecurityReport(analysis: SecurityAnalysis): Promise<string> {
    await this.initialize();
    
    try {
      return await this.aiRouter.generateReport(analysis, 'MCP Security Assessment');
    } catch (error) {
      console.error('Report generation failed:', error);
      return this.generateFallbackReport(analysis);
    }
  }

  /**
   * Analyze MCP server for prompt-level security vulnerabilities
   */
  async analyzeMCPPromptSecurity(mcpServer: MCPServer): Promise<PromptSecurityAnalysisResult> {
    console.log(`🔍 Running MCP prompt security analysis for server: ${mcpServer.name}`);

    // Run pattern-based analysis first
    const patternAnalysis = await this.promptSecurityAnalyzer.analyzeMCPServer(mcpServer);

    // If AI analysis is available, enhance with AI insights
    if (this.isInitialized) {
      try {
        const aiPrompt = this.promptSecurityAnalyzer.generateAIAnalysisPrompt(mcpServer);
        const aiResponse = await this.aiRouter.createCompletion([
          { role: 'user', content: aiPrompt }
        ], {
          temperature: 0.2,
          maxTokens: 2000
        });

        // Parse AI response and merge with pattern analysis
        const aiInsights = this.parseAIPromptSecurityResponse(aiResponse.content);

        // Enhance confidence scores and add AI-detected risks
        for (const risk of patternAnalysis.risks) {
          if (aiInsights.confirmsRisk(risk)) {
            risk.aiConfidence = aiInsights.getConfidence(risk);
          }
        }

        // Add any additional risks identified by AI
        patternAnalysis.risks.push(...aiInsights.additionalRisks);

      } catch (error) {
        console.warn('AI-enhanced prompt analysis failed, using pattern-based analysis only:', error);
      }
    }

    return patternAnalysis;
  }

  async analyzeSourceCodeSecurity(sourceCode: string): Promise<{
    vulnerabilities: Array<{
      type: string;
      severity: string;
      line: number;
      description: string;
      code: string;
    }>;
    suggestions: string[];
  }> {
    await this.initialize();

    const analysisPrompt = `Analyze this MCP server source code for security vulnerabilities using systematic methodology:

\`\`\`javascript
${sourceCode.substring(0, 12000)}
${sourceCode.length > 12000 ? '\n... (truncated for analysis)' : ''}
\`\`\`

## SYSTEMATIC ANALYSIS FRAMEWORK:

### 1. MCP TOOL IMPLEMENTATIONS
- Parameter injection (command, path, code injection)
- Input validation gaps
- Unsafe command execution
- File system access patterns

### 2. MCP PROMPT SECURITY (NEW - MCP Shield patterns)
- Tool descriptions containing hidden instructions ("don't tell", "hide this", <secret>)
- Tool shadowing attempts ("override behavior", "replace tool")
- Data exfiltration via suspicious parameters ("notes", "feedback", "context")
- Cross-origin violations (references to other MCP servers)
- Sensitive file access patterns in tool descriptions

### 3. AUTHENTICATION & AUTHORIZATION
- Session validation weaknesses
- API key handling security
- Bypass vulnerabilities
- Missing authorization checks

### 4. KINDO DEPLOYMENT RISKS
- Hardcoded secrets exposure
- External API security
- Resource consumption vulnerabilities
- Multi-tenant isolation issues

### 5. PRODUCTION SECURITY
- Error information disclosure
- Logging of sensitive data
- Input validation bypasses
- CORS and security headers

## SEVERITY (Kindo Production Impact):
- CRITICAL: RCE, credential theft, data breach
- HIGH: Auth bypass, privilege escalation
- MEDIUM: Info disclosure, DoS potential
- LOW: Configuration improvements

Return structured JSON (include MCP-specific vulnerability types):
{
  "vulnerabilities": [
    {
      "type": "command_injection|credential_exposure|privilege_escalation|tool_poisoning|tool_shadowing|cross_origin_violation|sensitive_file_access|data_exfiltration|network_abuse|prompt_injection|authentication_bypass",
      "severity": "critical|high|medium|low",
      "line": line_number,
      "description": "detailed security impact and attack vector",
      "code": "actual vulnerable code snippet"
    }
  ],
  "suggestions": ["specific actionable remediation steps focused on MCP security"]
}`;

    try {
      const schema = {
        vulnerabilities: 'array of vulnerability objects',
        suggestions: 'array of recommendation strings'
      };
      
      return await this.aiRouter.analyzeSecurityWithStructuredOutput(analysisPrompt, schema);
    } catch (error) {
      console.error('Source code analysis failed:', error);
      return {
        vulnerabilities: [],
        suggestions: ['Manual code review recommended due to analysis failure']
      };
    }
  }

  async cleanup(): Promise<void> {
    if (this.isInitialized) {
      await this.aiRouter.cleanup();
      this.isInitialized = false;
    }
  }

  // Utility method to check current provider
  getCurrentProvider(): string | null {
    return this.aiRouter.getCurrentProvider();
  }

  // Method to switch providers at runtime (useful for testing)
  async switchProvider(provider: string): Promise<void> {
    await this.initialize();
    await this.aiRouter.switchProvider(provider);
  }

  private formatAnalysisData(
    sandboxResult: SandboxResult,
    sourceCode?: string,
    mcpManifest?: any
  ): string {
    return `
SANDBOX EXECUTION ANALYSIS:
- Exit Code: ${sandboxResult.exitCode}
- Execution Duration: ${sandboxResult.duration}ms
- Network Activity: ${JSON.stringify(sandboxResult.networkActivity, null, 2)}
- File System Activity: ${JSON.stringify(sandboxResult.fileSystemActivity, null, 2)}  
- Process Activity: ${JSON.stringify(sandboxResult.processActivity, null, 2)}

${sourceCode ? `SOURCE CODE ANALYSIS:
\`\`\`javascript
${sourceCode.substring(0, 15000)}
${sourceCode.length > 15000 ? '\n... (truncated)' : ''}
\`\`\`` : 'SOURCE CODE: Not available - black-box analysis only'}

${mcpManifest ? `MCP MANIFEST:
${JSON.stringify(mcpManifest, null, 2)}` : 'MCP MANIFEST: Not available'}

ANALYSIS REQUIREMENTS:
- Identify MCP-specific security vulnerabilities based on 2025 research
- Assess behavioral patterns from sandbox execution
- Rate severity based on potential impact in production environments
- Provide evidence-based findings with actionable mitigation strategies
- Consider both static code issues (if available) and dynamic runtime behavior

KNOWN MCP SECURITY ISSUES TO FOCUS ON:
- Command injection via tool parameter manipulation
- Authentication bypass (widespread issue in MCP servers)
- Credential exposure in configuration or environment variables
- Tool poisoning through malicious tool descriptions
- Privilege escalation via confused deputy attacks
- Data exfiltration through resource access mechanisms
- Prompt injection vulnerabilities in tool descriptions
- Insecure network communications and external API calls
`;
  }

  private generateFallbackAnalysis(sandboxResult: SandboxResult): SecurityAnalysis {
    const risks = [];
    
    // Analyze network behavior
    if (sandboxResult.networkActivity.length > 0) {
      const externalConnections = sandboxResult.networkActivity.filter(
        na => na.host !== 'localhost' && 
              !na.host.startsWith('127.') &&
              !na.host.startsWith('::1')
      );
      
      if (externalConnections.length > 0) {
        risks.push({
          type: 'network_abuse' as const,
          severity: externalConnections.some(na => na.port === 80 || na.port === 443) ? 'medium' as const : 'high' as const,
          description: 'MCP server established unexpected external network connections',
          evidence: externalConnections.map(na => `${na.direction} ${na.host}:${na.port} (${na.protocol})`),
          mitigation: 'Implement network egress controls, audit external dependencies, use allowlist for required external services',
          confidence: 0.85
        });
      }
    }

    // Analyze command execution
    const commandExecution = sandboxResult.processActivity.filter(proc => 
      ['sh', 'bash', 'cmd', 'powershell', 'curl', 'wget', 'python', 'node', 'npm', 'pip'].includes(proc.command)
    );
    
    if (commandExecution.length > 0) {
      const severity = commandExecution.some(proc => 
        ['sh', 'bash', 'cmd', 'powershell'].includes(proc.command)
      ) ? 'high' as const : 'medium' as const;
      
      risks.push({
        type: 'command_injection' as const,
        severity,
        description: 'Shell command execution detected in MCP server runtime - potential command injection vulnerability',
        evidence: commandExecution.map(pa => `PID ${pa.pid}: ${pa.command} ${pa.args.join(' ')}`),
        mitigation: 'Audit all command execution paths, implement input sanitization, replace shell commands with safe API calls where possible',
        confidence: 0.9
      });
    }

    // Analyze file system access patterns
    const sensitiveFiles = sandboxResult.fileSystemActivity.filter(fa =>
      fa.path.includes('/etc/') || 
      fa.path.includes('/proc/') ||
      fa.path.includes('/sys/') ||
      fa.path.includes('.env') ||
      fa.path.includes('passwd') ||
      fa.path.includes('shadow') ||
      fa.path.includes('credentials') ||
      fa.path.includes('secrets') ||
      fa.path.includes('.ssh/') ||
      fa.path.includes('.aws/') ||
      fa.path.includes('.config/')
    );

    if (sensitiveFiles.length > 0) {
      risks.push({
        type: 'credential_exposure' as const,
        severity: 'critical' as const,
        description: 'Access to sensitive system files or credential stores detected',
        evidence: sensitiveFiles.map(fa => `${fa.operation.toUpperCase()}: ${fa.path}`),
        mitigation: 'Implement strict file access controls, use principle of least privilege, audit file access patterns, secure credential management',
        confidence: 0.95
      });
    }

    // Check for potential privilege escalation
    const privilegedProcesses = sandboxResult.processActivity.filter(proc =>
      proc.command === 'sudo' || 
      proc.command === 'su' ||
      proc.args.includes('--privileged') ||
      proc.args.includes('--user=root')
    );

    if (privilegedProcesses.length > 0) {
      risks.push({
        type: 'privilege_escalation' as const,
        severity: 'critical' as const,
        description: 'Privilege escalation attempts detected in MCP server execution',
        evidence: privilegedProcesses.map(pa => `${pa.command} ${pa.args.join(' ')}`),
        mitigation: 'Remove privilege escalation mechanisms, run with minimal privileges, implement proper access controls',
        confidence: 0.95
      });
    }

    // Determine overall risk
    const hasCritical = risks.some(r => r.severity === 'critical');
    const hasHigh = risks.some(r => r.severity === 'high');
    const overallRisk = hasCritical ? 'critical' : hasHigh ? 'high' : risks.length > 0 ? 'medium' : 'low';

    return {
      overallRisk,
      risks,
      mcpCapabilities: {
        tools: [], // Would be populated from MCP manifest if available
        resources: [], // Would be populated from MCP manifest if available
        prompts: [] // Would be populated from MCP manifest if available
      },
      recommendations: [
        'Conduct comprehensive source code security review',
        'Implement robust input validation for all MCP tool parameters',
        'Add strong authentication and authorization mechanisms', 
        'Implement network egress controls and monitoring',
        'Use principle of least privilege for file system access',
        'Add runtime security monitoring and anomaly detection',
        'Regular security assessments and penetration testing',
        'Follow OWASP guidelines for secure coding practices',
        'Implement secure credential management (avoid hardcoded secrets)',
        'Add comprehensive logging and audit trails'
      ],
      summary: `Behavioral analysis completed: ${risks.length} security issue(s) identified with ${overallRisk.toUpperCase()} overall risk. ${hasCritical || hasHigh ? 'Immediate security review required.' : 'Regular monitoring recommended.'} Full source code analysis strongly recommended for comprehensive assessment.`
    };
  }

  /**
   * Parse AI response for prompt security analysis
   */
  private parseAIPromptSecurityResponse(aiResponse: string): {
    confirmsRisk: (risk: any) => boolean;
    getConfidence: (risk: any) => number;
    additionalRisks: any[];
  } {
    // Simple implementation - in production this would be more sophisticated
    const lowercaseResponse = aiResponse.toLowerCase();

    return {
      confirmsRisk: (risk) => {
        return lowercaseResponse.includes(risk.type.toLowerCase().replace('_', ' ')) ||
               lowercaseResponse.includes(risk.toolName?.toLowerCase() || '');
      },
      getConfidence: (risk) => {
        // Extract confidence from AI response or default to moderate enhancement
        if (lowercaseResponse.includes('high confidence')) return 0.9;
        if (lowercaseResponse.includes('medium confidence')) return 0.7;
        if (lowercaseResponse.includes('low confidence')) return 0.5;
        return 0.8; // Default enhancement
      },
      additionalRisks: [] // Would parse additional risks from structured AI response
    };
  }

  private generateFallbackReport(analysis: SecurityAnalysis): string {
    const timestamp = new Date().toISOString();
    const provider = this.getCurrentProvider() || 'fallback';
    
    return `# MCP Security Assessment Report

**Generated:** ${timestamp}  
**Provider:** ${provider}  
**Overall Risk:** ${analysis.overallRisk.toUpperCase()}

## Executive Summary

${analysis.summary}

${analysis.risks.length === 0 ? '✅ No immediate security concerns identified in behavioral analysis.' : `⚠️ ${analysis.risks.length} security issue(s) identified requiring attention.`}

## Detailed Findings

${analysis.risks.length === 0 ? '*No security risks identified in current analysis.*' : 
  analysis.risks.map((risk, index) => `### ${index + 1}. ${risk.type.replace(/_/g, ' ').toUpperCase()}

**Severity Level:** ${risk.severity.toUpperCase()}  
**Confidence Score:** ${Math.round(risk.confidence * 100)}%

**Description:** ${risk.description}

**Supporting Evidence:**
${risk.evidence.map(e => `- ${e}`).join('\n')}

**Recommended Mitigation:**
${risk.mitigation}

---`).join('\n')}

## MCP Server Capabilities

- **Tools:** ${analysis.mcpCapabilities.tools.length} registered tool(s)
- **Resources:** ${analysis.mcpCapabilities.resources.length} resource handler(s)  
- **Prompts:** ${analysis.mcpCapabilities.prompts.length} prompt template(s)

## Security Recommendations

${analysis.recommendations.map((rec, i) => `${i + 1}. ${rec}`).join('\n')}

## Next Steps

### Immediate Actions (0-24 hours)
${analysis.overallRisk === 'critical' || analysis.overallRisk === 'high' ? 
  '- **URGENT:** Address all HIGH/CRITICAL severity findings immediately\n- Restrict MCP server access until security issues resolved\n- Review and audit recent MCP server activity' :
  '- Review findings and plan remediation timeline\n- Continue with standard security practices'}

### Short Term (1-7 days)
- Implement recommended security controls
- Conduct comprehensive source code review
- Set up security monitoring and alerting

### Long Term (1-4 weeks)
- Regular security assessments and testing
- Security training for development team
- Establish secure MCP development guidelines

---

**Security Scanner Information**
- Scanner Version: v${process.env.npm_package_version || '1.0.0'}
- Analysis Type: ${analysis.risks.some(r => r.evidence.some(e => e.includes('SOURCE CODE'))) ? 'Static + Dynamic' : 'Dynamic (Behavioral)'}
- Recommendations: Further source code analysis recommended if not already performed

*This report is generated by the Kindo MCP Security Scanner for internal security review purposes.*
`;
  }

  /**
   * Create completion using a specific provider (for source code analysis)
   */
  async createCompletionWithProvider(
    providerName: 'kindo' | 'anthropic',
    messages: any[],
    options: any = {}
  ): Promise<any> {
    await this.initialize();
    return await this.aiRouter.createCompletionWithProvider(providerName, messages, options);
  }
}