#!/usr/bin/env node

/**
 * MCP Security Scanner CLI
 * Command line interface for testing real MCP servers
 */

const { MCPSecurityScanner } = require('./dist/index.js');

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(`
🔒 MCP Security Scanner v0.1.0
Usage:
  # Source code analysis (when code is available)
  node mcp_scan_cli.js <local_mcp_server_path> [options]     # For local servers
  node mcp_scan_cli.js --repo <github_url> [options]        # For remote repositories

  # Black box analysis (when only MCP JSON config is available)
  node mcp_scan_cli.js --json <mcp_config_json> [options]   # For MCP JSON configurations

Arguments:
  local_mcp_server_path  Path to local MCP server executable (for dynamic analysis)

Options:
  --repo URL         GitHub/GitLab repository URL (for static analysis only)
  --json JSON        MCP configuration JSON string (for black box analysis)
  --mode MODE        Analysis mode: static, dynamic, hybrid (default: auto)
  --timeout MS       Timeout in milliseconds (default: 300000)
  --api-key KEY      API key for authenticated MCP servers (will auto-detect service)
  --allow-mcp-remote Allow scanning of mcp-remote proxy servers (disabled by default for security)
  --help             Show this help

Examples:
  # Source code static analysis
  node mcp_scan_cli.js --repo https://github.com/user/mcp-server

  # Black box MCP JSON analysis
  node mcp_scan_cli.js --json '{"mcpServers":{"linear":{"command":"npx","args":["-y","mcp-remote","https://mcp.linear.app/sse"]}}}'

  # Docker MCP server with API key
  node mcp_scan_cli.js --json '{"mcpServers":{"brave":{"command":"docker","args":["run","-i","--rm","-e","BRAVE_API_KEY","mcp/brave-search"],"env":{"BRAVE_API_KEY":"YOUR_API_KEY_HERE"}}}}' --api-key BSA-xyz123...

  # Dynamic analysis of local server
  node mcp_scan_cli.js /path/to/mcp-server.js
`);
    process.exit(0);
  }

  let mcpServerPath = null;
  let repoUrl = null;
  let mcpJsonConfig = null;
  const options = {};

  // Parse command line options
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--repo':
        repoUrl = args[++i];
        if (!repoUrl) {
          console.error('--repo requires a URL');
          process.exit(1);
        }
        break;
      case '--json':
        // Check if next arg exists and doesn't start with --
        if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
          mcpJsonConfig = args[++i];
        } else {
          // No JSON provided, will prompt for it later
          mcpJsonConfig = 'PROMPT_FOR_JSON';
        }
        break;
      case '--mode':
        options.mode = args[++i];
        break;
      case '--timeout':
        options.timeout = parseInt(args[++i]);
        break;
      case '--api-key':
        options.apiKey = args[++i];
        if (!options.apiKey) {
          console.error('--api-key requires a value');
          process.exit(1);
        }
        break;
      case '--allow-mcp-remote':
        options.allowMcpRemote = true;
        break;
      case '--help':
      case '-h':
        console.log('Help already shown above');
        process.exit(0);
        break;
      default:
        if (!args[i].startsWith('--') && !mcpServerPath) {
          mcpServerPath = args[i];
        } else if (!args[i].startsWith('--')) {
          console.error(`Unknown argument: ${args[i]}`);
          process.exit(1);
        } else {
          console.error(`Unknown option: ${args[i]}`);
          process.exit(1);
        }
    }
  }

  // Validate arguments
  const inputCount = [mcpServerPath, repoUrl, mcpJsonConfig].filter(Boolean).length;

  if (inputCount === 0) {
    console.error('Error: Must provide one of: local MCP server path, --repo URL, or --json config');
    console.log('Run with --help for usage examples');
    process.exit(1);
  }

  if (inputCount > 1) {
    console.error('Error: Cannot specify multiple input sources simultaneously');
    process.exit(1);
  }

  console.log(`🔒 MCP Security Scanner v0.1.0`);

  if (repoUrl) {
    console.log(`Repository: ${repoUrl}`);
    console.log(`Analysis: Static (dependency + source code)`);
    options.sourceCodeUrl = repoUrl;
    options.mode = 'static';
    // Use dummy path for static-only mode
    mcpServerPath = 'static-analysis-only';
  } else if (mcpJsonConfig) {
    console.log(`Analysis: Black Box (MCP JSON configuration)`);
    options.mode = 'json';

    // Handle JSON input
    let jsonInput = mcpJsonConfig;
    if (mcpJsonConfig === 'PROMPT_FOR_JSON') {
      console.log('\nPlease paste your MCP JSON configuration below.');
      console.log('Press Ctrl+D (Linux/Mac) or Ctrl+Z then Enter (Windows) when finished:\n');

      // Read from stdin
      const readline = require('readline');
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
      });

      let jsonLines = [];

      await new Promise((resolve) => {
        rl.on('line', (line) => {
          jsonLines.push(line);
        });

        rl.on('close', () => {
          resolve();
        });
      });

      jsonInput = jsonLines.join('\n');
      console.log('\nJSON received, parsing...\n');
    }

    // Parse JSON configuration
    if (jsonInput !== 'PROMPT_FOR_JSON') {
      console.log(`JSON Config: ${jsonInput.substring(0, 100)}${jsonInput.length > 100 ? '...' : ''}`);
    }
    try {
      const jsonConfig = JSON.parse(jsonInput);
      options.mcpJsonConfig = jsonConfig;
    } catch (error) {
      console.error(`Error: Invalid JSON format: ${error.message}`);
      process.exit(1);
    }
    mcpServerPath = 'json-analysis-mode';
  } else {
    console.log(`Target: ${mcpServerPath}`);
    console.log(`Mode: ${options.mode || 'auto'}`);
  }

  console.log('=====================================\n');

  let scanner;
  try {
    console.log('Initializing scanner...');
    scanner = new MCPSecurityScanner();
    await scanner.initialize();

    console.log('Starting security analysis...\n');
    const startTime = Date.now();

    const result = await scanner.scan(mcpServerPath, options);

    console.log('\n=====================================');
    console.log('🔍 SECURITY ANALYSIS COMPLETE');
    console.log('=====================================');

    console.log(`\n📊 SUMMARY:`);
    console.log(`   Analysis Mode: ${result.scanMode.toUpperCase()}`);
    console.log(`   Overall Risk:  ${result.overallRisk.toUpperCase()}`);
    console.log(`   Duration:      ${result.duration}ms`);
    console.log(`   Timestamp:     ${result.timestamp.toISOString()}`);

    if (result.dependencyAnalysis) {
      const deps = result.dependencyAnalysis.vulnerabilityReport;
      console.log(`\n📦 DEPENDENCY ANALYSIS:`);
      console.log(`   Packages Scanned:      ${deps.totalPackagesScanned}`);
      console.log(`   Vulnerable Packages:   ${deps.vulnerablePackages}`);
      console.log(`   Total Vulnerabilities: ${deps.totalVulnerabilities}`);
      console.log(`   Critical:              ${deps.severityBreakdown.critical}`);
      console.log(`   High:                  ${deps.severityBreakdown.high}`);
      console.log(`   Medium:                ${deps.severityBreakdown.medium}`);
      console.log(`   Low:                   ${deps.severityBreakdown.low}`);
    }

    if (result.sourceCodeAnalysis) {
      const code = result.sourceCodeAnalysis;
      console.log(`\n💻 SOURCE CODE ANALYSIS:`);
      console.log(`   Code Vulnerabilities: ${code.vulnerabilities.length}`);

      if (code.vulnerabilities.length > 0) {
        console.log(`\n🔍 CODE VULNERABILITIES FOUND:`);
        code.vulnerabilities.forEach((vuln, i) => {
          console.log(`   ${i + 1}. ${vuln.type.toUpperCase()} (${vuln.severity.toUpperCase()})`);
          console.log(`      ${vuln.description}`);
          if (vuln.line && vuln.line > 0) {
            console.log(`      Line: ${vuln.line}`);
          }
          if (vuln.code && vuln.code.trim()) {
            console.log(`      Code: ${vuln.code.trim()}`);
          }
        });
      }

      // Skip source code suggestions - they duplicate the recommendations section
    }

    if (result.behavioralAnalysis) {
      console.log(`\n🔬 BEHAVIORAL ANALYSIS:`);
      console.log(`   Security Risks:   ${result.behavioralAnalysis.risks.length}`);
      console.log(`   MCP Tools:        ${result.behavioralAnalysis.mcpCapabilities.tools.length}`);
      console.log(`   MCP Resources:    ${result.behavioralAnalysis.mcpCapabilities.resources.length}`);

      if (result.behavioralAnalysis.risks.length > 0) {
        console.log(`\n⚠️  SECURITY RISKS IDENTIFIED:`);
        result.behavioralAnalysis.risks.forEach((risk, i) => {
          console.log(`   ${i + 1}. ${risk.type.toUpperCase()} (${risk.severity.toUpperCase()})`);
          console.log(`      ${risk.description}`);
          console.log(`      Confidence: ${Math.round(risk.confidence * 100)}%`);
        });
      }
    } else {
      console.log(`\n🔬 BEHAVIORAL ANALYSIS:`);
      console.log(`   ⚠️  Skipped (static-only analysis mode)`);
    }

    // Docker/Proxy Behavioral Analysis Results (new)
    if (result.dockerBehavioralAnalysis && result.dockerBehavioralAnalysis.length > 0) {
      const nativeDockerCount = result.dockerBehavioralAnalysis.filter(analysis => !analysis.serverName.includes('-proxy-sandbox')).length;
      const proxyServerCount = result.dockerBehavioralAnalysis.filter(analysis => analysis.serverName.includes('-proxy-sandbox')).length;

      if (nativeDockerCount > 0 && proxyServerCount > 0) {
        console.log(`\n🐳 DOCKER BEHAVIORAL ANALYSIS:`);
        console.log(`   Docker Servers:       ${nativeDockerCount}`);
        console.log(`   Proxy Servers:        ${proxyServerCount}`);
      } else if (nativeDockerCount > 0) {
        console.log(`\n🐳 DOCKER BEHAVIORAL ANALYSIS:`);
        console.log(`   Docker Servers:       ${nativeDockerCount}`);
      } else {
        console.log(`\n🔗 PROXY BEHAVIORAL ANALYSIS:`);
        console.log(`   Proxy Servers:        ${proxyServerCount}`);
      }

      let totalRisks = 0;
      result.dockerBehavioralAnalysis.forEach(analysis => {
        totalRisks += analysis.securityAnalysis.risks.length;
      });
      console.log(`   Total Risks:          ${totalRisks}`);

      if (totalRisks > 0) {
        console.log(`\n🔍 DOCKER BEHAVIORAL RISKS FOUND:`);
        result.dockerBehavioralAnalysis.forEach((analysis, i) => {
          console.log(`\n   Server: ${analysis.serverName} (${analysis.dockerImage})`);
          console.log(`   Execution: ${analysis.executionSuccess ? '✅ Success' : '❌ Failed'}`);
          console.log(`   Network Connections: ${analysis.executionMetrics.networkConnections}`);
          console.log(`   File Operations: ${analysis.executionMetrics.fileOperations}`);

          if (analysis.securityAnalysis.risks.length > 0) {
            console.log(`   Security Risks:`);
            analysis.securityAnalysis.risks.forEach((risk, j) => {
              console.log(`      ${j + 1}. ${risk.type.replace(/_/g, ' ').toUpperCase()} (${risk.severity.toUpperCase()})`);
              console.log(`         ${risk.description}`);
              console.log(`         Confidence: ${Math.round(risk.confidence * 100)}%`);
              if (risk.evidence && risk.evidence.length > 0) {
                console.log(`         Evidence: ${risk.evidence.slice(0, 2).join(', ')}${risk.evidence.length > 2 ? '...' : ''}`);
              }
            });
          }
        });
      }
    }

    // MCP Prompt Security Analysis (new)
    if (result.mcpPromptSecurityAnalysis) {
      console.log(`\n🛡️  MCP PROMPT SECURITY ANALYSIS:`);
      console.log(`   Server Name:       ${result.mcpPromptSecurityAnalysis.serverName}`);
      console.log(`   Tools Analyzed:    ${result.mcpPromptSecurityAnalysis.totalTools}`);
      console.log(`   Prompt Risks:      ${result.mcpPromptSecurityAnalysis.risks.length}`);

      if (result.mcpPromptSecurityAnalysis.risks.length > 0) {
        console.log(`\n⚠️  MCP PROMPT SECURITY RISKS IDENTIFIED:`);
        result.mcpPromptSecurityAnalysis.risks.forEach((risk, i) => {
          console.log(`   ${i + 1}. ${risk.type.replace(/_/g, ' ').toUpperCase()} (${risk.severity.toUpperCase()})`);
          console.log(`      ${risk.description}`);
          if (risk.toolName) {
            console.log(`      Tool: ${risk.toolName}`);
          }
          if (risk.evidence && risk.evidence.length > 0) {
            console.log(`      Evidence: ${risk.evidence.join(', ')}`);
          }
          console.log(`      Confidence: ${Math.round(risk.confidence * 100)}%`);
        });
      }

      console.log(`\n📝 MCP PROMPT ANALYSIS SUMMARY:`);
      console.log(`   ${result.mcpPromptSecurityAnalysis.summary}`);
    } else {
      console.log(`\n🛡️  MCP PROMPT SECURITY ANALYSIS:`);
      console.log(`   ⚠️  Skipped (no MCP server configuration found)`);
    }

    if (result.mcpJsonAnalysis) {
      console.log(`\n🔍 MCP JSON CONFIGURATION ANALYSIS:`);
      console.log(`   Security Risks:        ${result.mcpJsonAnalysis.risks.length}`);
      console.log(`   Suspicious Packages:   ${result.mcpJsonAnalysis.packageAnalysis.suspiciousPackages.length}`);
      console.log(`   Bridge Packages:       ${result.mcpJsonAnalysis.packageAnalysis.bridgePackages.length}`);
      console.log(`   Remote Endpoints:      ${result.mcpJsonAnalysis.networkAnalysis.remoteEndpoints.length}`);

      if (result.mcpJsonAnalysis.risks.length > 0) {
        console.log(`\n⚠️  MCP CONFIGURATION RISKS IDENTIFIED:`);
        result.mcpJsonAnalysis.risks.forEach((risk, i) => {
          console.log(`   ${i + 1}. ${risk.type.replace(/_/g, ' ').toUpperCase()} (${risk.severity.toUpperCase()})`);
          console.log(`      ${risk.description}`);
          if (risk.evidence && risk.evidence.length > 0) {
            console.log(`      Evidence: ${risk.evidence.join(', ')}`);
          }
          if (risk.aiConfidence) {
            console.log(`      AI Confidence: ${Math.round(risk.aiConfidence * 100)}%`);
          }
        });
      }

      // Repository discovery for local execution patterns
      if (result.mcpJsonAnalysis.repositoryDiscovery && result.mcpJsonAnalysis.repositoryDiscovery.suggestions.length > 0) {
        console.log(`\n🔍 REPOSITORY DISCOVERY:`);
        result.mcpJsonAnalysis.repositoryDiscovery.suggestions.forEach(suggestion => {
          console.log(`   ${suggestion}`);
        });
      }

      if (result.mcpJsonAnalysis.packageAnalysis.suspiciousPackages.length > 0) {
        console.log(`\n📦 SUSPICIOUS PACKAGES DETECTED:`);
        result.mcpJsonAnalysis.packageAnalysis.suspiciousPackages.forEach((pkg, i) => {
          console.log(`   ${i + 1}. ${pkg}`);
        });
      }

      if (result.mcpJsonAnalysis.packageAnalysis.bridgePackages.length > 0) {
        console.log(`\n🌉 AUTHENTICATION BRIDGE PACKAGES:`);
        result.mcpJsonAnalysis.packageAnalysis.bridgePackages.forEach((bridge, i) => {
          console.log(`   ${i + 1}. ${bridge} (HIDES AUTH FLOW)`);
        });
      }

      if (result.mcpJsonAnalysis.networkAnalysis.insecureProtocols.length > 0) {
        console.log(`\n🔓 INSECURE NETWORK PROTOCOLS:`);
        result.mcpJsonAnalysis.networkAnalysis.insecureProtocols.forEach((protocol, i) => {
          console.log(`   ${i + 1}. ${protocol}`);
        });
      }
    }

    console.log(`\n📝 SUMMARY:`);
    console.log(result.summary);

    if (result.recommendations.length > 0) {
      console.log(`\n🔧 RECOMMENDATIONS:`);
      result.recommendations.forEach((rec, i) => {
        console.log(`   ${i + 1}. ${rec}`);
      });
    }

    // Exit with appropriate code
    if (result.overallRisk === 'critical') {
      console.log(`\n❌ CRITICAL SECURITY ISSUES FOUND - DO NOT DEPLOY`);
      process.exit(2);
    } else if (result.overallRisk === 'high') {
      console.log(`\n⚠️  HIGH SECURITY RISKS - REVIEW REQUIRED`);
      process.exit(1);
    } else {
      console.log(`\n✅ Security analysis complete`);
      process.exit(0);
    }

  } catch (error) {
    if (error.message.includes('LOCAL_EXECUTION_REDIRECT')) {
      // Clean exit for local execution redirect - message already shown
      process.exit(1);
    }
    console.error(`\n❌ Scan failed: ${error.message}`);

    if (error.message.includes('Docker')) {
      console.log('\nTroubleshooting:');
      console.log('- Ensure Docker is installed and running');
      console.log('- Try: docker --version');
    } else if (error.message.includes('KINDO_API_KEY')) {
      console.log('\nTroubleshooting:');
      console.log('- Check that KINDO_API_KEY is set in .env file');
    }

    process.exit(3);
  } finally {
    if (scanner) {
      await scanner.cleanup();
    }
  }
}

// Handle Ctrl+C gracefully
process.on('SIGINT', async () => {
  console.log('\n\nReceived SIGINT. Cleaning up...');
  process.exit(130);
});

main().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});