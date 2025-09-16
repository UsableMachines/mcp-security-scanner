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
  node mcp_scan_cli.js <local_mcp_server_path> [options]     # For local servers
  node mcp_scan_cli.js --repo <github_url> [options]        # For remote static analysis

Arguments:
  local_mcp_server_path  Path to local MCP server executable (for dynamic analysis)

Options:
  --repo URL         GitHub/GitLab repository URL (for static analysis only)
  --mode MODE        Analysis mode: static, dynamic, hybrid (default: auto)
  --timeout MS       Timeout in milliseconds (default: 300000)
  --help             Show this help

Examples:
  # Static analysis of GitHub repo
  node mcp_scan_cli.js --repo https://github.com/user/mcp-server

  # Dynamic analysis of local server (future feature)
  node mcp_scan_cli.js /path/to/mcp-server.js

  # Static analysis with custom timeout
  node mcp_scan_cli.js --repo https://github.com/user/mcp-server --timeout 60000
`);
    process.exit(0);
  }

  let mcpServerPath = null;
  let repoUrl = null;
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
      case '--mode':
        options.mode = args[++i];
        break;
      case '--timeout':
        options.timeout = parseInt(args[++i]);
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
  if (!mcpServerPath && !repoUrl) {
    console.error('Error: Must provide either a local MCP server path or --repo URL');
    console.log('Run with --help for usage examples');
    process.exit(1);
  }

  if (mcpServerPath && repoUrl) {
    console.error('Error: Cannot specify both local server path and --repo URL');
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
    }

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