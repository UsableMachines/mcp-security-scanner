yarn node mcp_scan_cli.js --allow-mcp-remote --json
[dotenv@17.2.2] injecting env (8) from .env -- tip: ⚙️  override existing env vars with { override: true }
🔒 MCP Security Scanner v0.1.0
Analysis: Black Box (MCP JSON configuration)

Please paste your MCP JSON configuration below.
Press Ctrl+D (Linux/Mac) or Ctrl+Z then Enter (Windows) when finished:

{
  "mcpServers": {
    "notionMCP": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://mcp.notion.com/mcp"]
    }
  }
}

JSON received, parsing...

JSON Config: {
  "mcpServers": {
    "notionMCP": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "h...
=====================================

Initializing scanner...
MCP Security Scanner initialized
Initialized sandbox provider: docker
AI Router initialized with provider: anthropic
AI Analyzer initialized with provider: anthropic
MCP Security Scanner Configuration:
- AI Provider: anthropic
- Sandbox Provider: auto
- Kindo Model: claude-sonnet-4-20250514
- Scanner Timeout: 300000ms
- Max Code Size: 50000 bytes
- Network Analysis: enabled
- Log Level: info
- Kindo API: configured
- Daytona API: not configured
Scanner ready - Sandbox: docker, AI: anthropic
Starting security analysis...

Starting JSON analysis of MCP server: json-analysis-mode
⚠️  Behavioral analysis skipped: JSON-only analysis mode
🌐 Detected remote MCP server: notionMCP
🌐 Detected 1 remote MCP servers
Starting static pattern analysis of MCP configuration...
🔗 Detected proxy/bridge server: mcp-remote (serving notionMCP)
   Package: mcp-remote | URL: YES | Transport: YES
   Command: npx -y mcp-remote https://mcp.notion.com/mcp
🔗 Detected 1 proxy/bridge servers: notionMCP
   These will be analyzed as remote servers in sandbox environment
Analyzing server: notionMCP
Analyzing local execution configuration: notionMCP
🌐 Found 1 remote MCP servers for behavioral analysis
🌐 Starting parallel remote MCP analysis for 1 servers...
🔍 Analyzing remote MCP server: notionMCP (https://mcp.notion.com/mcp)
🔌 Attempting direct connection to notionMCP...
🔍 Performing pre-flight authentication check for: https://mcp.notion.com/mcp
🔗 Detected proxy/bridge server: mcp-remote (serving notionMCP)
   Package: mcp-remote | URL: YES | Transport: YES
   Command: npx -y mcp-remote https://mcp.notion.com/mcp
🔐 Authentication required for notionMCP: Authentication required: 401 Unauthorized
🚀 Starting MCP OAuth 2.1 DCR flow for notionMCP...
🔍 Starting MCP OAuth 2.1 DCR flow for notionMCP...
🔍 Discovering OAuth metadata at: https://mcp.notion.com/.well-known/oauth-authorization-server
📋 OAuth metadata validated: issuer=https://mcp.notion.com
✅ Discovered OAuth metadata for notionMCP
🔐 Generated PKCE code challenge
🔄 Registering dynamic client for notionMCP...
✅ Dynamic client registered successfully
   Client ID: l5KHSFA5UvSxGwmY
   Callback URL: http://localhost:8080/callback
🆔 Dynamically registered client: l5KHSFA5UvSxGwmY
🌐 Starting browser authorization flow...
🖥️  Callback server listening on port 8080
🚀 Opening browser for user consent...
🔗 Opening browser: https://mcp.notion.com/authorize?response_type=code&client_id=l5KHSFA5UvSxGwmY&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&scope=openid+profile+email&state=HvhuRuBZEpUc2lCzQ1Om3K5.tM7wnjAZ&code_challenge=1DntOgjeXPmzduD7nc7cEf0-YMN1IVUISn4HWCTNy2g&code_challenge_method=S256&resource=https%3A%2F%2Fmcp.notion.com%2Fmcp
Could not open browser automatically. Please visit the URL manually:
   https://mcp.notion.com/authorize?response_type=code&client_id=l5KHSFA5UvSxGwmY&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&scope=openid+profile+email&state=HvhuRuBZEpUc2lCzQ1Om3K5.tM7wnjAZ&code_challenge=1DntOgjeXPmzduD7nc7cEf0-YMN1IVUISn4HWCTNy2g&code_challenge_method=S256&resource=https%3A%2F%2Fmcp.notion.com%2Fmcp
🎫 Received authorization code
🔄 Exchanging authorization code for tokens...
✅ Successfully obtained Bearer token
   Token type: bearer
   Expires in: 3600 seconds
🎟️ Successfully obtained Bearer token
🔄 Connecting with OAuth 2.1 Bearer token...
🤝 Establishing MCP connection to notionMCP via HTTP...
🔍 Discovering remote server capabilities...
✅ Remote discovery complete: 14 tools, 1 resources, 0 prompts
✅ Authenticated connection successful to notionMCP
🤖 Running security analysis on remote server data for notionMCP...
🔍 Running MCP prompt security analysis for server: notionMCP
🔍 Analyzing MCP server "notionMCP" for prompt security vulnerabilities...
   Tools to analyze: 14
✅ Remote analysis completed for: notionMCP
🌐 Parallel remote analysis complete: 1/1 successful
✅ Enhanced MCP JSON analysis completed in 24194ms
🌐 Remote MCP analysis: 1 servers analyzed
MCP JSON analysis complete: 3 security risks identified
Scan complete in 24198ms - Overall risk: CRITICAL

=====================================
🔍 SECURITY ANALYSIS COMPLETE
=====================================

📊 SUMMARY:
   Analysis Mode: JSON
   Overall Risk:  CRITICAL
   Duration:      24198ms
   Timestamp:     2025-09-22T17:37:03.589Z

🔍 MCP JSON CONFIGURATION ANALYSIS:
   Security Risks:        3
   Suspicious Packages:   0
   Bridge Packages:       1
   Remote Endpoints:      1

⚠️  MCP CONFIGURATION RISKS IDENTIFIED:
   1. PROXY BRIDGE DETECTED (HIGH)
      Server "notionMCP" uses proxy/bridge package "mcp-remote" which may obfuscate authentication and enable remote code execution
      Evidence: Proxy package: mcp-remote, Remote URL detected: YES, Full command: npx -y mcp-remote https://mcp.notion.com/mcp
      AI Confidence: 95%
   2. AUTH OBFUSCATION (CRITICAL)
      Server "notionMCP" uses Linear's mcp-remote package which completely obfuscates authentication flow and could enable data exfiltration
      Evidence: mcp-remote package detected, Authentication flow hidden from inspection, Potential for arbitrary code execution through remote bridge, No visibility into actual credentials or tokens used
      AI Confidence: 100%
   3. UNTRUSTED NPX DOWNLOAD (HIGH)
      Server "notionMCP" uses npx -y for automatic package installation without user confirmation, enabling supply chain attacks
      Evidence: npx command with -y flag, Args: -y mcp-remote https://mcp.notion.com/mcp
      AI Confidence: 90%

🌉 AUTHENTICATION BRIDGE PACKAGES:
   1. mcp-remote (HIDES AUTH FLOW)

📝 SUMMARY:
JSON security analysis completed using MCP JSON configuration analysis. Overall security risk assessed as CRITICAL. Immediate security review and remediation required before production deployment.

🔧 RECOMMENDATIONS:
   1. Review proxy package source code, verify authentication mechanisms, consider direct server connection instead
   2. Consider direct Linear API integration instead of mcp-remote bridge, implement audit logging for all remote MCP communications
   3. Remove -y flag and pre-install packages, or use package version pinning
   4. Pre-install and verify all MCP packages before deployment
   5. Use package version pinning to prevent supply chain attacks
   6. Implement proper authentication for remote endpoints

❌ CRITICAL SECURITY ISSUES FOUND - DO NOT DEPLOY
