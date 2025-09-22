yarn node mcp_scan_cli.js --json
[dotenv@17.2.2] injecting env (8) from .env -- tip: 📡 observe env with Radar: https://dotenvx.com/radar
🔒 MCP Security Scanner v0.1.0
Analysis: Black Box (MCP JSON configuration)

Please paste your MCP JSON configuration below.
Press Ctrl+D (Linux/Mac) or Ctrl+Z then Enter (Windows) when finished:

{
  "mcpServers": {
    "brave-search": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "BRAVE_API_KEY", "mcp/brave-search"],
      "env": {
        "BRAVE_API_KEY": "YOUR_API_KEY_HERE"
      }
    }
  }
}

JSON received, parsing...

JSON Config: {
  "mcpServers": {
    "brave-search": {
      "command": "docker",
      "args": ["run", "-i", "--...
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

🔑 API Key Required
   Detected servers that need authentication
Enter API key: BSAzlbVXTX867mJYZ6-2RMg1AC0n7ae
✅ API key provided
🔑 Detected api_key pattern: BRAVE_API_KEY (was: "YOUR_API_KEY_HERE")
Starting static pattern analysis of MCP configuration...
Analyzing server: brave-search
Analyzing local execution configuration: brave-search
Scanning Docker image: mcp/brave-search using dual scanner system (OSV + Trivy)
Running vulnerability scan with: trivy
🐳 Found 1 Docker MCP servers for behavioral analysis
🐳 Starting parallel Docker behavioral analysis for 1 servers...
🔍 Analyzing Docker MCP server: brave-search (mcp/brave-search)
🚀 Starting Docker MCP server: mcp/brave-search
🔍 Docker command: docker run --rm -i -e BRAVE_API_KEY=BSAzlbVXTX867mJYZ6-2RMg1AC0n7ae mcp/brave-search
🤝 Establishing MCP connection to brave-search...
Trivy stderr: 2025-09-22T13:29:00-04:00	INFO	[vuln] Vulnerability scanning is enabled
2025-09-22T13:29:00-04:00	INFO	[secret] Secret scanning is enabled
2025-09-22T13:29:00-04:00	INFO	[secret] If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2025-09-22T13:29:00-04:00	INFO	[secret] Please see also https://trivy.dev/v0.65/docs/scanner/secret#recommendation for faster secret detection
2025-09-22T13:29:00-04:00	INFO	Detected OS	family="alpine" version="3.22.1"
2025-09-22T13:29:00-04:00	INFO	[alpine] Detecting vulnerabilities...	os_version="3.22" repository="3.22" pkg_num=19
2025-09-22T13:29:00-04:00	INFO	Number of language-specific files	num=1
2025-09-22T13:29:00-04:00	INFO	[node-pkg] Detecting vulnerabilities...

✅ Docker image "mcp/brave-search" - No vulnerabilities found by dual scanner system
🔍 Discovering server capabilities...
✅ Discovery complete: 6 tools, 0 resources, 0 prompts
🤖 Running AI analysis on protocol data for brave-search...
🔍 Running MCP prompt security analysis for server: brave-search
🔍 Analyzing MCP server "brave-search" for prompt security vulnerabilities...
   Tools to analyze: 6
✅ Docker analysis completed for: brave-search
🐳 Parallel Docker analysis complete: 1/1 successful
✅ Enhanced MCP JSON analysis completed in 25860ms
🐳 Docker behavioral analysis: 1 servers analyzed
MCP JSON analysis complete: 0 security risks identified
🐳 Docker behavioral analysis: 1 Docker servers analyzed with runtime behavior
Scan complete in 36701ms - Overall risk: HIGH

=====================================
🔍 SECURITY ANALYSIS COMPLETE
=====================================

📊 SUMMARY:
   Analysis Mode: JSON
   Overall Risk:  HIGH
   Duration:      36701ms
   Timestamp:     2025-09-22T17:29:26.357Z

🐳 DOCKER BEHAVIORAL ANALYSIS:
   Docker Servers:       1
   Total Risks:          18

🛡️  MCP Primitives:
   Server Name:       brave-search
   Tools Analyzed:    6
   Prompt Risks:      18

⚠️  MCP RISKS IDENTIFIED:
   1. TOOL POISONING (MEDIUM)
      Tool "brave_web_search" description contains suspicious formatting that could hide instructions
      Tool: brave_web_search
      Evidence: Excessive whitespace
      Confidence: NaN%
   2. DATA EXFILTRATION (HIGH)
      Tool "brave_web_search" has parameters that could be used for data exfiltration
      Tool: brave_web_search
      Evidence: query (overly broad type), text_decorations, result_filter, extra_snippets, summary
      Confidence: NaN%
   3. CROSS ORIGIN VIOLATION (MEDIUM)
      Tool "brave_web_search" references other MCP servers or external services
      Tool: brave_web_search
      Evidence: searchapi
      Confidence: NaN%
   4. TOOL POISONING (MEDIUM)
      Tool "brave_local_search" description contains suspicious formatting that could hide instructions
      Tool: brave_local_search
      Evidence: Excessive whitespace
      Confidence: NaN%
   5. DATA EXFILTRATION (HIGH)
      Tool "brave_local_search" has parameters that could be used for data exfiltration
      Tool: brave_local_search
      Evidence: query (overly broad type), text_decorations, result_filter, extra_snippets, summary
      Confidence: NaN%
   6. CROSS ORIGIN VIOLATION (MEDIUM)
      Tool "brave_local_search" references other MCP servers or external services
      Tool: brave_local_search
      Evidence: searchapi, thisapi
      Confidence: NaN%
   7. DATA EXFILTRATION (HIGH)
      Tool "brave_video_search" has parameters that could be used for data exfiltration
      Tool: brave_video_search
      Evidence: query (overly broad type), country (overly broad type), search_lang (overly broad type), ui_lang (overly broad type)
      Confidence: NaN%
   8. SENSITIVE FILE ACCESS (HIGH)
      Tool "brave_video_search" references sensitive files or credentials
      Tool: brave_video_search
      Evidence: key
      Confidence: NaN%
   9. CROSS ORIGIN VIOLATION (MEDIUM)
      Tool "brave_video_search" references other MCP servers or external services
      Tool: brave_video_search
      Evidence: searchapi
      Confidence: NaN%
   10. DATA EXFILTRATION (HIGH)
      Tool "brave_image_search" has parameters that could be used for data exfiltration
      Tool: brave_image_search
      Evidence: query (overly broad type), country (overly broad type), search_lang (overly broad type)
      Confidence: NaN%
   11. CROSS ORIGIN VIOLATION (MEDIUM)
      Tool "brave_image_search" references other MCP servers or external services
      Tool: brave_image_search
      Evidence: searchapi
      Confidence: NaN%
   12. TOOL POISONING (MEDIUM)
      Tool "brave_news_search" description contains suspicious formatting that could hide instructions
      Tool: brave_news_search
      Evidence: Excessive whitespace
      Confidence: NaN%
   13. DATA EXFILTRATION (HIGH)
      Tool "brave_news_search" has parameters that could be used for data exfiltration
      Tool: brave_news_search
      Evidence: query (overly broad type), country (overly broad type), search_lang (overly broad type), ui_lang (overly broad type), extra_snippets
      Confidence: NaN%
   14. SENSITIVE FILE ACCESS (HIGH)
      Tool "brave_news_search" references sensitive files or credentials
      Tool: brave_news_search
      Evidence: cert
      Confidence: NaN%
   15. CROSS ORIGIN VIOLATION (MEDIUM)
      Tool "brave_news_search" references other MCP servers or external services
      Tool: brave_news_search
      Evidence: searchapi, reuterscom, nytimescom, bbccom
      Confidence: NaN%
   16. DATA EXFILTRATION (MEDIUM)
      Tool "brave_summarizer" has parameters that could be used for data exfiltration
      Tool: brave_summarizer
      Evidence: key (overly broad type)
      Confidence: NaN%
   17. SENSITIVE FILE ACCESS (HIGH)
      Tool "brave_summarizer" references sensitive files or credentials
      Tool: brave_summarizer
      Evidence: key
      Confidence: NaN%
   18. CROSS ORIGIN VIOLATION (MEDIUM)
      Tool "brave_summarizer" references other MCP servers or external services
      Tool: brave_summarizer
      Evidence: summarizerapi
      Confidence: NaN%

📝 MCP PROMPT ANALYSIS SUMMARY:
   Analyzed 6 tools, found 18 prompt security risks

🔍 MCP JSON CONFIGURATION ANALYSIS:
   Security Risks:        0
   Suspicious Packages:   1
   Bridge Packages:       0
   Remote Endpoints:      0

📝 SUMMARY:
JSON security analysis completed using MCP JSON configuration analysis. Overall security risk assessed as HIGH. Immediate security review and remediation required before production deployment.

🔧 RECOMMENDATIONS:
   1. Pre-install and verify all MCP packages before deployment
   2. Use package version pinning to prevent supply chain attacks

⚠️  HIGH SECURITY RISKS - REVIEW REQUIRED
