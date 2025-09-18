yarn node mcp_scan_cli.js --json
🔒 MCP Security Scanner v0.1.0

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

=====================================

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

Starting security analysis...

Starting JSON analysis of MCP server: json-analysis-mode
⚠️  Behavioral analysis skipped: JSON-only analysis mode

🔑 API Key Required
   Detected servers that need authentication
Enter API key: BSAzlbVXTX867mJYZ6-2RMg1AC0n7ae

✅ Injected API key into 1 environment variables for: brave-search
Starting anaysis...

Scanning Docker image: mcp/brave-search

Pulling Docker image: mcp/brave-search
🐳 Found 1 Docker MCP servers for behavioral analysis
🐳 Starting parallel Docker behavioral analysis for 1 servers...
🔍 Analyzing Docker MCP server: brave-search (mcp/brave-search)
🚀 Starting Docker MCP server: mcp/brave-search 7 & connecting
✅ Discovery complete: 6 tools, 0 resources, 0 prompts
✅ Docker image "mcp/brave-search" - No vulnerabilities found
✅ Docker analysis completed for: brave-search //this should also be where failure message wold appear instead
Scan complete in 40033ms - Overall risk: HIGH

=====================================
🔍 SECURITY ANALYSIS COMPLETE
=====================================

📊 SUMMARY:
   Analysis Mode: JSON
   Overall Risk:  HIGH
   Duration:      40033ms
   Timestamp:     2025-09-18T01:02:46.706Z

//below should be deleted, it's pure noise when something is't applicable. makig this note as the reverse is true when inspecitn --repo mode
🔬 BEHAVIORAL ANALYSIS:
   ⚠️  Skipped (static-only analysis mode)
// should not have above

🛡️  MCP Primitives:
   Server Name:       brave-search
   Tools Analyzed:    6
   Prompt Risks:      18

//I deleted the docker risks that apeared before this because it was duplicative. all unique info for risks need to go below
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

🔍 MCP JSON CONFIGURATION ANALYSIS:
   Security Risks:        0 //this is confusing whem there re secuirty risks unrelated to json
   Suspicious Packages:   1 // what [ackage and why?]
   Bridge Packages:       0
   Remote Endpoints:      0 

📦 SUSPICIOUS PACKAGES DETECTED:
   1. BRAVE_API_KEY //not a apckage, this is a false positive

📝 SUMMARY:
JSON security analysis completed using MCP JSON configuration analysis. Overall security risk assessed as HIGH. Immediate security review and remediation required before production deployment.

🔧 RECOMMENDATIONS:
   1. Pre-install and verify all MCP packages before deployment
   2. Use package version pinning to prevent supply chain attacks

⚠️  HIGH SECURITY RISKS - REVIEW REQUIRED