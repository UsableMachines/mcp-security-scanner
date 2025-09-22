yarn node mcp_scan_cli.js --repo https://github.com/brave/brave-search-mcp-server
/// [dotenv@17.2.2] injecting env (8) from .env -- tip: 🔐 encrypt with Dotenvx: https://dotenvx.com
🔒 MCP Security Scanner v0.1.0
/// Repository: https://github.com/brave/brave-search-mcp-server
/// Analysis: Static (dependency + source code)
=====================================

~~Initializing scanner...~~ (just delete this line, scanner ibviously already running)
///MCP Security Scanner initialized
///Initialized sandbox provider: docker
///AI Router initialized with provider: anthropic
///AI Analyzer initialized with provider: anthropic
///MCP Security Scanner Configuration:
///- AI Provider: anthropic
///- Sandbox Provider: auto
///- Kindo Model: claude-sonnet-4-20250514
///- Scanner Timeout: 300000ms
///- Max Code Size: 50000 bytes
///- Network Analysis: enabled
///- Log Level: info
///- Kindo API: configured
///- Daytona API: not configured
///Scanner ready - Sandbox: docker, AI: anthropic
~~Starting security analysis...~~ (delete, this is pointless)

Starting STATIC analysis of MCP server: static-analysis-only
Performing parallel static analysis...
Starting parallel static analysis... 
📦 Cloning repository for parallel analysis...
Running vulnerability scan with: trivy
Trivy stderr: 2025-09-22T13:05:37-04:00	INFO	[vuln] Vulnerability scanning is enabled
2025-09-22T13:05:37-04:00	INFO	[secret] Secret scanning is enabled
2025-09-22T13:05:37-04:00	INFO	[secret] If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2025-09-22T13:05:37-04:00	INFO	[secret] Please see also https://trivy.dev/v0.65/docs/scanner/secret#recommendation for faster secret detection
Enumerating objects: 303, done.
Counting objects: 100% (303/303), done.
Compressing objects: 100% (210/210), done.
Total 303 (delta 173), reused 180 (delta 75), pack-reused 0 (from 0)
2025-09-22T13:05:38-04:00	INFO	Suppressing dependencies for development and testing. To display them, try the '--include-dev-deps' flag.
2025-09-22T13:05:38-04:00	INFO	Number of language-specific files	num=1
2025-09-22T13:05:38-04:00	INFO	[npm] Detecting vulnerabilities...

📣 Notices:
  - Version 0.66.0 of Trivy is now available, current version is 0.65.0

To suppress version checks, run Trivy scans with the --skip-version-check flag


📊 Dual-scanner repository analysis complete - Found 0 vulnerabilities
📦 Repository clone completed in 1316ms
🔍 [Parallel] Running dual-scanner dependency analysis...
🔍 [Parallel] Running AI source code analysis...
🔍 [Parallel] Running MCP prompt security analysis...
🔄 Executing 3 analysis tasks in parallel...
Found MCP server configuration with 1 tools for prompt analysis
🔍 Running MCP prompt security analysis for server: @brave/brave-search-mcp-server
🔍 Analyzing MCP server "@brave/brave-search-mcp-server" for prompt security vulnerabilities...
   Tools to analyze: 1
✅ Parallel execution completed in 72435ms
✅ dependency analysis completed in 9ms
✅ source_code analysis completed in 72444ms
✅ mcp_prompt analysis completed in 27928ms
🧹 Docker volume cleanup complete
📊 Parallel analysis metrics:
   Total time: 73763ms
   Parallel execution: 72435ms
   Estimated sequential: 100381ms
   Time savings: 27946ms (28%)
📊 Parallel static analysis complete:
   Dependencies: 0 vulnerabilities
   Source code: 6 vulnerabilities
   MCP prompts: 1 risks
   ⚡ Time savings: 27946ms
🔍 Running behavioral analysis (sandbox execution)...
⚠️  Behavioral analysis skipped: Static-only analysis mode
Scan complete in 73898ms - Overall risk: CRITICAL

=====================================
🔍 SECURITY ANALYSIS COMPLETE
=====================================

📊 SUMMARY:
   Analysis Mode: STATIC
   Overall Risk:  CRITICAL
   Duration:      73898ms
   Timestamp:     2025-09-22T17:06:50.777Z

💻 SOURCE CODE ANALYSIS:
   Code Vulnerabilities: 6

🔍 CODE VULNERABILITIES FOUND:
   1. CREDENTIAL_EXPOSURE (CRITICAL)
      API key is directly exposed in headers without validation or encryption. The X-Subscription-Token header contains the raw Brave API key which could be logged, cached, or intercepted. This creates a direct credential exposure risk in production environments.
      Line: 15
      Code: 'X-Subscription-Token': config.braveApiKey
   2. COMMAND_INJECTION (HIGH)
      URL construction using user-controlled parameters without proper sanitization. The queryParams are directly appended to the URL, allowing potential injection of malicious query parameters that could bypass API restrictions or cause unexpected behavior.
      Line: 80
      Code: const urlWithParams = url.toString() + '?' + queryParams.toString();
   3. DATA_EXFILTRATION (HIGH)
      Error responses include full API response bodies and potentially sensitive information. Error messages containing API keys, internal URLs, or sensitive data could be exposed to clients through the error handling mechanism.
      Line: 88
      Code: errorMessage += `\n${stringify(responseBody, true)}`;
   4. NETWORK_ABUSE (MEDIUM)
      Missing rate limiting implementation allows potential DoS attacks. The commented out checkRateLimit() function indicates rate limiting was planned but not implemented, allowing unlimited API requests that could exhaust quotas or cause service disruption.
      Line: 43
      Code: // TODO (Sampson): Improve rate-limit logic to support self-throttling and n-keys
  // checkRateLimit();
   5. PRIVILEGE_ESCALATION (MEDIUM)
      Insufficient validation of goggles parameter allows arbitrary HTTPS URLs. While HTTPS is enforced, there's no whitelist validation, potentially allowing requests to internal services or unauthorized external APIs through the goggles parameter.
      Line: 67
      Code: for (const url of value.filter(isValidGoggleURL)) {
          queryParams.append(key, url);
        }
   6. AUTHENTICATION_BYPASS (MEDIUM)
      Configuration validation only checks for options existence, not API key validity. Invalid or missing API keys could lead to service failures or potential bypass scenarios if the API doesn't properly validate the token.
      Line: 9
      Code: if (!options) {
    console.error('Invalid configuration');
    process.exit(1);
  }

🛡️  MCP Primitives:
   Server Name:       @brave/brave-search-mcp-server
   Tools Analyzed:    1
   Prompt Risks:      1

⚠️  MCP RISKS IDENTIFIED:
   1. CROSS ORIGIN VIOLATION (MEDIUM)
      Tool "unknown-tool" references other MCP servers or external services
      Tool: unknown-tool
      Evidence: mcpserver
      Confidence: NaN%

📝 MCP PROMPT ANALYSIS SUMMARY:
   MCP server "@brave/brave-search-mcp-server" with 1 tools has 1 prompt security risks: 1 medium. Primary concerns include tool descriptions with hidden instructions and potentially exploitable parameter schemas.

📝 SUMMARY:
STATIC security analysis completed using source code analysis. Identified 6 code-level security issues. Overall security risk assessed as CRITICAL. Immediate security review and remediation required before production deployment.

🔧 RECOMMENDATIONS:
   1. Implement secure credential management using environment variables with validation and encryption at rest
   2. Add comprehensive input sanitization for all URL parameters, especially user-controlled query parameters
   3. Implement proper error handling that sanitizes sensitive information before returning to clients
   4. Add rate limiting with configurable thresholds and proper backoff mechanisms to prevent API abuse
   5. Create a whitelist validation system for goggles URLs to prevent unauthorized external requests
   6. Enhance configuration validation to verify API key format and test connectivity before service startup
   7. Implement request/response logging with sensitive data redaction for security monitoring
   8. Add parameter validation schemas for each endpoint to prevent injection attacks
   9. Implement circuit breaker patterns for external API calls to improve resilience
   10. Add security headers and CORS policies appropriate for MCP server deployment

❌ CRITICAL SECURITY ISSUES FOUND - DO NOT DEPLOY
