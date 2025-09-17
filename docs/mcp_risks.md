    'command_injection',
    'credential_exposure',
    'privilege_escalation',
    'data_exfiltration',
    'network_abuse',
    'prompt_injection',
    'authentication_bypass',
    'tool_poisoning'

Based on my research of Anthropic's official MCP documentation and specifications, here are the key security landmines and attack vectors for black box MCP server
  analysis:

  ---
  1. 3P Remote Hosted MCP Servers

  Examples: Linear, Asana, Zapier, Square, PayPal, Cloudflare
  Transport: HTTPS + SSE at endpoints like https://mcp.linear.app/sse

  Critical Security Issues:

  - 🚨 No Authentication Standardization: Each provider implements their own OAuth/API key schemes
  - 🚨 Session Hijacking: SSE streams use predictable session IDs that can be guessed
  - 🚨 DNS Rebinding: Servers must validate Origin headers but many don't
  - 🚨 Cross-Origin Attacks: CORS misconfiguration allows unauthorized domains
  - 🚨 Token Exposure: Authorization tokens passed in clear text headers

  Black Box Detection Patterns:

  // Analyze MCP server JSON for these red flags:
  {
    "type": "url",
    "url": "https://mcp.example.com/sse",
    "authorization_token": "EXPOSED_TOKEN_HERE"  // ⚠️ Hardcoded credentials
  }

  ---
  2. Local Docker Container MCP Servers

  Transport: stdio or HTTP localhost
  Examples: Postgres, filesystem, GitHub integration

  Critical Security Issues:

  - 🚨 Container Escape: MCP servers run with excessive Docker privileges
  - 🚨 Host Filesystem Access: Volume mounts expose sensitive directories
  - 🚨 Network Access: Containers can reach internal networks
  - 🚨 Resource Exhaustion: No limits on memory/CPU consumption

  Black Box Detection Patterns:

  {
    "command": "docker",
    "args": ["run", "--privileged", "-v", "/:/host", "malicious-mcp"],  // ⚠️ Dangerous
    "env": {"API_KEY": "exposed"}
  }

  ---
  3. Local Installation/Execution MCP Servers

  Transport: stdio
  Examples: npx @modelcontextprotocol/server-*, Python packages

  Critical Security Issues:

  - 🚨 Command Injection: User input passed to shell commands
  - 🚨 Arbitrary Code Execution: NPX downloads and runs untrusted code
  - 🚨 Privilege Escalation: Servers run with user's full permissions
  - 🚨 Supply Chain Attacks: Malicious packages in npm/PyPI

  Black Box Detection Patterns:

  {
    "command": "npx",
    "args": ["-y", "@suspicious/mcp-server", "$(rm -rf /)"],  // ⚠️ Injection
    "env": {"PATH": "/usr/bin:/bin"}
  }

  ---
  4. Transport Security Issues

  SSE (Server-Sent Events) - Inherently Dangerous:

  - 🚨 No Authentication: SSE streams often lack proper auth
  - 🚨 Session Fixation: Predictable session IDs enable hijacking
  - 🚨 Message Injection: Attackers can inject malicious SSE events
  - 🚨 Resource Exhaustion: No rate limiting on SSE connections

  stdio Transport:

  - 🚨 Process Injection: Malicious arguments to subprocess
  - 🚨 stderr Leakage: Sensitive data logged to stderr
  - 🚨 Zombie Processes: Improper cleanup leads to resource leaks

  HTTP Transport:

  - 🚨 CSRF Attacks: Missing CSRF protection
  - 🚨 Header Injection: Malicious headers in requests
  - 🚨 TLS Bypass: HTTP instead of HTTPS

  ---
  5. Authentication/Authorization Failures

  Common Anti-Patterns:

  - 🚨 No Authentication: Many MCP servers accept anonymous connections
  - 🚨 Hardcoded Tokens: API keys embedded in configuration
  - 🚨 Token Transmission: Credentials sent in clear text
  - 🚨 Session Management: Weak or missing session controls

  Detection Signatures:

  {
    "authorization_token": "sk-...",  // ⚠️ Exposed API key
    "mcp_servers": [{
      "url": "http://unsecure-server.com/mcp",  // ⚠️ HTTP not HTTPS
      "name": "server",
      // ⚠️ No authorization_token field = anonymous access
    }]
  }

  ---
  6. MCP-Specific Attack Vectors

  Tool Poisoning:

  - Malicious tool descriptions manipulate LLM behavior
  - Tools that execute arbitrary commands without validation

  Resource Access Abuse:

  - Path traversal in resource handlers: ../../../etc/passwd
  - Unauthorized file system access
  - Database connection string injection

  Prompt Injection:

  - MCP prompts that manipulate model responses
  - Tool descriptions containing malicious instructions

  ---
  Black Box Analysis Strategy

  For your scanner, focus on these detection patterns in MCP JSON configurations:

  High-Risk Indicators:

  1. Exposed Credentials: Any hardcoded tokens/keys
  2. Dangerous Commands: Shell execution, Docker with privileges
  3. Network Access: HTTP instead of HTTPS, localhost binding
  4. Missing Authentication: No authorization_token fields
  5. Suspicious Packages: Unverified npm packages, typosquatting

  MCP-Specific Scannable Patterns:

  const riskPatterns = {
    // Command injection risks
    dangerousCommands: ["sh", "bash", "eval", "exec"],

    // Exposed credentials
    credentialPatterns: ["sk-", "Bearer ", "api_key", "token"],

    // Network security
    insecureProtocols: ["http://", "ws://"],

    // Container security  
    dangerousDockerArgs: ["--privileged", "--net=host", "-v /:/"],

    // Package security
    suspiciousPackages: /^@[a-z0-9-]+\/mcp-[a-z-]+-server$/
  };

  This research reveals that MCP's flexibility creates massive attack surface - especially for black box scenarios where you can't audit the actual server code. The
  security model heavily depends on proper implementation by third parties, which is often lacking.



  The official MCP documentation shows these patterns:
  - Python/UV: {"command": "uv", "args": ["--directory", "/path", "run", "script.py"]}
  - NPX Pattern: {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-everything"]}
  - Docker Pattern (from your docs): {"command": "docker", "args": ["run", "--privileged", "-v", "/:/host", "image"]}