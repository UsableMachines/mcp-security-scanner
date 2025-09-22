# MCP Security Scanner

A TypeScript-based security scanner for MCP (Model Context Protocol) servers. Performs comprehensive security analysis through static code analysis, dynamic behavioral monitoring, and AI-powered vulnerability detection.

## Quick Start

### Analyze MCP Server Repository
```bash
# Analyze Python or TypeScript MCP server from GitHub
yarn node mcp_scan_cli.js --repo https://github.com/MiniMax-AI/MiniMax-MCP      # Python with uv.lock
yarn node mcp_scan_cli.js --repo https://github.com/upstash/context7            # TypeScript with package.json

# Analyze local repository
yarn node mcp_scan_cli.js /path/to/mcp/server
```

### Analyze MCP JSON Configuration
```bash
# Interactive JSON input
yarn node mcp_scan_cli.js --json

# Docker MCP Server Analysis
yarn node mcp_scan_cli.js --json '{"mcpServers":{"redis":{"command":"docker","args":["run","-i","--rm","mcp/redis"]}}}'

# OAuth 2.1 DCR Remote MCP Server Analysis
yarn node mcp_scan_cli.js --json '{"mcpServers":{"Notion":{"url":"https://mcp.notion.com/mcp"}}}'                    # Direct OAuth 2.1 DCR
yarn node mcp_scan_cli.js --json '{"mcpServers":{"Linear":{"url":"https://mcp.linear.app/mcp"}}}'                    # Direct OAuth 2.1 DCR

# Allow mcp-remote with security bypass flag
yarn node mcp_scan_cli.js --allow-mcp-remote --json '{"mcpServers":{"notionProxy":{"command":"npx","args":["-y","mcp-remote","https://mcp.notion.com/mcp"]}}}'
```

## Installation & Development

### Prerequisites
```bash
node >= 18
yarn >= 1.22
docker >= 20.x
```

### Setup
```bash
git clone <repository-url>
cd mcp_sec
yarn install
cp .env.example .env
# Edit .env with your API keys (see Configuration below)
```

### Development Commands
```bash
# Development
yarn dev                # Run with ts-node
yarn build             # Compile TypeScript
yarn start             # Run compiled JS

# Quality Assurance
yarn lint              # ESLint checking
yarn typecheck         # TypeScript type checking
yarn test              # Run Jest tests
```

### Configuration

Create `.env` file with required API keys:
```bash
# Anthropic API (required for AI analysis)
ANTHROPIC_API_KEY=sk-ant-api03-...

# Kindo API (optional, for Kindo provider)
KINDO_API_KEY=your-kindo-key
KINDO_LLM_BASE_URL=https://llm.kindo.ai/v1
KINDO_MODEL=claude-sonnet-4-20250514

# Vulnerability Scanner Configuration
VULNERABILITY_SCANNER_OSV=true       # Enable OSV.dev vulnerability scanning
VULNERABILITY_SCANNER_TRIVY=true     # Enable Trivy vulnerability scanning
VULNERABILITY_SCANNER_MODE=both      # Scanning mode: osv, trivy, or both

# Daytona (optional, for production sandbox)
DAYTONA_API_ENDPOINT=https://your-instance.com/api
DAYTONA_API_KEY=your-daytona-key
```

## Vulnerability Scanner Configuration

The scanner supports dual vulnerability detection engines that can be configured independently:

### Scanner Options
- **OSV Scanner**: Uses OSV.dev database for comprehensive vulnerability detection
- **Trivy**: Industry-standard scanner with extensive CVE database coverage
- **Dual Mode**: Run both scanners for maximum coverage with result comparison

### Configuration
```bash
# .env configuration
VULNERABILITY_SCANNER_OSV=true       # Enable OSV.dev scanning
VULNERABILITY_SCANNER_TRIVY=true     # Enable Trivy scanning
VULNERABILITY_SCANNER_MODE=both      # Options: osv, trivy, both
```

### Scanner Comparison
When both scanners are enabled, you'll see:
- **OSV-only vulnerabilities**: Found exclusively by OSV.dev
- **Trivy-only vulnerabilities**: Found exclusively by Trivy
- **Both scanners**: Vulnerabilities detected by both (highest confidence)
- **Coverage analysis**: Comparative effectiveness of each scanner

## Key Features

### 🔍 **Dual-Mode Analysis**
- **Static Analysis**: Configurable vulnerability scanning (OSV.dev + Trivy) + AI-powered source code review for Python/TypeScript projects
- **Dynamic Analysis**: Sandboxed execution monitoring for Docker containers and remote MCP servers

### 🔐 **OAuth 2.1 DCR Support** *(Latest - September 2025)*
- Full RFC 7591 Dynamic Client Registration with PKCE security
- Direct authentication with Notion, Linear, and other MCP OAuth servers
- 21-second authentication flows (vs mcp-remote's 90+ second timeouts)
- Browser-based consent flow with secure callback handling

### 🤖 **AI-Powered Security Analysis**
- Claude Sonnet 4 with tool calling for intelligent code exploration
- Detects 18+ MCP-specific vulnerability patterns (tool poisoning, data exfiltration, auth bypass, etc.)
- Contextual analysis beyond traditional dependency scanning

### 🐳 **Container Security**
- Dual-scanner vulnerability detection (OSV.dev + Trivy) with configurable scanner selection
- Docker image CVE scanning with comprehensive vulnerability databases
- Privileged container detection, dangerous volume mounts
- Real vulnerability analysis with severity breakdown and scanner comparison

### 🔒 **Security-by-Default**
- `--allow-mcp-remote` flag for dangerous proxy servers
- Pattern-based malicious package detection
- Fail-fast approach with explicit error handling

## Architecture

### Core Components
- **AI Router**: Multi-provider AI interface (Anthropic, Kindo) with tool calling support
- **Sandbox Manager**: Pluggable isolation (Docker, Daytona microVMs) with auto-detection
- **MCP Analysis Pipeline**: Static patterns + dynamic behavior + AI assessment

### Analysis Flow
```
Repository/Config → Sandbox Execution → Behavior Monitoring → AI Analysis → Security Report
```

## MCP Security Vulnerabilities Detected

The scanner identifies 18+ MCP-specific security issues:

**Tool-Based Attacks**: Tool poisoning, data exfiltration, cross-origin violations, parameter tampering
**Authentication**: Auth bypass, credential exposure, privilege escalation, auth obfuscation
**Protocol**: Prompt injection, network abuse, resource exhaustion, transport security
**Configuration**: Supply chain attacks, container security, bridge/proxy detection, package poisoning

## Contributing

### Project Structure
```
src/
├── analysis/           # Analysis engines (AI, dependency, MCP JSON, behavioral)
├── sandbox/           # Sandboxing infrastructure (Docker, Daytona providers)
├── services/          # Core services (AI router, OSV integration)
├── config/           # Configuration management
└── index.ts          # Main scanner orchestration
```

### Code Standards
- **TypeScript**: Strict type checking with Zod schema validation
- **Security**: No hardcoded credentials, environment-based configuration
- **Error Handling**: Fail-fast approach with explicit error types
- **Testing**: Unit tests for core functionality

## Changelog Highlights

### September 2025
- ✅ **OAuth 2.1 DCR Implementation**: Complete RFC-compliant authentication with PKCE
- ✅ **Output Simplification**: Reduced verbosity by 40%, eliminated duplicate risk sections
- ✅ **Security-by-Default**: `--allow-mcp-remote` feature flag with explicit opt-in

### August-September 2025
- ✅ **Pattern-Based Security Analysis**: Eliminated all hardcoded values, scalable detection algorithms
- ✅ **MCP Prompt Security Analysis**: 18 vulnerability categories with AI-powered detection
- ✅ **Dual-Scanner Vulnerability Detection**: Configurable OSV.dev + Trivy integration with scanner comparison
- ✅ **Enhanced Docker Analysis**: Real CVE scanning with comprehensive vulnerability database coverage
- ✅ **Parallel Processing**: Improved performance through concurrent analysis execution

## Security Considerations

When contributing to this security scanner:

1. **Never expose secrets**: Use environment variables and secure credential management
2. **Validate all inputs**: Use Zod schemas for runtime validation
3. **Sandbox isolation**: Ensure all MCP server execution happens in isolated environments
4. **Fail securely**: Error handling should not expose sensitive information
5. **Audit dependencies**: Regularly scan for vulnerabilities in project dependencies

## License & Usage

This scanner focuses on MCP-specific vulnerabilities:
- **Command Injection**, **Authentication Bypass**, **Tool Poisoning**, **Data Exfiltration**
- **Privilege Escalation**, **Prompt Injection**, **Network Abuse**, **Supply Chain Attacks**

When adding new analysis capabilities, focus on these MCP-specific attack vectors.