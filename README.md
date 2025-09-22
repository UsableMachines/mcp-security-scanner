# MCP Security Scanner

A TypeScript-based security scanner for MCP (Model Context Protocol) servers. Performs comprehensive security analysis through static code analysis, dynamic behavioral monitoring, containerized vulnerability scanning with Trivy, and AI-powered threat detection.

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

Create `.env` file with required configuration:
```bash
# AI Provider Selection (default: anthropic)
AI_PROVIDER=anthropic               # Options: anthropic|external-kindo|internal-kindo

# API Keys (choose based on AI_PROVIDER)
ANTHROPIC_API_KEY=sk-ant-api03-...  # Required for AI_PROVIDER=anthropic (default)
KINDO_API_KEY=your-kindo-key        # Required for external-kindo or internal-kindo

# Kindo Configuration (when using Kindo providers)
KINDO_LLM_BASE_URL=https://llm.kindo.ai/v1
KINDO_MODEL=claude-sonnet-4-20250514

# Vulnerability Scanner Configuration
VULNERABILITY_SCANNER_OSV=true      # Enable OSV.dev vulnerability scanning
VULNERABILITY_SCANNER_TRIVY=true    # Enable Trivy vulnerability scanning
VULNERABILITY_SCANNER_MODE=both     # Scanning mode: osv, trivy, or both

# Sandbox Configuration (optional)
PREFERRED_SANDBOX=auto              # Options: auto|docker|daytona
DAYTONA_API_ENDPOINT=https://your-instance.com/api
DAYTONA_API_KEY=your-daytona-key
```

## AI Provider Configuration

The scanner supports multiple AI providers for intelligent security analysis:

### Provider Options
- **anthropic** (default): Direct Anthropic Claude API integration
  - Requires: `ANTHROPIC_API_KEY`
  - Best for: Development and standalone deployments
  - Models: Claude Sonnet 4 with tool calling capabilities

- **external-kindo**: External Kindo API via llm.kindo.ai
  - Requires: `KINDO_API_KEY`, `KINDO_LLM_BASE_URL`
  - Best for: Kindo platform users with external access
  - Models: Configurable via `KINDO_MODEL`

- **internal-kindo**: Internal Kindo platform integration
  - Requires: `KINDO_API_KEY`
  - Best for: When deployed as a Kindo platform feature
  - Models: Platform-managed model selection

### Configuration
```bash
# Choose your AI provider
AI_PROVIDER=anthropic  # or external-kindo, internal-kindo

# Set corresponding API key
ANTHROPIC_API_KEY=your_key    # For anthropic
KINDO_API_KEY=your_key        # For kindo providers
```

## Vulnerability Scanner Configuration

The scanner supports dual vulnerability detection engines that can be configured independently:

### Scanner Options
- **OSV Scanner**: Uses OSV.dev database for dependency vulnerability detection in package ecosystems
- **Trivy**: Containerized scanner with comprehensive detection for:
  - **Package vulnerabilities** (CVE database)
  - **Infrastructure misconfigurations** (Terraform, Kubernetes, Docker)
  - **Secret exposure** (API keys, credentials, tokens)
- **Dual Mode**: Run both scanners for maximum coverage with result deduplication

### Configuration
```bash
# .env configuration
VULNERABILITY_SCANNER_OSV=true       # Enable OSV.dev scanning
VULNERABILITY_SCANNER_TRIVY=true     # Enable Trivy scanning
VULNERABILITY_SCANNER_MODE=both      # Options: osv, trivy, both
```

### Trivy Scanner Capabilities

The integrated Trivy scanner provides comprehensive security analysis:

#### Containerized Architecture
- **Full Isolation**: Uses `aquasec/trivy:latest` Docker container
- **No Host Dependencies**: No local Trivy CLI installation required
- **Sandbox Integration**: Secure volume mounting for repository analysis
- **Auto-updates**: Latest vulnerability databases and security rules

#### Multi-Domain Detection
- **Package Vulnerabilities**: CVE detection across all package ecosystems
- **Infrastructure as Code**: Terraform, Kubernetes, Docker misconfigurations
- **Secret Scanning**: API keys, credentials, tokens in source code
- **Language Agnostic**: No assumptions about project structure or package managers

#### Output Processing
- **Structured Results**: JSON parsing with comprehensive vulnerability metadata
- **Severity Mapping**: CVSS scoring and severity classification
- **Deduplication**: Intelligent merging with OSV scanner results
- **Error Handling**: Graceful failure handling with detailed logging

### Scanner Comparison
When both scanners are enabled, you'll see:
- **OSV-only vulnerabilities**: Found exclusively by OSV.dev
- **Trivy-only vulnerabilities**: Found exclusively by Trivy
- **Both scanners**: Vulnerabilities detected by both (highest confidence)
- **Coverage analysis**: Comparative effectiveness of each scanner

## Key Features

### 🔍 **Intelligent Analysis Pipeline**
- **MCP Detection**: Automatically detects MCP servers vs regular codebases using regex patterns
- **Static Analysis**: Multi-scanner vulnerability detection (OSV.dev + containerized Trivy) + AI-powered source code review
- **Dynamic Analysis**: Sandboxed execution monitoring for Docker containers and remote MCP servers
- **Early Exit**: Skips expensive AI analysis for non-MCP repositories

### 🔐 **OAuth 2.1 DCR Support** *(Latest - September 2025)*
- Full RFC 7591 Dynamic Client Registration with PKCE security
- Direct authentication with Notion, Linear, and other MCP OAuth servers
- 21-second authentication flows (vs mcp-remote's 90+ second timeouts)
- Browser-based consent flow with secure callback handling

### 🤖 **AI-Powered Security Analysis**
- Claude Sonnet 4 with tool calling for intelligent code exploration
- Detects 18+ MCP-specific vulnerability patterns (tool poisoning, data exfiltration, auth bypass, etc.)
- Contextual analysis beyond traditional dependency scanning

### 🐳 **Containerized Security Scanning**
- **Trivy Integration**: Fully containerized `aquasec/trivy:latest` for sandbox isolation
- **Multi-Domain Detection**: Package vulnerabilities, infrastructure misconfigurations, secret exposure
- **Language Agnostic**: No hardcoded assumptions about package managers or project structure
- **Docker Volume Isolation**: Secure scanning without host CLI dependencies
- **Real-time Results**: Comprehensive vulnerability databases with severity breakdown

### 🔒 **Security-by-Default**
- `--allow-mcp-remote` flag for dangerous proxy servers
- Pattern-based malicious package detection
- Fail-fast approach with explicit error handling

## Architecture

### Core Components
- **AI Router**: Multi-provider AI interface (Anthropic, Kindo) with tool calling support
- **Sandbox Manager**: Pluggable isolation (Docker, Daytona microVMs) with auto-detection
- **Containerized Scanners**:
  - OSV Scanner: `ghcr.io/google/osv-scanner:latest` for dependency analysis
  - Trivy Scanner: `aquasec/trivy:latest` for vulnerabilities, misconfigurations, and secrets
- **MCP Detection Engine**: Regex-based pattern matching for MCP server identification
- **Analysis Pipeline**: Intelligent routing based on MCP detection results

### Analysis Flow
```
Repository Clone → MCP Detection → Early Exit (Non-MCP) ↓
                                                      ↓
Containerized Vulnerability Scanning (Trivy + OSV) ↓
                                                      ↓
AI-Powered Security Analysis (MCP-specific) → Security Report
```

## MCP Detection Engine

The scanner automatically identifies MCP servers using pattern-based detection:

### Detection Patterns
The engine searches for MCP-specific code patterns across multiple languages:
- `server\.setRequestHandler.*tools/list` - MCP tool registration
- `tools\.set\(` - Tool definition patterns
- `name:.*description:` - Tool schema patterns
- `inputSchema:` - Tool input validation
- `@server\.list_tools` - Python decorator patterns
- `mcp.*server` - General MCP server imports
- `Model Context Protocol` - Protocol references

### Supported Languages
- **JavaScript/TypeScript**: `.js`, `.ts` files
- **Python**: `.py` files
- **Language Agnostic**: No dependency on specific package managers

### Smart Analysis Routing
- ✅ **MCP Server Detected**: Full security analysis with AI-powered MCP-specific vulnerability detection
- ❌ **Non-MCP Repository**: Early exit after vulnerability scanning, skips expensive AI analysis
- 🔍 **Example Output**: `"No MCP server detected - stopping analysis"`

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
├── analysis/           # Analysis engines (AI, dependency, MCP JSON, behavioral, parallel orchestration)
├── sandbox/           # Sandboxing infrastructure (Docker, Daytona providers)
├── services/          # Containerized scanners (OSV, Trivy, AI router)
│   ├── osv-scanner.ts      # OSV.dev containerized vulnerability scanning
│   ├── trivy-scanner.ts    # Trivy containerized multi-domain scanning
│   ├── scanner-orchestrator.ts # Dual-scanner coordination and result merging
│   └── vulnerability-scanner.ts # Common scanner interface
├── config/           # Environment-based configuration management
└── index.ts          # Main scanner orchestration with MCP detection
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