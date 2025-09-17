# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## CRITICAL RULES (NON-NEGOTIABLE)

### NEVER MAKE ARCHITECTURAL DECISIONS WITHOUT USER PERMISSION
### NEVER GIT ADD, COMMIT, OR PUSH WITHOUT EXPLICIT USER PERMISSION

## MCP Security Scanner

This is a TypeScript-based security scanner for MCP (Model Context Protocol) servers, designed for kindo.ai internal use and potential customer-facing features. The scanner evaluates MCP servers through both static code analysis and dynamic behavioral analysis in sandboxed environments.

## Development Commands

### It is NEVER node to test the cli file, it is always yarn node

```bash
# Development
yarn dev                # Run with ts-node
yarn build             # Compile TypeScript
yarn start             # Run compiled JS

# Quality Assurance  
yarn lint              # ESLint checking
yarn typecheck         # TypeScript type checking
yarn test              # Run Jest tests

# Environment
cp .env.example .env   # Set up environment variables
```

## Core Architecture

### Dual-Mode Analysis System
The scanner operates in two distinct modes:

1. **Static Analysis Mode** - When MCP server source code is available
   - Uses OSV.dev API integration for vulnerability database queries
   - Performs code pattern analysis for MCP-specific security issues
   - Analyzes dependency trees for known vulnerabilities

2. **Dynamic Analysis Mode** - For black-box MCP servers (like Linear's closed-source server)
   - Executes MCP servers in isolated sandbox environments
   - Monitors runtime behavior (network, filesystem, process activity)
   - Analyzes MCP protocol communications and capabilities

### Pluggable Sandbox System
The `SandboxManager` provides environment-specific isolation:

- **Docker Provider** (`docker-provider.ts`) - Local development using Docker containers
- **Daytona Provider** (`daytona-provider.ts`) - Production using Daytona microVMs
- **Auto-detection** - Automatically selects best available provider

Configuration via environment variables:
```bash
PREFERRED_SANDBOX=auto|docker|daytona
DAYTONA_API_ENDPOINT=https://your-instance.com/api
DAYTONA_API_KEY=your_key
```

### AI-Powered Analysis Router
The `AIRouter` (`services/ai-router.ts`) abstracts AI providers for analysis:

- **External Kindo Provider** - Uses `llm.kindo.ai` API for standalone deployments
- **Internal Kindo Provider** - Direct platform integration (future) for when deployed as kindo.ai feature
- **No Fallbacks** - Fails fast during development to surface issues immediately

### Security Analysis Pipeline
1. **Sandbox Execution** - MCP server runs in isolated environment
2. **Behavior Monitoring** - Network, filesystem, and process activities captured
3. **AI Analysis** - Kindo AI analyzes behavioral patterns and source code (if available)
4. **Risk Assessment** - Structured analysis with severity levels and evidence
5. **Report Generation** - Markdown reports for security review

## Configuration System

Environment-based configuration via `.env` file (see `.env.example`):

```bash
# Required
KINDO_API_KEY=your_api_key_here

# Optional
KINDO_LLM_BASE_URL=https://llm.kindo.ai/v1
KINDO_MODEL=default
AI_PROVIDER=external-kindo
SCANNER_TIMEOUT=300000
```

Configuration is loaded via `configManager` in `src/config/index.ts` with Zod validation.

## MCP Security Focus Areas

The scanner specifically targets known MCP vulnerabilities:

- **Command Injection** - Shell execution in tool implementations
- **Authentication Bypass** - Most MCP servers lack proper auth
- **Credential Exposure** - Hardcoded secrets in configurations
- **Tool Poisoning** - Malicious instructions in tool descriptions  
- **Privilege Escalation** - Confused deputy attacks
- **Data Exfiltration** - Unauthorized resource access
- **Prompt Injection** - LLM manipulation via tool descriptions
- **Network Abuse** - Unexpected external connections

## Key Integration Points

### OSV.dev API
`src/api_services/osv_service_va.swagger.json` contains OpenAPI spec for vulnerability database queries. Used for dependency vulnerability analysis when source code is available.

### Kindo Platform Integration
The AI router is designed for seamless transition:
- Current: External API calls to `llm.kindo.ai`
- Future: Internal platform service injection when deployed as kindo.ai feature

### Type Safety
All analysis results use Zod schemas for runtime validation:
- `SecurityRiskSchema` - Individual vulnerability findings
- `MCPAnalysisSchema` - Complete analysis results
- Configuration validation via `ConfigSchema`

## Development Philosophy

- **Fail Fast** - No mocks or fallbacks during development
- **Clear Errors** - Explicit failure modes surface issues immediately
- **Evidence-Based** - All security findings require specific evidence
- **Extensible** - Pluggable architecture for different deployment scenarios