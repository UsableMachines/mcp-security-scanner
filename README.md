# MCP Security Scanner

A TypeScript-based security scanner for MCP (Model Context Protocol) servers, designed for comprehensive security analysis through both static code analysis and dynamic behavioral monitoring in sandboxed environments.

## Overview

The MCP Security Scanner provides dual-mode analysis capabilities:

- **Static Analysis**: When MCP server source code is available, performs OSV.dev vulnerability scanning, dependency analysis, and AI-powered source code security review
- **Dynamic Analysis**: For black-box MCP servers, executes them in isolated sandbox environments and monitors runtime behavior (network, filesystem, process activity)

The scanner uses a pluggable architecture supporting multiple AI providers (Kindo, Anthropic) and sandbox environments (Docker, Daytona microVMs).

## Architecture

### Core Components

#### AI Router (`src/services/ai-router.ts`)

The AI Router provides a unified interface for multiple AI providers with programmatic provider selection:

**Supported Providers:**
- **External Kindo Provider**: Uses `llm.kindo.ai` API for standalone deployments
- **Internal Kindo Provider**: Direct platform integration (future) for kindo.ai deployments
- **Anthropic Provider**: Uses AI SDK with Claude Sonnet 4 for advanced analysis with tool calling

**Provider Selection:**
```typescript
// Explicit provider selection in options
await aiRouter.createCompletion(messages, { provider: 'anthropic' });

// Programmatic provider selection
await aiRouter.createCompletionWithProvider('anthropic', messages, options);

// Default provider (configured preference)
await aiRouter.createCompletion(messages);
```

**Key Features:**
- **Tool Calling Support**: Anthropic provider supports streaming and tool execution for intelligent code exploration
- **Fail-Fast Design**: No fallbacks during development to surface issues immediately
- **Configuration-Based**: Provider settings loaded from environment variables and config objects
- **Type Safety**: Full TypeScript support with Zod schema validation

**Adding New Providers:**
1. Extend `AIProvider` abstract class
2. Implement `initialize()`, `isAvailable()`, and `createCompletion()` methods
3. Register provider in `AIRouter` constructor
4. Add configuration interfaces and initialization logic

#### Sandbox Manager (`src/sandbox/sandbox-manager.ts`)

The Sandbox Manager handles automatic selection and management of sandbox providers for secure MCP server execution:

**Provider Selection Logic:**
```typescript
// Priority order: Daytona (production) > Docker (dev)
private async selectBestProvider(): Promise<SandboxProvider | null> {
  const preferred = this.config.preferredProvider;

  // Try preferred provider first
  if (preferred && preferred !== 'auto') {
    const provider = this.providers.get(preferred);
    if (provider && await provider.isAvailable()) {
      return provider;
    }
  }

  // Auto-select best available
  for (const providerName of ['daytona', 'docker']) {
    const provider = this.providers.get(providerName);
    if (provider && await provider.isAvailable()) {
      return provider;
    }
  }

  return null;
}
```

**Supported Sandbox Providers:**
- **Docker Provider** (`src/sandbox/docker-provider.ts`): Local development using Docker containers with volume management
- **Daytona Provider** (`src/sandbox/daytona-provider.ts`): Production using Daytona microVMs for enhanced isolation

**MCP-Specific Analysis:**
The sandbox manager includes specialized MCP behavior analysis:
- **Network Activity Monitoring**: Detects suspicious external connections
- **File System Access Tracking**: Identifies sensitive file access patterns
- **Process Execution Monitoring**: Captures command execution for security assessment
- **MCP Protocol Analysis**: Future support for MCP-specific vulnerability detection

**Adding New Sandbox Providers:**
1. Extend `SandboxProvider` abstract class
2. Implement required methods: `initialize()`, `cleanup()`, `executeInSandbox()`, `isAvailable()`
3. Add provider-specific methods: `cloneWithGitImage()`, `scanWithOSVImage()`
4. Register provider in `SandboxManager.initializeProviders()`

### Security Analysis Pipeline

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│  Repository     │───▶│   Sandbox        │───▶│  Security Analysis  │
│  Cloning        │    │   Execution      │    │  (AI + Behavioral)  │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
         │                       │                         │
         ▼                       ▼                         ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│  OSV Dependency │    │   Behavior       │    │   Comprehensive     │
│  Scanning       │    │   Monitoring     │    │   Report Generation │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
```

## Development Setup

### Prerequisites
```bash
# Required tools
node >= 18
yarn >= 1.22
docker >= 20.x

# Verify installations
node --version
yarn --version
docker --version
```

### Installation
```bash
git clone <repository-url>
cd mcp_sec
yarn install
cp .env.example .env
# Edit .env with your API keys
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

# Daytona (optional, for production sandbox)
DAYTONA_API_ENDPOINT=https://your-instance.com/api
DAYTONA_API_KEY=your-daytona-key
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

# Usage
yarn node mcp_scan_cli.js <local_path>                    # Local analysis
yarn node mcp_scan_cli.js --repo <github_url>             # Remote analysis
yarn node mcp_scan_cli.js --repo <url> --mode static      # Static only
```

## Contributing

### Project Structure

```
src/
├── analysis/           # Analysis engines
│   ├── ai-analyzer.ts     # AI-powered security analysis
│   └── dependency-analyzer.ts # OSV vulnerability scanning
├── sandbox/           # Sandboxing infrastructure
│   ├── sandbox-manager.ts    # Provider selection & management
│   ├── docker-provider.ts    # Docker isolation
│   └── daytona-provider.ts   # Daytona microVM isolation
├── services/          # Core services
│   ├── ai-router.ts          # Multi-provider AI routing
│   └── osv-service.ts        # OSV.dev API integration
├── config/           # Configuration management
└── index.ts          # Main scanner orchestration
```

### Adding New Features

#### 1. New AI Provider
```typescript
// src/services/my-provider.ts
export class MyAIProvider extends AIProvider {
  name = 'my-provider';

  async initialize(config: MyProviderConfig): Promise<void> {
    // Provider initialization
  }

  async createCompletion(messages: AIMessage[], options: AICompletionOptions): Promise<AIResponse> {
    // Implement provider-specific completion logic
  }
}

// Register in ai-router.ts
this.providers.set('my-provider', new MyAIProvider());
```

#### 2. New Analysis Module
```typescript
// src/analysis/my-analyzer.ts
export class MyAnalyzer {
  async analyze(input: AnalysisInput): Promise<AnalysisResult> {
    // Custom analysis logic
    return {
      vulnerabilities: [...],
      suggestions: [...]
    };
  }
}

// Integrate in index.ts
private myAnalyzer = new MyAnalyzer();
```

#### 3. New Sandbox Provider
```typescript
// src/sandbox/my-provider.ts
export class MySandboxProvider extends SandboxProvider {
  name = 'my-provider';

  async executeInSandbox(command: string, args: string[], config: SandboxConfig): Promise<SandboxResult> {
    // Implement isolated execution
  }
}
```

### Code Standards

- **TypeScript**: Strict type checking enabled
- **Error Handling**: Fail-fast approach with explicit error types
- **Testing**: Unit tests for core functionality
- **Documentation**: JSDoc comments for public APIs
- **Configuration**: Zod schema validation for all configs
- **Security**: No hardcoded credentials, environment-based configuration

### Testing

```bash
# Run all tests
yarn test

# Test specific provider
yarn test --grep "AnthropicProvider"

# Integration tests with Docker
yarn test:integration
```

### Security Considerations

When contributing to this security scanner:

1. **Never expose secrets**: Use environment variables and secure credential management
2. **Validate all inputs**: Use Zod schemas for runtime validation
3. **Sandbox isolation**: Ensure all MCP server execution happens in isolated environments
4. **Fail securely**: Error handling should not expose sensitive information
5. **Audit dependencies**: Regularly scan for vulnerabilities in project dependencies

### MCP-Specific Vulnerabilities

The scanner focuses on these MCP security patterns:

- **Command Injection**: Shell execution in tool implementations
- **Authentication Bypass**: Most MCP servers lack proper authentication
- **Credential Exposure**: Hardcoded secrets in configurations
- **Tool Poisoning**: Malicious instructions in tool descriptions
- **Privilege Escalation**: Confused deputy attacks
- **Data Exfiltration**: Unauthorized resource access
- **Prompt Injection**: LLM manipulation via tool descriptions
- **Network Abuse**: Unexpected external connections

When adding new analysis capabilities, focus on these MCP-specific attack vectors.

## Architecture Decisions

### Why Multiple AI Providers?
- **Flexibility**: Different providers excel at different analysis types
- **Reliability**: Fallback options if primary provider is unavailable
- **Cost Optimization**: Choose appropriate provider based on task complexity
- **Future-Proofing**: Easy integration of new AI capabilities

### Why Pluggable Sandboxes?
- **Environment Adaptation**: Docker for development, Daytona for production
- **Security Levels**: Different isolation requirements for different deployments
- **Performance**: Optimize for local vs cloud execution environments
- **Scalability**: Support for distributed analysis in production

### Why AI-Powered Analysis?
- **Context Understanding**: AI can understand complex code patterns and relationships
- **Adaptive Detection**: Learns from new vulnerability patterns over time
- **Natural Language Output**: Human-readable security reports and recommendations
- **Tool Integration**: Can dynamically explore codebases and call analysis tools

This architecture provides a solid foundation for comprehensive MCP security analysis while remaining extensible for future security research and tooling needs.
