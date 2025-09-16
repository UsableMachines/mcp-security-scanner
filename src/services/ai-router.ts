/**
 * Abstracted AI service router for seamless switching between external API and internal platform
 */
import { generateText } from 'ai';
import { createAnthropic } from '@ai-sdk/anthropic';

export interface AIMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface AITool {
  name: string;
  description: string;
  parameters: Record<string, any>; // JSON Schema
  handler?: (params: any) => Promise<any>; // Optional handler for execution
}

export interface AICompletionOptions {
  maxTokens?: number;
  temperature?: number;
  stream?: boolean;
  model?: string;
  tools?: AITool[];
  toolChoice?: 'auto' | 'none' | { type: 'tool'; name: string };
  provider?: 'kindo' | 'anthropic'; // Explicit provider selection
}

export interface AIToolCall {
  id: string;
  name: string;
  arguments: Record<string, any>;
  result?: any; // Result after execution
}

export interface AIResponse {
  content: string;
  usage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  model?: string;
  toolCalls?: AIToolCall[];
  finishReason?: 'stop' | 'length' | 'tool_calls' | 'content_filter';
}

export abstract class AIProvider {
  abstract name: string;
  
  abstract initialize(config: any): Promise<void>;
  abstract isAvailable(): Promise<boolean>;
  abstract createCompletion(
    messages: AIMessage[], 
    options?: AICompletionOptions
  ): Promise<AIResponse>;
  
  async cleanup?(): Promise<void> {
    // Default implementation - providers can override if needed
  }
}

/**
 * External Kindo API provider for standalone deployments
 */
export class ExternalKindoProvider extends AIProvider {
  name = 'external-kindo';
  private config: {
    apiKey: string;
    baseUrl: string;
    model: string;
  };

  constructor() {
    super();
    this.config = {
      apiKey: '',
      baseUrl: 'https://llm.kindo.ai/v1',
      model: 'default'
    };
  }

  async initialize(config: {
    apiKey: string;
    baseUrl?: string;
    model?: string;
  }): Promise<void> {
    this.config = {
      ...this.config,
      ...config
    };

    if (!this.config.apiKey) {
      throw new Error('Kindo API key is required for external provider');
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      // Test API connectivity with a minimal chat completion request
      const response = await fetch(`${this.config.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'api-key': this.config.apiKey,
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          model: this.config.model,
          messages: [{ role: 'user', content: 'test' }],
          max_tokens: 1
        })
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  async createCompletion(
    messages: AIMessage[], 
    options: AICompletionOptions = {}
  ): Promise<AIResponse> {
    const response = await fetch(`${this.config.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'api-key': this.config.apiKey,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        model: options.model || this.config.model,
        messages,
        max_tokens: options.maxTokens || 4000,
        temperature: options.temperature || 0.2,
        stream: options.stream || false
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Kindo API error (${response.status}): ${error}`);
    }

    const data = await response.json();
    
    return {
      content: data.choices[0].message.content,
      usage: data.usage ? {
        promptTokens: data.usage.prompt_tokens || 0,
        completionTokens: data.usage.completion_tokens || 0,
        totalTokens: data.usage.total_tokens || 0
      } : undefined,
      model: data.model,
      finishReason: data.choices[0].finish_reason
    };
  }
}

/**
 * Anthropic provider using AI SDK for streaming and tool calling support
 */
export class AnthropicProvider extends AIProvider {
  name = 'anthropic';
  private anthropic: any;

  async initialize(config: { apiKey?: string } = {}): Promise<void> {
    // Use provided API key or fall back to environment variable
    const apiKey = config.apiKey || process.env?.ANTHROPIC_API_KEY || '';

    if (!apiKey) {
      throw new Error('Anthropic API key is required (ANTHROPIC_API_KEY environment variable or config)');
    }

    // Create Anthropic provider with API key
    this.anthropic = createAnthropic({
      apiKey: apiKey
    });
  }

  async isAvailable(): Promise<boolean> {
    try {
      // Test API connectivity with a minimal request using Sonnet 4
      const { text } = await generateText({
        model: this.anthropic('claude-sonnet-4-20250514'),
        prompt: 'test'
      });
      return !!text;
    } catch {
      return false;
    }
  }

  async createCompletion(
    messages: AIMessage[],
    options: AICompletionOptions = {}
  ): Promise<AIResponse> {
    const result = await generateText({
      model: this.anthropic(options.model || 'claude-sonnet-4-20250514'),
      messages,
      temperature: options.temperature || 0.6
    });

    return {
      content: result.text,
      usage: result.usage ? {
        promptTokens: (result.usage as any).promptTokens || 0,
        completionTokens: (result.usage as any).completionTokens || 0,
        totalTokens: result.usage.totalTokens || 0
      } : undefined,
      finishReason: result.finishReason === 'stop' ? 'stop' :
                    result.finishReason === 'length' ? 'length' :
                    result.finishReason === 'tool-calls' ? 'tool_calls' :
                    result.finishReason === 'content-filter' ? 'content_filter' : 'stop'
    };
  }
}

/**
 * Internal Kindo platform provider for integrated deployments
 */
export class InternalKindoProvider extends AIProvider {
  name = 'internal-kindo';
  private platformService: any; // Will be injected by platform

  async initialize(config: {
    platformService?: any;
    defaultModel?: string;
  }): Promise<void> {
    this.platformService = config.platformService;
    
    if (!this.platformService) {
      throw new Error('Platform service is required for internal provider');
    }
  }

  async isAvailable(): Promise<boolean> {
    return this.platformService && typeof this.platformService.createCompletion === 'function';
  }

  async createCompletion(
    messages: AIMessage[], 
    options: AICompletionOptions = {}
  ): Promise<AIResponse> {
    // Direct internal platform call - no HTTP overhead
    const result = await this.platformService.createCompletion({
      messages,
      maxTokens: options.maxTokens || 4000,
      temperature: options.temperature || 0.6,
      model: options.model || 'default'
    });

    return {
      content: result.content,
      usage: result.usage,
      model: result.model
    };
  }
}


/**
 * AI Router - automatically selects and manages AI providers
 */
export class AIRouter {
  private providers: Map<string, AIProvider> = new Map();
  private activeProvider: AIProvider | null = null;
  private config: {
    preferredProvider?: 'external-kindo' | 'internal-kindo' | 'anthropic';
  };

  constructor(config: {
    preferredProvider?: 'external-kindo' | 'internal-kindo' | 'anthropic';
  } = {}) {
    this.config = {
      preferredProvider: 'anthropic',
      ...config
    };

    // Register available providers
    this.providers.set('external-kindo', new ExternalKindoProvider());
    this.providers.set('internal-kindo', new InternalKindoProvider());
    this.providers.set('anthropic', new AnthropicProvider());
  }

  async initialize(providerConfigs: {
    'external-kindo'?: { apiKey: string; baseUrl?: string; model?: string };
    'internal-kindo'?: { platformService?: any; defaultModel?: string };
    'anthropic'?: { apiKey?: string };
  }): Promise<void> {
    // Initialize all configured providers
    for (const [providerName, config] of Object.entries(providerConfigs)) {
      const provider = this.providers.get(providerName);
      if (provider && config) {
        try {
          await provider.initialize(config);
        } catch (error) {
          console.warn(`Failed to initialize ${providerName} provider:`, error);
        }
      }
    }

    // Select active provider
    this.activeProvider = await this.selectBestProvider();
    
    if (!this.activeProvider) {
      throw new Error('No AI providers available');
    }

    console.log(`AI Router initialized with provider: ${this.activeProvider.name}`);
  }

  async createCompletion(
    messages: AIMessage[],
    options: AICompletionOptions = {}
  ): Promise<AIResponse> {
    // Use explicit provider if specified in options
    if (options.provider) {
      return await this.createCompletionWithProvider(options.provider, messages, options);
    }

    if (!this.activeProvider) {
      throw new Error('AI Router not initialized');
    }

    try {
      return await this.activeProvider.createCompletion(messages, options);
    } catch (error) {
      console.error(`AI completion failed with ${this.activeProvider.name}:`, error);
      throw error; // Fail fast - no fallbacks
    }
  }

  /**
   * Create completion using a specific provider (programmatic provider selection)
   */
  async createCompletionWithProvider(
    providerName: 'kindo' | 'anthropic',
    messages: AIMessage[],
    options: Omit<AICompletionOptions, 'provider'> = {}
  ): Promise<AIResponse> {
    const provider = this.providers.get(providerName === 'kindo' ? 'external-kindo' : providerName);

    if (!provider) {
      throw new Error(`Provider '${providerName}' not found`);
    }

    if (!(await provider.isAvailable())) {
      throw new Error(`Provider '${providerName}' not available`);
    }

    try {
      return await provider.createCompletion(messages, options);
    } catch (error) {
      console.error(`AI completion failed with ${providerName}:`, error);
      throw error;
    }
  }

  getCurrentProvider(): string | null {
    return this.activeProvider?.name || null;
  }

  async switchProvider(providerName: string): Promise<void> {
    const provider = this.providers.get(providerName);
    if (!provider) {
      throw new Error(`Provider '${providerName}' not found`);
    }

    if (!(await provider.isAvailable())) {
      throw new Error(`Provider '${providerName}' not available`);
    }

    this.activeProvider = provider;
    console.log(`Switched to AI provider: ${providerName}`);
  }

  async cleanup(): Promise<void> {
    for (const provider of this.providers.values()) {
      if (provider.cleanup) {
        await provider.cleanup();
      }
    }
  }

  private async selectBestProvider(): Promise<AIProvider | null> {
    const preferred = this.config.preferredProvider;

    // Use specific provider - fail if not available
    if (preferred && this.providers.has(preferred)) {
      const provider = this.providers.get(preferred)!;
      if (await provider.isAvailable()) {
        return provider;
      } else {
        throw new Error(`Required provider '${preferred}' is not available`);
      }
    }

    // Fallback selection: internal-kindo > external-kindo
    const providerOrder = ['internal-kindo', 'external-kindo'];
    
    for (const providerName of providerOrder) {
      const provider = this.providers.get(providerName);
      if (provider && await provider.isAvailable()) {
        return provider;
      }
    }

    throw new Error('No AI providers available');
  }

  // Utility methods for common patterns
  async analyzeSecurityWithStructuredOutput(
    analysisData: string,
    schema: any
  ): Promise<any> {
    const systemPrompt = `You are a cybersecurity expert. Analyze the provided data and return ONLY valid JSON matching the required schema. No additional text.`;
    
    const response = await this.createCompletion([
      { role: 'system', content: systemPrompt },
      { role: 'user', content: `${analysisData}\n\nReturn JSON matching schema: ${JSON.stringify(schema)}` }
    ], {
      temperature: 0.6,
      maxTokens: 6000
    });

    try {
      const cleanResponse = response.content.replace(/```json\n?/, '').replace(/```\n?$/, '').trim();
      return JSON.parse(cleanResponse);
    } catch (error) {
      throw new Error(`Failed to parse structured response: ${error}`);
    }
  }

  async generateReport(data: any, reportType: string = 'security'): Promise<string> {
    const prompt = `Generate a comprehensive ${reportType} report for the following analysis data:

${JSON.stringify(data, null, 2)}

Create a professional markdown report suitable for technical review.`;

    const response = await this.createCompletion([
      { role: 'user', content: prompt }
    ], {
      temperature: 0.6,
      maxTokens: 8000
    });

    return response.content;
  }
}