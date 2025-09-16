/**
 * Configuration management for MCP Security Scanner
 */

import { config } from 'dotenv';
import { z } from 'zod';

// Load environment variables
config();

// Configuration schema validation
const ConfigSchema = z.object({
  // Kindo API configuration
  KINDO_API_KEY: z.string().min(1, 'Kindo API key is required'),
  KINDO_LLM_BASE_URL: z.string().url().default('https://llm.kindo.ai/v1'),
  KINDO_MODEL: z.string().default('default'),
  
  // Sandbox configuration
  PREFERRED_SANDBOX: z.enum(['docker', 'daytona', 'auto']).default('auto'),
  DAYTONA_API_ENDPOINT: z.string().url().optional(),
  DAYTONA_API_KEY: z.string().optional(),
  
  // AI Router configuration
  AI_PROVIDER: z.enum(['external-kindo', 'internal-kindo']).default('external-kindo'),
  
  // Scanner configuration
  SCANNER_TIMEOUT: z.number().default(300000), // 5 minutes
  MAX_SOURCE_CODE_SIZE: z.number().default(50000), // 50KB
  ENABLE_NETWORK_ANALYSIS: z.boolean().default(true),
  
  // Logging and debugging
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  ENABLE_AI_DEBUG: z.boolean().default(false)
});

type Config = z.infer<typeof ConfigSchema>;

class ConfigManager {
  private _config: Config | null = null;

  get config(): Config {
    if (!this._config) {
      this._config = this.loadAndValidateConfig();
    }
    return this._config;
  }

  private loadAndValidateConfig(): Config {
    const rawConfig = {
      // Kindo configuration
      KINDO_API_KEY: process.env.KINDO_API_KEY,
      KINDO_LLM_BASE_URL: process.env.KINDO_LLM_BASE_URL,
      KINDO_MODEL: process.env.KINDO_MODEL,
      
      // Sandbox configuration  
      PREFERRED_SANDBOX: process.env.PREFERRED_SANDBOX,
      DAYTONA_API_ENDPOINT: process.env.DAYTONA_API_ENDPOINT,
      DAYTONA_API_KEY: process.env.DAYTONA_API_KEY,
      
      // AI Router configuration
      AI_PROVIDER: process.env.AI_PROVIDER,
      
      // Scanner configuration
      SCANNER_TIMEOUT: process.env.SCANNER_TIMEOUT ? parseInt(process.env.SCANNER_TIMEOUT) : undefined,
      MAX_SOURCE_CODE_SIZE: process.env.MAX_SOURCE_CODE_SIZE ? parseInt(process.env.MAX_SOURCE_CODE_SIZE) : undefined,
      ENABLE_NETWORK_ANALYSIS: process.env.ENABLE_NETWORK_ANALYSIS !== 'false',
      
      // Logging
      LOG_LEVEL: process.env.LOG_LEVEL,
      ENABLE_AI_DEBUG: process.env.ENABLE_AI_DEBUG === 'true'
    };

    try {
      return ConfigSchema.parse(rawConfig);
    } catch (error) {
      if (error instanceof z.ZodError) {
        const missingFields = error.issues.map((e: any) => e.path.join('.')).join(', ');
        throw new Error(`Configuration validation failed. Missing or invalid fields: ${missingFields}`);
      }
      throw error;
    }
  }

  // Helper methods for specific configurations
  getKindoConfig() {
    const config = this.config;
    return {
      apiKey: config.KINDO_API_KEY,
      baseUrl: config.KINDO_LLM_BASE_URL,
      model: config.KINDO_MODEL
    };
  }

  getSandboxConfig() {
    const config = this.config;
    return {
      preferredProvider: config.PREFERRED_SANDBOX,
      daytona: config.DAYTONA_API_ENDPOINT && config.DAYTONA_API_KEY ? {
        apiEndpoint: config.DAYTONA_API_ENDPOINT,
        apiKey: config.DAYTONA_API_KEY
      } : undefined
    };
  }

  getAIAnalyzerConfig() {
    const config = this.config;
    return {
      aiProvider: config.AI_PROVIDER,
      fallbackToMock: false, // No fallbacks in development
      externalKindo: {
        apiKey: config.KINDO_API_KEY,
        baseUrl: config.KINDO_LLM_BASE_URL,
        model: config.KINDO_MODEL
      }
    };
  }

  // Validation helpers
  validateKindoConnection(): boolean {
    return !!(this.config.KINDO_API_KEY && this.config.KINDO_LLM_BASE_URL);
  }

  validateDaytonaConnection(): boolean {
    return !!(this.config.DAYTONA_API_ENDPOINT && this.config.DAYTONA_API_KEY);
  }

  // Debug/logging helpers
  isDebugMode(): boolean {
    return this.config.LOG_LEVEL === 'debug' || this.config.ENABLE_AI_DEBUG;
  }

  logConfig(): void {
    const config = this.config;
    console.log('MCP Security Scanner Configuration:');
    console.log(`- AI Provider: ${config.AI_PROVIDER}`);
    console.log(`- Sandbox Provider: ${config.PREFERRED_SANDBOX}`);
    console.log(`- Kindo Model: ${config.KINDO_MODEL}`);
    console.log(`- Scanner Timeout: ${config.SCANNER_TIMEOUT}ms`);
    console.log(`- Max Code Size: ${config.MAX_SOURCE_CODE_SIZE} bytes`);
    console.log(`- Network Analysis: ${config.ENABLE_NETWORK_ANALYSIS ? 'enabled' : 'disabled'}`);
    console.log(`- Log Level: ${config.LOG_LEVEL}`);
    console.log(`- Kindo API: ${this.validateKindoConnection() ? 'configured' : 'missing'}`);
    console.log(`- Daytona API: ${this.validateDaytonaConnection() ? 'configured' : 'not configured'}`);
  }
}

// Export singleton instance
export const configManager = new ConfigManager();
export type { Config };

// Export commonly used configs
export const kindoConfig = () => configManager.getKindoConfig();
export const sandboxConfig = () => configManager.getSandboxConfig();  
export const aiAnalyzerConfig = () => configManager.getAIAnalyzerConfig();