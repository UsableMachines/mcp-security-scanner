/**
 * MCP Configuration Schema using Zod
 * Defines the structure of MCP server configurations (claude_desktop_config.json)
 */

import { z } from 'zod';

// Schema for individual MCP server configuration
export const MCPServerConfigSchema = z.object({
  command: z.string(),
  args: z.array(z.string()).optional(),
  env: z.record(z.string(), z.string()).optional(),
  // Future: URL-based configurations
  url: z.string().optional(),
  headers: z.record(z.string(), z.string()).optional()
});

// Schema for the complete MCP configuration file
export const MCPConfigurationSchema = z.object({
  mcpServers: z.record(z.string(), MCPServerConfigSchema),
  // Allow additional properties for extensibility
}).passthrough();

// Type exports
export type MCPServerConfig = z.infer<typeof MCPServerConfigSchema>;
export type MCPConfiguration = z.infer<typeof MCPConfigurationSchema>;

/**
 * Docker Command Parser
 * Properly extracts Docker image name from command arguments
 */
export class DockerCommandParser {
  private static FLAGS_WITH_VALUES = [
    '-v', '--volume',
    '-e', '--env', '--env-file',
    '-p', '--publish', '--expose',
    '--name', '--hostname',
    '--network', '--net',
    '--workdir', '-w',
    '--user', '-u',
    '--label', '-l',
    '--mount',
    '--restart',
    '--log-driver', '--log-opt',
    '--device',
    '--cap-add', '--cap-drop',
    '--security-opt',
    '--ulimit',
    '--group-add',
    '--pid',
    '--ipc',
    '--uts',
    '--cgroupns',
    '--platform'
  ];

  /**
   * Extract Docker image name from command arguments
   */
  static extractImageName(args: string[]): string | null {
    // Find the 'run' command position
    const runIndex = args.findIndex(arg => arg === 'run');
    if (runIndex === -1) {
      // Not a docker run command, check if first arg is image
      return args.length > 0 && !args[0].startsWith('-') ? args[0] : null;
    }

    // Parse arguments after 'run' to find the image name
    for (let i = runIndex + 1; i < args.length; i++) {
      const arg = args[i];

      // Skip flags and their values
      if (arg.startsWith('-')) {
        // Handle combined short flags like -it
        if (arg.startsWith('-') && !arg.startsWith('--') && arg.length > 2) {
          // This is a combined short flag like -it, -rm, etc.
          continue;
        }

        // Check if this flag takes a value
        if (this.FLAGS_WITH_VALUES.includes(arg)) {
          i++; // Skip the next argument (the value)
          continue;
        }

        // Check for flags with inline values like --env=VAR=value
        if (arg.includes('=')) {
          continue;
        }

        // Otherwise, this is a standalone flag
        continue;
      }

      // This is the first non-flag argument, which should be the image name
      return arg;
    }

    return null;
  }

  /**
   * Extract all arguments that come after the Docker image (command to run in container)
   */
  static extractContainerCommand(args: string[]): string[] {
    const imageName = this.extractImageName(args);
    if (!imageName) return [];

    const imageIndex = args.findIndex(arg => arg === imageName);
    if (imageIndex === -1) return [];

    // Return all arguments after the image name
    return args.slice(imageIndex + 1);
  }

  /**
   * Parse Docker run arguments into structured format
   */
  static parseDockerRun(args: string[]): {
    image: string | null;
    containerCommand: string[];
    flags: Record<string, string | boolean | string[]>;
    volumes: string[];
    envVars: string[];
    ports: string[];
    isPrivileged: boolean;
    networkMode: string | null;
  } {
    const result = {
      image: this.extractImageName(args),
      containerCommand: this.extractContainerCommand(args),
      flags: {} as Record<string, string | boolean | string[]>,
      volumes: [] as string[],
      envVars: [] as string[],
      ports: [] as string[],
      isPrivileged: false,
      networkMode: null as string | null
    };

    // Parse flags for detailed analysis
    const runIndex = args.findIndex(arg => arg === 'run');
    if (runIndex === -1) return result;

    for (let i = runIndex + 1; i < args.length; i++) {
      const arg = args[i];

      if (!arg.startsWith('-')) {
        // Reached the image name, stop parsing flags
        break;
      }

      // Handle specific flags
      if (arg === '--privileged') {
        result.isPrivileged = true;
        result.flags['privileged'] = true;
      } else if (arg === '-v' || arg === '--volume') {
        if (i + 1 < args.length) {
          result.volumes.push(args[++i]);
          result.flags['volume'] = result.volumes;
        }
      } else if (arg === '-e' || arg === '--env') {
        if (i + 1 < args.length) {
          result.envVars.push(args[++i]);
          result.flags['env'] = result.envVars;
        }
      } else if (arg === '-p' || arg === '--publish') {
        if (i + 1 < args.length) {
          result.ports.push(args[++i]);
          result.flags['publish'] = result.ports;
        }
      } else if (arg === '--network' || arg === '--net') {
        if (i + 1 < args.length) {
          result.networkMode = args[++i];
          result.flags['network'] = result.networkMode;
        }
      } else if (arg.includes('=')) {
        // Handle flags with inline values
        const [key, value] = arg.split('=', 2);
        result.flags[key.replace(/^-+/, '')] = value;
      } else {
        // Other flags
        result.flags[arg.replace(/^-+/, '')] = true;
      }
    }

    return result;
  }
}

/**
 * Validate and parse MCP configuration with proper error handling
 */
export function parseAndValidateMCPConfig(input: any): MCPConfiguration {
  try {
    return MCPConfigurationSchema.parse(input);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const issues = error.issues.map(issue =>
        `${issue.path.join('.')}: ${issue.message}`
      );
      throw new Error(`Invalid MCP configuration:\n${issues.join('\n')}`);
    }
    throw error;
  }
}