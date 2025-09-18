/**
 * Remote OAuth Handler using OAuth2-Proxy
 * Handles OAuth authentication for remote MCP servers through containerized OAuth2-proxy
 */

import { spawn, ChildProcess } from 'child_process';
import { createServer, Server } from 'http';
import { URL } from 'url';

export interface RemoteServerConfig {
  serverName: string;
  url: string;
  type?: string;
  headers?: Record<string, string>;
  config: any;
}

export interface OAuthProvider {
  name: string;
  provider: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  additionalArgs?: string[];
  issuerUrl?: string;
}

export interface AuthenticatedProxy {
  proxyUrl: string;
  authUrl: string;
  containerId: string;
  port: number;
  cleanup: () => Promise<void>;
}

export class RemoteOAuthHandler {
  private authenticatedProxies: AuthenticatedProxy[] = [];

  /**
   * Detect OAuth configuration from environment variables (generic approach)
   */
  private detectOAuthConfig(): OAuthProvider | null {
    // Generic OAuth2-proxy environment variable pattern
    const clientId = process.env.OAUTH2_PROXY_CLIENT_ID;
    const clientSecret = process.env.OAUTH2_PROXY_CLIENT_SECRET;
    const provider = process.env.OAUTH2_PROXY_PROVIDER || 'oidc'; // Default to OIDC

    if (!clientId || !clientSecret) {
      return null;
    }

    // Optional additional configuration
    const issuerUrl = process.env.OAUTH2_PROXY_OIDC_ISSUER_URL;
    const scopes = process.env.OAUTH2_PROXY_SCOPE;

    const additionalArgs: string[] = [];
    if (issuerUrl) {
      additionalArgs.push(`--oidc-issuer-url=${issuerUrl}`);
    }
    if (scopes) {
      additionalArgs.push(`--scope=${scopes}`);
    }

    return {
      name: 'Generic',
      provider,
      clientIdEnv: 'OAUTH2_PROXY_CLIENT_ID',
      clientSecretEnv: 'OAUTH2_PROXY_CLIENT_SECRET',
      additionalArgs
    };
  }

  /**
   * Start OAuth2-proxy container for authentication
   */
  private async startOAuthProxy(provider: OAuthProvider, remoteConfig: RemoteServerConfig): Promise<AuthenticatedProxy> {
    const port = await this.findAvailablePort();
    const containerId = `mcp-auth-${remoteConfig.serverName}-${Date.now()}`;

    console.log(`🐳 Starting OAuth2-proxy container...`);

    const dockerArgs = [
      'run', '-d',
      '--name', containerId,
      '-p', `${port}:4180`,
      '--rm'
    ];

    // Add environment variables using OAuth2-proxy standard naming
    const env = { ...process.env };
    const requiredEnvVars = [
      'OAUTH2_PROXY_CLIENT_ID',
      'OAUTH2_PROXY_CLIENT_SECRET',
      'OAUTH2_PROXY_PROVIDER'
    ];

    // Pass through OAuth2-proxy environment variables
    for (const envVar of requiredEnvVars) {
      if (env[envVar]) {
        dockerArgs.push('-e', envVar);
      }
    }

    // Optional OAuth2-proxy environment variables
    const optionalEnvVars = [
      'OAUTH2_PROXY_OIDC_ISSUER_URL',
      'OAUTH2_PROXY_SCOPE',
      'OAUTH2_PROXY_COOKIE_SECRET'
    ];

    for (const envVar of optionalEnvVars) {
      if (env[envVar]) {
        dockerArgs.push('-e', envVar);
      }
    }

    // Set required OAuth2-proxy configuration
    dockerArgs.push(
      '-e', `OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180`,
      '-e', `OAUTH2_PROXY_REDIRECT_URL=http://localhost:${port}/oauth2/callback`,
      '-e', `OAUTH2_PROXY_UPSTREAMS=${remoteConfig.url}`,
      '-e', 'OAUTH2_PROXY_COOKIE_SECURE=false', // For localhost development
      'quay.io/oauth2-proxy/oauth2-proxy:latest'
    );

    // Validation
    if (!env.OAUTH2_PROXY_CLIENT_ID || !env.OAUTH2_PROXY_CLIENT_SECRET) {
      console.warn(`⚠️  Missing required OAuth2-proxy environment variables:`);
      console.log(`   • OAUTH2_PROXY_CLIENT_ID`);
      console.log(`   • OAUTH2_PROXY_CLIENT_SECRET`);
      console.log(`   • OAUTH2_PROXY_PROVIDER (optional, defaults to 'oidc')`);
      console.log(`   Set these environment variables for OAuth authentication`);
    }

    try {
      const dockerProcess = spawn('docker', dockerArgs, {
        stdio: ['ignore', 'pipe', 'pipe'],
        env
      });

      await new Promise((resolve, reject) => {
        dockerProcess.on('close', (code) => {
          if (code === 0) resolve(void 0);
          else reject(new Error(`Docker container failed to start: exit code ${code}`));
        });

        // Wait a moment for container to start
        setTimeout(resolve, 2000);
      });

      const proxyUrl = `http://localhost:${port}`;
      const authUrl = `${proxyUrl}/oauth2/start`;

      const authenticatedProxy: AuthenticatedProxy = {
        proxyUrl,
        authUrl,
        containerId,
        port,
        cleanup: async () => {
          await this.cleanupProxy(containerId);
        }
      };

      this.authenticatedProxies.push(authenticatedProxy);
      return authenticatedProxy;

    } catch (error) {
      throw new Error(`Failed to start OAuth2-proxy: ${error}`);
    }
  }

  /**
   * Open browser for OAuth authentication
   */
  private async openBrowserForAuth(authUrl: string): Promise<void> {
    console.log(`📱 Opening browser for OAuth authentication...`);
    console.log(`🔗 Auth URL: ${authUrl}`);

    try {
      const open = require('open');
      await open(authUrl);
    } catch (error) {
      console.warn('Could not open browser automatically. Please visit the URL above.');
    }
  }

  /**
   * Wait for authentication completion by checking proxy health
   */
  private async waitForAuthentication(proxy: AuthenticatedProxy, timeout: number = 120000): Promise<void> {
    console.log(`⏳ Waiting for OAuth authentication completion...`);
    console.log(`   Complete authentication in your browser, then return here.`);

    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      try {
        // Try to access the upstream through the proxy
        const response = await fetch(`${proxy.proxyUrl}/`, {
          method: 'HEAD',
          redirect: 'manual'
        });

        // If we get a 200 or 307 (redirect to upstream), authentication succeeded
        if (response.status === 200 || response.status === 307) {
          console.log(`✅ OAuth authentication successful!`);
          return;
        }
      } catch (error) {
        // Continue waiting
      }

      await new Promise(resolve => setTimeout(resolve, 2000));
    }

    throw new Error('OAuth authentication timed out');
  }

  /**
   * Authenticate remote server and return proxy URL for MCP connection
   */
  async authenticateRemoteServer(remoteConfig: RemoteServerConfig): Promise<string> {
    const provider = this.detectOAuthConfig();

    if (!provider) {
      console.log(`⚠️  No OAuth configuration found`);
      console.log(`   Set OAUTH2_PROXY_CLIENT_ID, OAUTH2_PROXY_CLIENT_SECRET, and OAUTH2_PROXY_PROVIDER environment variables`);
      console.log(`   Attempting direct connection (may require manual authentication)`);
      return remoteConfig.url;
    }

    console.log(`🔐 OAuth authentication required for server: ${remoteConfig.serverName}`);

    try {
      // Start OAuth2-proxy container
      const proxy = await this.startOAuthProxy(provider, remoteConfig);

      // Open browser for authentication
      await this.openBrowserForAuth(proxy.authUrl);

      // Wait for user to complete authentication
      await this.waitForAuthentication(proxy);

      console.log(`🤝 Authenticated proxy ready at: ${proxy.proxyUrl}`);
      return proxy.proxyUrl;

    } catch (error) {
      throw new Error(`OAuth authentication failed: ${error}`);
    }
  }

  /**
   * Find an available port for OAuth2-proxy
   */
  private async findAvailablePort(startPort: number = 4180): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = createServer();

      server.listen(startPort, () => {
        const port = (server.address() as any)?.port;
        server.close(() => resolve(port));
      });

      server.on('error', () => {
        resolve(this.findAvailablePort(startPort + 1));
      });
    });
  }

  /**
   * Cleanup OAuth2-proxy container
   */
  private async cleanupProxy(containerId: string): Promise<void> {
    try {
      const killProcess = spawn('docker', ['kill', containerId], { stdio: 'ignore' });
      await new Promise(resolve => killProcess.on('close', resolve));
      console.log(`🧹 Cleaned up OAuth proxy: ${containerId}`);
    } catch (error) {
      console.warn(`Warning: Failed to cleanup proxy ${containerId}:`, error);
    }
  }

  /**
   * Cleanup all active OAuth proxies
   */
  async cleanup(): Promise<void> {
    console.log(`🧹 Cleaning up ${this.authenticatedProxies.length} OAuth proxies...`);

    await Promise.all(
      this.authenticatedProxies.map(proxy => proxy.cleanup())
    );

    this.authenticatedProxies = [];
  }
}