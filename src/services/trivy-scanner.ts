/**
 * Trivy vulnerability scanner implementation
 * Uses containerized Trivy (aquasec/trivy) for comprehensive security scanning in sandbox
 */

import { VulnerabilityScanner, ScanResult, Vulnerability, DockerImageTarget, RepositoryTarget, PackageListTarget } from './vulnerability-scanner';
import { SandboxProvider } from '../sandbox/sandbox-provider';

// Trivy JSON output types (no validation, trust Trivy's output)
interface TrivyVulnerability {
  VulnerabilityID: string;
  Title?: string;
  Description?: string;
  Severity: string;
  CVSS?: Record<string, {
    V3Score?: number;
    V3Vector?: string;
    V2Score?: number;
    V2Vector?: string;
  }>;
  CweIDs?: string[];
  References?: string[];
  PublishedDate?: string;
  LastModifiedDate?: string;
  PkgName: string;
  PkgPath?: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Status?: string;
  Layer?: {
    DiffID?: string;
  };
}

interface TrivyMisconfiguration {
  Type?: string;
  ID: string;
  Title?: string;
  Description?: string;
  Severity: string;
}

interface TrivySecret {
  RuleID: string;
  Category: string;
  Severity: string;
  Title: string;
  Match: string;
}

interface TrivyTarget {
  Target: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: TrivyMisconfiguration[];
  Secrets?: TrivySecret[];
}

interface TrivyResult {
  SchemaVersion?: number;
  ArtifactName?: string;
  ArtifactType?: string;
  Metadata?: Record<string, unknown>;
  Results?: TrivyTarget[];
}

export class TrivyScanner extends VulnerabilityScanner {
  readonly name = 'trivy';
  private static readonly TIMEOUT = 300000; // 5 minutes
  private sandboxProvider: SandboxProvider;

  constructor(sandboxProvider: SandboxProvider) {
    super();
    this.sandboxProvider = sandboxProvider;
  }

  async scanDockerImage(target: DockerImageTarget): Promise<ScanResult> {
    const startTime = Date.now();

    try {
      let dockerCmd: string;

      if (target.tarballPath) {
        // Scan from tarball - mount the tarball into the container
        dockerCmd = [
          'docker run --rm',
          `-v ${target.tarballPath}:/tmp/image.tar`,
          'aquasec/trivy:latest',
          'image',
          '--format json',
          '--timeout 5m',
          '--input /tmp/image.tar'
        ].join(' ');
      } else if (target.imageId) {
        // Scan by image ID - need to share Docker socket
        dockerCmd = [
          'docker run --rm',
          '-v /var/run/docker.sock:/var/run/docker.sock',
          'aquasec/trivy:latest',
          'image',
          '--format json',
          '--timeout 5m',
          target.imageId
        ].join(' ');
      } else {
        throw new Error('Either imageId or tarballPath must be provided');
      }

      const { stdout, stderr } = await this.runDockerCommand(dockerCmd);

      if (stderr && !stderr.includes('INFO') && !stderr.includes('WARN')) {
        console.warn('Trivy stderr:', stderr);
      }

      const trivyResult = JSON.parse(stdout) as TrivyResult;
      const duration = Date.now() - startTime;

      return this.convertTrivyResult(trivyResult, duration);
    } catch (error) {
      const duration = Date.now() - startTime;
      return this.createErrorResult(
        `Docker image scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        duration
      );
    }
  }

  async scanRepository(target: RepositoryTarget): Promise<ScanResult> {
    const startTime = Date.now();

    try {
      let volumeName: string;

      if (target.repoUrl) {
        // Clone repository to sandbox first
        const cloneResult = await this.sandboxProvider.cloneRepository(target.repoUrl, '/tmp/repo');
        if (!cloneResult.success) {
          throw new Error(`Failed to clone repository: ${cloneResult.error}`);
        }
        volumeName = (this.sandboxProvider as any)._currentVolume;
      } else {
        // Assume repository is already mounted in sandbox volume
        volumeName = (this.sandboxProvider as any)._currentVolume;
      }

      if (!volumeName) {
        throw new Error('No sandbox volume available for Trivy scan');
      }

      // Run Trivy in container with mounted volume
      const { stdout, stderr } = await this.runTrivyInSandbox(volumeName, 'fs', '/src');

      if (stderr && !stderr.includes('INFO') && !stderr.includes('WARN')) {
        console.warn('Trivy stderr:', stderr);
      }

      const trivyResult = JSON.parse(stdout) as TrivyResult;
      const duration = Date.now() - startTime;

      return this.convertTrivyResult(trivyResult, duration);
    } catch (error) {
      const duration = Date.now() - startTime;
      console.error('🚨 TRIVY SCANNER FAILURE:');
      console.error('   Error:', error instanceof Error ? error.message : String(error));
      console.error('   Stack:', error instanceof Error ? error.stack : 'No stack trace');
      return this.createErrorResult(
        `Repository scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        duration
      );
    }
  }

  async scanPackages(target: PackageListTarget): Promise<ScanResult> {
    const startTime = Date.now();

    try {
      // Trivy doesn't support direct package list scanning
      // This would require generating a temporary manifest file
      throw new Error('Direct package list scanning not supported by Trivy. Use repository or image scanning.');
    } catch (error) {
      const duration = Date.now() - startTime;
      return this.createErrorResult(
        `Package scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        duration
      );
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      const { stdout } = await this.runTrivyInSandbox('', 'version', '');
      return stdout.includes('Version:');
    } catch (error) {
      console.warn('Trivy health check failed:', error);
      return false;
    }
  }

  async getVersion(): Promise<string> {
    try {
      const { stdout } = await this.runTrivyInSandbox('', 'version', '');
      const match = stdout.match(/Version:\s*([^\n\r]+)/);
      return match ? match[1].trim() : 'aquasec/trivy container';
    } catch (error) {
      return 'aquasec/trivy container';
    }
  }

  private async runTrivyInSandbox(volumeName: string, command: string, target: string): Promise<{ stdout: string; stderr: string }> {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);

    let dockerCmd: string;

    if (command === 'version') {
      // Version check doesn't need volumes
      dockerCmd = 'docker run --rm aquasec/trivy:latest version';
    } else {
      // Regular scans need volume mounting - enable misconfig scanner for IaC detection
      dockerCmd = [
        'docker run --rm',
        `-v ${volumeName}:/src`,
        'aquasec/trivy:latest',
        command,
        '--scanners', 'vuln,secret,misconfig',
        '--format json',
        '--timeout 5m',
        target
      ].join(' ');
    }

    console.log('🔍 Executing Trivy command:', dockerCmd);


    try {
      const { stdout, stderr } = await execAsync(dockerCmd, {
        timeout: TrivyScanner.TIMEOUT,
        maxBuffer: 10 * 1024 * 1024
      });

      console.log('✅ Trivy command completed successfully');
      if (stderr) {
        console.log('Trivy stderr:', stderr);
      }

      return { stdout, stderr };
    } catch (error) {
      console.error('❌ Trivy Docker command failed:');
      console.error('   Command:', dockerCmd);
      console.error('   Error:', error);
      throw error;
    }
  }

  private async runDockerCommand(dockerCmd: string): Promise<{ stdout: string; stderr: string }> {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);

    const { stdout, stderr } = await execAsync(dockerCmd, {
      timeout: TrivyScanner.TIMEOUT,
      maxBuffer: 10 * 1024 * 1024
    });

    return { stdout, stderr };
  }

  private convertTrivyResult(trivyResult: TrivyResult, duration: number): ScanResult {
    const vulnerabilities: Vulnerability[] = [];
    const severityBreakdown = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0
    };

    const packageCount = new Set<string>();
    let vulnerablePackageCount = 0;
    let hasAnyFindings = false;

    for (const target of trivyResult.Results || []) {
      // Process package vulnerabilities
      if (target.Vulnerabilities && target.Vulnerabilities.length > 0) {
        hasAnyFindings = true;
        vulnerablePackageCount++;

        for (const vuln of target.Vulnerabilities) {
          packageCount.add(`${vuln.PkgName}@${vuln.InstalledVersion}`);

          const severity = this.mapTrivySeverity(vuln.Severity);
          const cvssScore = this.extractCVSSScore(vuln);
          const ecosystem = this.detectEcosystem(target.Target, vuln.PkgPath);

          const vulnerability: Vulnerability = {
            id: vuln.VulnerabilityID,
            title: vuln.Title || vuln.VulnerabilityID,
            description: vuln.Description || `${vuln.VulnerabilityID} in ${vuln.PkgName}`,
            severity,
            cvssScore,
            cveIds: vuln.VulnerabilityID.startsWith('CVE-') ? [vuln.VulnerabilityID] : [],
            packageName: vuln.PkgName,
            packageVersion: vuln.InstalledVersion,
            ecosystem,
            fixedVersion: vuln.FixedVersion,
            references: vuln.References,
            publishedDate: vuln.PublishedDate,
            modifiedDate: vuln.LastModifiedDate,
            source: 'trivy'
          };

          vulnerabilities.push(vulnerability);
          severityBreakdown[severity]++;
        }
      }

      // Process misconfigurations (IaC vulnerabilities)
      if (target.Misconfigurations && target.Misconfigurations.length > 0) {
        hasAnyFindings = true;

        for (const misconfig of target.Misconfigurations) {
          const severity = this.mapTrivySeverity(misconfig.Severity);

          const vulnerability: Vulnerability = {
            id: misconfig.ID,
            title: misconfig.Title || misconfig.ID,
            description: misconfig.Description || `Configuration issue: ${misconfig.ID}`,
            severity,
            packageName: target.Target,
            packageVersion: 'config',
            ecosystem: 'infrastructure',
            source: 'trivy'
          };

          vulnerabilities.push(vulnerability);
          severityBreakdown[severity]++;
        }
      }

      // Process secrets
      if (target.Secrets && target.Secrets.length > 0) {
        hasAnyFindings = true;

        for (const secret of target.Secrets) {
          const severity = this.mapTrivySeverity(secret.Severity);

          const vulnerability: Vulnerability = {
            id: secret.RuleID,
            title: secret.Title,
            description: `Secret detected: ${secret.Category} - ${secret.Match}`,
            severity,
            packageName: target.Target,
            packageVersion: 'secret',
            ecosystem: 'secret',
            source: 'trivy'
          };

          vulnerabilities.push(vulnerability);
          severityBreakdown[severity]++;
        }
      }
    }

    return {
      scanner: 'trivy',
      totalPackagesScanned: packageCount.size,
      vulnerablePackages: hasAnyFindings ? vulnerablePackageCount : 0,
      totalVulnerabilities: vulnerabilities.length,
      severityBreakdown,
      vulnerabilities,
      scanDuration: duration,
      success: true
    };
  }

  private mapTrivySeverity(trivySeverity: string): 'critical' | 'high' | 'medium' | 'low' | 'unknown' {
    switch (trivySeverity.toUpperCase()) {
      case 'CRITICAL':
        return 'critical';
      case 'HIGH':
        return 'high';
      case 'MEDIUM':
        return 'medium';
      case 'LOW':
        return 'low';
      default:
        return 'unknown';
    }
  }

  private extractCVSSScore(vuln: TrivyVulnerability): number | undefined {
    if (!vuln.CVSS) return undefined;

    // Look for CVSS scores across all CVE entries
    let highestScore: number | undefined;

    for (const [, cvssData] of Object.entries(vuln.CVSS)) {
      const score = (cvssData as any).V3Score ?? (cvssData as any).V2Score;
      if (score !== undefined && (highestScore === undefined || score > highestScore)) {
        highestScore = score;
      }
    }

    return highestScore;
  }

  private detectEcosystem(target: string, pkgPath?: string): string {
    // Try to detect ecosystem from target name or package path
    if (target.includes('package-lock.json') || target.includes('node_modules')) {
      return 'npm';
    }
    if (target.includes('requirements.txt') || target.includes('Pipfile') || target.includes('pyproject.toml')) {
      return 'pypi';
    }
    if (target.includes('go.mod') || target.includes('go.sum')) {
      return 'go';
    }
    if (target.includes('Cargo.toml') || target.includes('Cargo.lock')) {
      return 'cargo';
    }
    if (target.includes('composer.json') || target.includes('composer.lock')) {
      return 'composer';
    }
    if (target.includes('Gemfile') || target.includes('Gemfile.lock')) {
      return 'gem';
    }
    if (target.includes('pom.xml') || target.includes('build.gradle')) {
      return 'maven';
    }

    // Fallback based on package path
    if (pkgPath) {
      if (pkgPath.includes('node_modules')) return 'npm';
      if (pkgPath.includes('site-packages')) return 'pypi';
    }

    return 'unknown';
  }
}