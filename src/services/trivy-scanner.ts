/**
 * Trivy vulnerability scanner implementation
 * Uses Trivy CLI for comprehensive security scanning
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { z } from 'zod';
import { VulnerabilityScanner, ScanResult, Vulnerability, DockerImageTarget, RepositoryTarget, PackageListTarget } from './vulnerability-scanner';

const execAsync = promisify(exec);

// Trivy JSON output schemas
const TrivySeveritySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);

const TrivyVulnerabilitySchema = z.object({
  VulnerabilityID: z.string(),
  Title: z.string().optional(),
  Description: z.string().optional(),
  Severity: TrivySeveritySchema,
  CVSS: z.record(z.string(), z.object({
    V3Score: z.number().optional(),
    V3Vector: z.string().optional(),
    V2Score: z.number().optional(),
    V2Vector: z.string().optional()
  })).optional(),
  CweIDs: z.array(z.string()).optional(),
  References: z.array(z.string()).optional(),
  PublishedDate: z.string().optional(),
  LastModifiedDate: z.string().optional(),
  PkgName: z.string(),
  PkgPath: z.string().optional(),
  InstalledVersion: z.string(),
  FixedVersion: z.string().optional(),
  Status: z.string().optional(),
  Layer: z.object({
    DiffID: z.string().optional()
  }).optional()
});

const TrivyTargetSchema = z.object({
  Target: z.string(),
  Class: z.string().optional(),
  Type: z.string().optional(),
  Vulnerabilities: z.array(TrivyVulnerabilitySchema).optional()
});

const TrivyResultSchema = z.object({
  SchemaVersion: z.number(),
  ArtifactName: z.string(),
  ArtifactType: z.string(),
  Metadata: z.record(z.string(), z.unknown()).optional(),
  Results: z.array(TrivyTargetSchema)
});

type TrivyVulnerability = z.infer<typeof TrivyVulnerabilitySchema>;
type TrivyResult = z.infer<typeof TrivyResultSchema>;

export class TrivyScanner extends VulnerabilityScanner {
  readonly name = 'trivy';
  private static readonly TIMEOUT = 300000; // 5 minutes

  async scanDockerImage(target: DockerImageTarget): Promise<ScanResult> {
    const startTime = Date.now();

    try {
      let command: string;

      if (target.tarballPath) {
        // Scan from tarball
        command = `trivy image --format json --timeout 5m --input "${target.tarballPath}"`;
      } else if (target.imageId) {
        // Scan by image ID (works for untagged images)
        command = `trivy image --format json --timeout 5m "${target.imageId}"`;
      } else {
        throw new Error('Either imageId or tarballPath must be provided');
      }

      const { stdout, stderr } = await execAsync(command, {
        timeout: TrivyScanner.TIMEOUT,
        maxBuffer: 10 * 1024 * 1024 // 10MB buffer for large outputs
      });

      if (stderr && !stderr.includes('WARN')) {
        console.warn('Trivy stderr:', stderr);
      }

      const result = JSON.parse(stdout);
      const trivyResult = TrivyResultSchema.parse(result);
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
      let command: string;

      if (target.repoUrl) {
        // Scan remote repository
        command = `trivy repo --format json --timeout 5m "${target.repoUrl}"`;
      } else {
        // Scan local filesystem
        command = `trivy fs --format json --timeout 5m "${target.path}"`;
      }

      const { stdout, stderr } = await execAsync(command, {
        timeout: TrivyScanner.TIMEOUT,
        maxBuffer: 10 * 1024 * 1024
      });

      if (stderr && !stderr.includes('WARN')) {
        console.warn('Trivy stderr:', stderr);
      }

      const result = JSON.parse(stdout);
      const trivyResult = TrivyResultSchema.parse(result);
      const duration = Date.now() - startTime;

      return this.convertTrivyResult(trivyResult, duration);
    } catch (error) {
      const duration = Date.now() - startTime;
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
      const { stdout } = await execAsync('trivy version', { timeout: 10000 });
      return stdout.includes('Version:');
    } catch (error) {
      console.warn('Trivy health check failed:', error);
      return false;
    }
  }

  async getVersion(): Promise<string> {
    try {
      const { stdout } = await execAsync('trivy version', { timeout: 10000 });
      const match = stdout.match(/Version:\s*([^\n\r]+)/);
      return match ? match[1].trim() : 'Unknown';
    } catch (error) {
      return 'Unknown';
    }
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

    for (const target of trivyResult.Results) {
      if (!target.Vulnerabilities || target.Vulnerabilities.length === 0) {
        continue;
      }

      const hasVulnerabilities = target.Vulnerabilities.length > 0;
      if (hasVulnerabilities) {
        vulnerablePackageCount++;
      }

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

    return {
      scanner: 'trivy',
      totalPackagesScanned: packageCount.size,
      vulnerablePackages: vulnerablePackageCount,
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
      const score = cvssData.V3Score ?? cvssData.V2Score;
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