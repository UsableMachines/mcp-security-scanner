/**
 * OSV.dev vulnerability scanner implementation
 * Refactored to implement the VulnerabilityScanner interface
 */

import { VulnerabilityScanner, ScanResult, Vulnerability, DockerImageTarget, RepositoryTarget, PackageListTarget } from './vulnerability-scanner';
import { OSVService, OSVVulnerability } from './osv-service';

export class OSVScanner extends VulnerabilityScanner {
  readonly name = 'osv';
  private osvService: OSVService;

  constructor() {
    super();
    this.osvService = new OSVService();
  }

  async scanDockerImage(target: DockerImageTarget): Promise<ScanResult> {
    const startTime = Date.now();

    try {
      // Note: Current OSV limitation - can't scan Docker images directly
      // This would require package extraction from the image first
      throw new Error('OSV scanner cannot directly scan Docker images. Use package list extraction first.');
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
      // Note: OSV service doesn't have repository scanning - would need package file parsing
      throw new Error('Repository scanning not implemented for OSV scanner. Use package list extraction first.');
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
      if (target.packages.length === 0) {
        return this.createSuccessResult(new Map(), Date.now() - startTime);
      }

      const scanResults = await this.osvService.scanPackageBatch(target.packages);
      const duration = Date.now() - startTime;

      return this.createSuccessResult(scanResults, duration);
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
      // Test with a simple known package
      const testPackages = [{ name: 'lodash', version: '4.17.20', ecosystem: 'npm' }];
      const result = await this.osvService.scanPackageBatch(testPackages);
      return result.size > 0;
    } catch (error) {
      console.warn('OSV health check failed:', error);
      return false;
    }
  }

  async getVersion(): Promise<string> {
    // OSV.dev doesn't provide version info via API
    return 'OSV.dev API v1';
  }

  private createSuccessResult(scanResults: Map<string, OSVVulnerability[]>, duration: number): ScanResult {
    const vulnerabilities: Vulnerability[] = [];
    const severityBreakdown = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0
    };

    for (const [packageVersion, vulns] of scanResults) {
      const [packageName, version] = packageVersion.split('@');

      for (const vuln of vulns) {
        const severity = this.mapOSVSeverity(vuln);
        const cvssScore = this.extractCVSSScore(vuln);

        const vulnerability: Vulnerability = {
          id: vuln.id,
          title: vuln.summary,
          description: vuln.details,
          severity,
          cvssScore,
          cveIds: vuln.aliases?.filter(alias => alias.startsWith('CVE-')),
          packageName,
          packageVersion: version,
          ecosystem: this.extractEcosystem(vuln),
          fixedVersion: this.extractFixedVersion(vuln),
          references: vuln.references?.map(ref => ref.url),
          publishedDate: vuln.published,
          modifiedDate: vuln.modified,
          source: 'osv'
        };

        vulnerabilities.push(vulnerability);
        severityBreakdown[severity]++;
      }
    }

    return {
      scanner: 'osv',
      totalPackagesScanned: scanResults.size,
      vulnerablePackages: Array.from(scanResults.values()).filter(vulns => vulns.length > 0).length,
      totalVulnerabilities: vulnerabilities.length,
      severityBreakdown,
      vulnerabilities,
      scanDuration: duration,
      success: true
    };
  }

  private mapOSVSeverity(vulnerability: OSVVulnerability): 'critical' | 'high' | 'medium' | 'low' | 'unknown' {
    // Use the existing OSV service severity mapping logic
    let highestScore = this.getHighestCVSSScore(vulnerability.severity);

    if (highestScore === null) {
      for (const affected of vulnerability.affected) {
        const score = this.getHighestCVSSScore(affected.severity);
        if (score !== null && (highestScore === null || score > highestScore)) {
          highestScore = score;
        }
      }
    }

    if (highestScore === null) return 'unknown';
    if (highestScore >= 9.0) return 'critical';
    if (highestScore >= 7.0) return 'high';
    if (highestScore >= 4.0) return 'medium';
    if (highestScore > 0) return 'low';

    return 'unknown';
  }

  private extractCVSSScore(vulnerability: OSVVulnerability): number | undefined {
    let score = this.getHighestCVSSScore(vulnerability.severity);

    if (score === null) {
      for (const affected of vulnerability.affected) {
        const affectedScore = this.getHighestCVSSScore(affected.severity);
        if (affectedScore !== null && (score === null || affectedScore > score)) {
          score = affectedScore;
        }
      }
    }

    return score ?? undefined;
  }

  private getHighestCVSSScore(severityEntries?: Array<{ type: string; score: string }>): number | null {
    if (!severityEntries || severityEntries.length === 0) {
      return null;
    }

    const priorities = ['CVSS_V3', 'CVSS_V4', 'CVSS_V2'];
    let highestScore = null;

    for (const priority of priorities) {
      const severity = severityEntries.find(s => s.type === priority);
      if (severity) {
        const score = parseFloat(severity.score);
        if (!isNaN(score) && (highestScore === null || score > highestScore)) {
          highestScore = score;
        }
      }
    }

    return highestScore;
  }

  private extractEcosystem(vulnerability: OSVVulnerability): string {
    // Try to get ecosystem from affected packages
    const firstAffected = vulnerability.affected[0];
    return firstAffected?.package.ecosystem || 'unknown';
  }

  private extractFixedVersion(vulnerability: OSVVulnerability): string | undefined {
    // Extract fixed version from ranges
    for (const affected of vulnerability.affected) {
      if (affected.ranges) {
        for (const range of affected.ranges) {
          for (const event of range.events) {
            if (event.fixed) {
              return event.fixed;
            }
          }
        }
      }
    }
    return undefined;
  }
}