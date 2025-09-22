/**
 * Scanner Orchestrator - Manages multiple vulnerability scanners
 * Runs OSV and Trivy scanners in parallel, merges results, handles feature flags
 */

import { VulnerabilityScanner, ScanResult, CombinedScanResult, ScanTarget, Vulnerability } from './vulnerability-scanner';
import { OSVScanner } from './osv-scanner';
import { TrivyScanner } from './trivy-scanner';
import { vulnerabilityScannerConfig } from '../config';
import { SandboxProvider } from '../sandbox/sandbox-provider';

interface ScannerConfig {
  enableOsv: boolean;
  enableTrivy: boolean;
  mode: 'osv' | 'trivy' | 'both';
}

export class ScannerOrchestrator {
  private osvScanner: OSVScanner;
  private trivyScanner?: TrivyScanner;
  private config: ScannerConfig;

  constructor() {
    this.osvScanner = new OSVScanner();
    this.config = vulnerabilityScannerConfig();
  }

  /**
   * Scan target with configured scanners
   */
  async scan(target: ScanTarget, sandboxProvider?: SandboxProvider): Promise<CombinedScanResult> {
    // Create TrivyScanner with sandbox provider if needed
    if (!this.trivyScanner && sandboxProvider) {
      this.trivyScanner = new TrivyScanner(sandboxProvider);
    }
    const startTime = Date.now();
    const scanPromises: Array<Promise<{ scanner: string; result: ScanResult }>> = [];

    // Determine which scanners to run based on configuration
    const scannersToRun = this.getScannersToRun();

    console.log(`Running vulnerability scan with: ${scannersToRun.join(', ')}`);

    // Start scans in parallel
    if (scannersToRun.includes('osv')) {
      scanPromises.push(
        this.runScannerSafely(this.osvScanner, target).then(result => ({
          scanner: 'osv',
          result
        }))
      );
    }

    if (scannersToRun.includes('trivy') && this.trivyScanner) {
      scanPromises.push(
        this.runScannerSafely(this.trivyScanner, target).then(result => ({
          scanner: 'trivy',
          result
        }))
      );
    }

    // Wait for all scans to complete
    const scanResults = await Promise.all(scanPromises);
    const totalDuration = Date.now() - startTime;

    // Extract results
    const osvResult = scanResults.find(r => r.scanner === 'osv')?.result;
    const trivyResult = scanResults.find(r => r.scanner === 'trivy')?.result;

    return this.combineResults(osvResult, trivyResult, totalDuration);
  }

  /**
   * Health check for configured scanners
   */
  async healthCheck(): Promise<{ osv: boolean; trivy: boolean }> {
    const checks = await Promise.allSettled([
      this.config.enableOsv ? this.osvScanner.healthCheck() : Promise.resolve(false),
      this.config.enableTrivy && this.trivyScanner ? this.trivyScanner.healthCheck() : Promise.resolve(false)
    ]);

    return {
      osv: checks[0].status === 'fulfilled' ? checks[0].value : false,
      trivy: checks[1].status === 'fulfilled' ? checks[1].value : false
    };
  }

  /**
   * Get version information for configured scanners
   */
  async getVersionInfo(): Promise<{ osv?: string; trivy?: string }> {
    const versions: { osv?: string; trivy?: string } = {};

    if (this.config.enableOsv) {
      try {
        versions.osv = await this.osvScanner.getVersion();
      } catch (error) {
        versions.osv = 'Error getting version';
      }
    }

    if (this.config.enableTrivy && this.trivyScanner) {
      try {
        versions.trivy = await this.trivyScanner.getVersion();
      } catch (error) {
        versions.trivy = 'Error getting version';
      }
    }

    return versions;
  }

  private getScannersToRun(): string[] {
    const scanners: string[] = [];

    switch (this.config.mode) {
      case 'osv':
        if (this.config.enableOsv) scanners.push('osv');
        break;
      case 'trivy':
        if (this.config.enableTrivy) scanners.push('trivy');
        break;
      case 'both':
        if (this.config.enableOsv) scanners.push('osv');
        if (this.config.enableTrivy) scanners.push('trivy');
        break;
    }

    if (scanners.length === 0) {
      throw new Error('No vulnerability scanners enabled. Check configuration.');
    }

    return scanners;
  }

  private async runScannerSafely(scanner: VulnerabilityScanner, target: ScanTarget): Promise<ScanResult> {
    try {
      switch (target.type) {
        case 'docker-image':
          return await scanner.scanDockerImage(target);
        case 'repository':
          return await scanner.scanRepository(target);
        case 'package-list':
          return await scanner.scanPackages(target);
        default:
          throw new Error(`Unsupported target type: ${(target as any).type}`);
      }
    } catch (error) {
      // If scanner fails, return error result instead of throwing
      console.warn(`${scanner.name} scanner failed:`, error);
      return {
        scanner: scanner.name as 'osv' | 'trivy',
        totalPackagesScanned: 0,
        vulnerablePackages: 0,
        totalVulnerabilities: 0,
        severityBreakdown: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          unknown: 0
        },
        vulnerabilities: [],
        scanDuration: 0,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  private combineResults(
    osvResult: ScanResult | undefined,
    trivyResult: ScanResult | undefined,
    totalDuration: number
  ): CombinedScanResult {
    const allVulnerabilities: Vulnerability[] = [];
    const vulnMap = new Map<string, Vulnerability>();

    // Collect all vulnerabilities, deduplicating by ID + package combination
    if (osvResult?.success && osvResult.vulnerabilities) {
      for (const vuln of osvResult.vulnerabilities) {
        const key = `${vuln.id}:${vuln.packageName}:${vuln.packageVersion}`;
        vulnMap.set(key, vuln);
      }
    }

    if (trivyResult?.success && trivyResult.vulnerabilities) {
      for (const vuln of trivyResult.vulnerabilities) {
        const key = `${vuln.id}:${vuln.packageName}:${vuln.packageVersion}`;

        if (vulnMap.has(key)) {
          // Vulnerability found by both scanners - could merge additional data
          continue;
        }

        vulnMap.set(key, vuln);
      }
    }

    const combinedVulnerabilities = Array.from(vulnMap.values());

    // Calculate combined severity breakdown
    const combinedSeverityBreakdown = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0
    };

    for (const vuln of combinedVulnerabilities) {
      combinedSeverityBreakdown[vuln.severity as keyof typeof combinedSeverityBreakdown]++;
    }

    // Calculate scanner comparison stats
    const osvVulns = new Set(
      (osvResult?.vulnerabilities || []).map((v: Vulnerability) => `${v.id}:${v.packageName}:${v.packageVersion}`)
    );
    const trivyVulns = new Set(
      (trivyResult?.vulnerabilities || []).map((v: Vulnerability) => `${v.id}:${v.packageName}:${v.packageVersion}`)
    );

    const scannerComparison = {
      osvOnly: Array.from(osvVulns).filter(v => !trivyVulns.has(v)).length,
      trivyOnly: Array.from(trivyVulns).filter(v => !osvVulns.has(v)).length,
      bothScanners: Array.from(osvVulns).filter(v => trivyVulns.has(v)).length
    };

    return {
      osvResult,
      trivyResult,
      combinedVulnerabilities,
      combinedSeverityBreakdown,
      totalUniqueVulnerabilities: combinedVulnerabilities.length,
      scannerComparison,
      combinedScanDuration: totalDuration
    };
  }

  /**
   * Generate a human-readable summary of the scan results
   */
  generateSummary(result: CombinedScanResult): string {
    const lines: string[] = [];

    lines.push('=== Vulnerability Scan Summary ===');
    lines.push(`Total unique vulnerabilities: ${result.totalUniqueVulnerabilities}`);
    lines.push(`Scan duration: ${result.combinedScanDuration}ms`);
    lines.push('');

    // Severity breakdown
    lines.push('Severity Breakdown:');
    lines.push(`  Critical: ${result.combinedSeverityBreakdown.critical}`);
    lines.push(`  High: ${result.combinedSeverityBreakdown.high}`);
    lines.push(`  Medium: ${result.combinedSeverityBreakdown.medium}`);
    lines.push(`  Low: ${result.combinedSeverityBreakdown.low}`);
    lines.push(`  Unknown: ${result.combinedSeverityBreakdown.unknown}`);
    lines.push('');

    // Scanner comparison
    if (result.osvResult && result.trivyResult) {
      lines.push('Scanner Comparison:');
      lines.push(`  OSV only: ${result.scannerComparison.osvOnly}`);
      lines.push(`  Trivy only: ${result.scannerComparison.trivyOnly}`);
      lines.push(`  Both scanners: ${result.scannerComparison.bothScanners}`);
      lines.push('');
    }

    // Individual scanner results
    if (result.osvResult) {
      lines.push(`OSV Scanner: ${result.osvResult.success ? 'SUCCESS' : 'FAILED'}`);
      if (result.osvResult.success) {
        lines.push(`  Packages scanned: ${result.osvResult.totalPackagesScanned}`);
        lines.push(`  Vulnerabilities found: ${result.osvResult.totalVulnerabilities}`);
        lines.push(`  Duration: ${result.osvResult.scanDuration}ms`);
      } else {
        lines.push(`  Error: ${result.osvResult.error}`);
      }
    }

    if (result.trivyResult) {
      lines.push(`Trivy Scanner: ${result.trivyResult.success ? 'SUCCESS' : 'FAILED'}`);
      if (result.trivyResult.success) {
        lines.push(`  Packages scanned: ${result.trivyResult.totalPackagesScanned}`);
        lines.push(`  Vulnerabilities found: ${result.trivyResult.totalVulnerabilities}`);
        lines.push(`  Duration: ${result.trivyResult.scanDuration}ms`);
      } else {
        lines.push(`  Error: ${result.trivyResult.error}`);
      }
    }

    return lines.join('\n');
  }
}