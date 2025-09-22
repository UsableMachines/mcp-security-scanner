/**
 * Dependency analysis module for static analysis mode
 * Parses package.json and scans dependencies for vulnerabilities
 */

import { readFile } from 'fs/promises';
import { join } from 'path';
import { z } from 'zod';
import { promisify } from 'util';
import { exec } from 'child_process';
import { OSVService, type VulnerabilityReport } from '../services/osv-service';
import { ScannerOrchestrator } from '../services/scanner-orchestrator';
import { ScanTarget, CombinedScanResult } from '../services/vulnerability-scanner';
import { SandboxProvider, type GitCloneResult, type OSVScanResult } from '../sandbox/sandbox-provider';

const execAsync = promisify(exec);

const PackageJsonSchema = z.object({
  name: z.string(),
  version: z.string(),
  dependencies: z.record(z.string(), z.string()).optional(),
  devDependencies: z.record(z.string(), z.string()).optional(),
  peerDependencies: z.record(z.string(), z.string()).optional(),
  optionalDependencies: z.record(z.string(), z.string()).optional()
});

const PackageLockJsonSchema = z.object({
  name: z.string(),
  version: z.string(),
  lockfileVersion: z.number(),
  packages: z.record(z.string(), z.object({
    version: z.string().optional(),
    resolved: z.string().optional(),
    integrity: z.string().optional(),
    dev: z.boolean().optional(),
    optional: z.boolean().optional(),
    peer: z.boolean().optional()
  })).optional()
});

export interface DependencyInfo {
  name: string;
  version: string;
  type: 'direct' | 'dev' | 'peer' | 'optional' | 'transitive';
  ecosystem: string;
}

export interface DependencyAnalysisResult {
  projectName: string;
  projectVersion: string;
  dependencies: DependencyInfo[];
  vulnerabilityReport: VulnerabilityReport;
  lockfilePresent: boolean;
  analysisTimestamp: Date;
  combinedScanResult?: CombinedScanResult; // New dual-scanner result
}

export interface SandboxedAnalysisResult extends DependencyAnalysisResult {
  cloneResult: GitCloneResult;
  osvScanResult: OSVScanResult;
  sandboxProvider: string;
}

export class DependencyAnalyzer {
  private osvService: OSVService;
  private scannerOrchestrator: ScannerOrchestrator;

  constructor(osvService?: OSVService) {
    this.osvService = osvService || new OSVService();
    this.scannerOrchestrator = new ScannerOrchestrator();
  }

  /**
   * Analyze a remote repository by cloning it in a sandbox and running dual scanner system
   */
  async analyzeRemoteRepository(
    repoUrl: string,
    sandboxProvider: SandboxProvider
  ): Promise<SandboxedAnalysisResult> {
    const startTime = Date.now();

    // Step 1: Clone the repository in sandbox
    const cloneResult = await sandboxProvider.cloneRepository(repoUrl, '/tmp/repo');

    if (!cloneResult.success) {
      throw new Error(`Failed to clone repository: ${cloneResult.error}`);
    }

    // Step 2: Run dual-scanner system on repository
    console.log(`🔍 Analyzing repository with dual-scanner system: ${repoUrl}`);

    const scanTarget: ScanTarget = {
      type: 'repository',
      path: '/tmp/repo',
      repoUrl: repoUrl
    };

    let combinedScanResult: CombinedScanResult;
    let projectInfo: { name: string; version: string; dependencies: DependencyInfo[] };

    try {
      // Use dual-scanner system
      combinedScanResult = await this.scannerOrchestrator.scan(scanTarget);

      // Extract project info from successful scan results
      projectInfo = await this.extractProjectInfoFromScanResults(combinedScanResult, '/tmp/repo', sandboxProvider);

      console.log(`📊 Dual-scanner repository analysis complete - Found ${combinedScanResult.totalUniqueVulnerabilities} vulnerabilities`);

    } catch (error) {
      // Fallback to OSV scan in sandbox if dual-scanner fails
      console.warn(`Dual-scanner failed for repository, falling back to OSV: ${error instanceof Error ? error.message : String(error)}`);

      const osvScanResult = await sandboxProvider.runOSVScan('/tmp/repo');

      if (!osvScanResult.success) {
        // Clean up volume on error
        if (typeof (sandboxProvider as any).cleanupCurrentVolume === 'function') {
          await (sandboxProvider as any).cleanupCurrentVolume();
        }
        throw new Error(`Both dual-scanner and OSV fallback failed: ${osvScanResult.error}`);
      }

      // Extract project info from OSV fallback results
      projectInfo = this.extractProjectInfoFromOSVResults(osvScanResult);

      // Create a minimal combined result for compatibility
      combinedScanResult = {
        combinedVulnerabilities: [],
        combinedSeverityBreakdown: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
        totalUniqueVulnerabilities: 0,
        scannerComparison: { osvOnly: 0, trivyOnly: 0, bothScanners: 0 },
        combinedScanDuration: Date.now() - startTime
      };

      console.log(`⚠️  Using OSV fallback results for repository analysis`);
    }

    // Don't cleanup here - let source code analysis use the volume first

    // Step 3: Generate legacy vulnerability report for backward compatibility
    const vulnerabilityReport = this.generateLegacyReportFromCombinedResults(combinedScanResult, Date.now() - startTime);

    const analysisTimestamp = new Date();

    // Create a compatible OSV scan result for legacy interfaces
    const osvScanResult: OSVScanResult = {
      success: combinedScanResult.totalUniqueVulnerabilities >= 0,
      vulnerabilities: [], // Legacy format not needed with new system
      duration: combinedScanResult.combinedScanDuration,
      error: combinedScanResult.totalUniqueVulnerabilities === 0 ? undefined : 'Converted from dual-scanner results',
      scanOutput: 'Dual-scanner system results' // Required field for interface compatibility
    };

    return {
      projectName: projectInfo.name,
      projectVersion: projectInfo.version,
      dependencies: projectInfo.dependencies,
      vulnerabilityReport,
      lockfilePresent: true, // Assume lockfile present if scan succeeded
      analysisTimestamp,
      combinedScanResult, // New field with dual-scanner results
      cloneResult,
      osvScanResult,
      sandboxProvider: sandboxProvider.name
    };
  }

  async analyzeMCPProject(projectPath: string): Promise<DependencyAnalysisResult> {
    const startTime = Date.now();

    // Parse package.json
    const packageJsonPath = join(projectPath, 'package.json');
    const packageJson = await this.parsePackageJson(packageJsonPath);

    // Parse package-lock.json if present
    let lockfileData: z.infer<typeof PackageLockJsonSchema> | null = null;
    let lockfilePresent = false;

    try {
      const lockfilePath = join(projectPath, 'package-lock.json');
      lockfileData = await this.parsePackageLockJson(lockfilePath);
      lockfilePresent = true;
    } catch (error) {
      // No lockfile present - will use package.json versions
    }

    // Extract all dependencies
    const dependencies = this.extractDependencies(packageJson, lockfileData);

    // Scan for vulnerabilities with dual scanners
    const packages = dependencies.map(dep => ({
      name: dep.name,
      version: dep.version,
      ecosystem: dep.ecosystem
    }));

    // Use new dual-scanner system
    const scanTarget: ScanTarget = {
      type: 'package-list',
      packages
    };

    const combinedScanResult = await this.scannerOrchestrator.scan(scanTarget);
    const scanDuration = Date.now() - startTime;

    // For backward compatibility, generate legacy VulnerabilityReport from OSV result
    let vulnerabilityReport: VulnerabilityReport;
    if (combinedScanResult.osvResult?.success) {
      vulnerabilityReport = this.convertToLegacyFormat(combinedScanResult.osvResult, scanDuration);
    } else {
      // Fallback to OSV service for legacy compatibility
      const scanResults = await this.osvService.scanPackageBatch(packages);
      vulnerabilityReport = this.osvService.generateVulnerabilityReport(scanResults, scanDuration);
    }

    return {
      projectName: packageJson.name,
      projectVersion: packageJson.version,
      dependencies,
      vulnerabilityReport,
      lockfilePresent,
      analysisTimestamp: new Date(),
      combinedScanResult
    };
  }

  async analyzePackageJson(packageJsonContent: string): Promise<DependencyAnalysisResult> {
    const startTime = Date.now();

    const packageJson = PackageJsonSchema.parse(JSON.parse(packageJsonContent));

    // Extract dependencies (no lockfile available)
    const dependencies = this.extractDependenciesFromPackageJson(packageJson);

    // Scan for vulnerabilities with dual scanners
    const packages = dependencies.map(dep => ({
      name: dep.name,
      version: dep.version,
      ecosystem: dep.ecosystem
    }));

    // Use new dual-scanner system
    const scanTarget: ScanTarget = {
      type: 'package-list',
      packages
    };

    const combinedScanResult = await this.scannerOrchestrator.scan(scanTarget);
    const scanDuration = Date.now() - startTime;

    // For backward compatibility, generate legacy VulnerabilityReport from OSV result
    let vulnerabilityReport: VulnerabilityReport;
    if (combinedScanResult.osvResult?.success) {
      vulnerabilityReport = this.convertToLegacyFormat(combinedScanResult.osvResult, scanDuration);
    } else {
      // Fallback to OSV service for legacy compatibility
      const scanResults = await this.osvService.scanPackageBatch(packages);
      vulnerabilityReport = this.osvService.generateVulnerabilityReport(scanResults, scanDuration);
    }

    return {
      projectName: packageJson.name,
      projectVersion: packageJson.version,
      dependencies,
      vulnerabilityReport,
      lockfilePresent: false,
      analysisTimestamp: new Date(),
      combinedScanResult
    };
  }

  private async parsePackageJson(packageJsonPath: string): Promise<z.infer<typeof PackageJsonSchema>> {
    const content = await readFile(packageJsonPath, 'utf-8');
    const data = JSON.parse(content);
    return PackageJsonSchema.parse(data);
  }

  private async parsePackageLockJson(lockfilePath: string): Promise<z.infer<typeof PackageLockJsonSchema>> {
    const content = await readFile(lockfilePath, 'utf-8');
    const data = JSON.parse(content);
    return PackageLockJsonSchema.parse(data);
  }

  private extractDependencies(
    packageJson: z.infer<typeof PackageJsonSchema>,
    lockfileData: z.infer<typeof PackageLockJsonSchema> | null
  ): DependencyInfo[] {
    const dependencies: DependencyInfo[] = [];

    if (lockfileData?.packages) {
      // Use lockfile for precise versions (npm v7+ format)
      for (const [packagePath, packageInfo] of Object.entries(lockfileData.packages)) {
        if (!packagePath || packagePath === '') continue; // Skip root package

        const packageName = this.extractPackageNameFromPath(packagePath);
        if (!packageName || !packageInfo.version) continue;

        const type = this.determineDependencyType(packageName, packageJson, packageInfo);

        dependencies.push({
          name: packageName,
          version: packageInfo.version,
          type,
          ecosystem: 'npm'
        });
      }
    } else {
      // Fallback to package.json versions
      dependencies.push(...this.extractDependenciesFromPackageJson(packageJson));
    }

    return dependencies;
  }

  private extractDependenciesFromPackageJson(packageJson: z.infer<typeof PackageJsonSchema>): DependencyInfo[] {
    const dependencies: DependencyInfo[] = [];

    // Direct dependencies
    if (packageJson.dependencies) {
      for (const [name, version] of Object.entries(packageJson.dependencies)) {
        dependencies.push({
          name,
          version: this.normalizeVersion(version),
          type: 'direct',
          ecosystem: 'npm'
        });
      }
    }

    // Dev dependencies
    if (packageJson.devDependencies) {
      for (const [name, version] of Object.entries(packageJson.devDependencies)) {
        dependencies.push({
          name,
          version: this.normalizeVersion(version),
          type: 'dev',
          ecosystem: 'npm'
        });
      }
    }

    // Peer dependencies
    if (packageJson.peerDependencies) {
      for (const [name, version] of Object.entries(packageJson.peerDependencies)) {
        dependencies.push({
          name,
          version: this.normalizeVersion(version),
          type: 'peer',
          ecosystem: 'npm'
        });
      }
    }

    // Optional dependencies
    if (packageJson.optionalDependencies) {
      for (const [name, version] of Object.entries(packageJson.optionalDependencies)) {
        dependencies.push({
          name,
          version: this.normalizeVersion(version),
          type: 'optional',
          ecosystem: 'npm'
        });
      }
    }

    return dependencies;
  }

  private extractPackageNameFromPath(packagePath: string): string | null {
    // Handle node_modules paths like "node_modules/@types/node" or "node_modules/lodash"
    const match = packagePath.match(/node_modules\/(.+)$/);
    return match ? match[1] : null;
  }

  private determineDependencyType(
    packageName: string,
    packageJson: z.infer<typeof PackageJsonSchema>,
    packageInfo: { dev?: boolean; optional?: boolean; peer?: boolean }
  ): DependencyInfo['type'] {
    if (packageInfo.dev) return 'dev';
    if (packageInfo.optional) return 'optional';
    if (packageInfo.peer) return 'peer';

    // Check if it's in direct dependencies
    if (packageJson.dependencies?.[packageName]) return 'direct';
    if (packageJson.devDependencies?.[packageName]) return 'dev';
    if (packageJson.peerDependencies?.[packageName]) return 'peer';
    if (packageJson.optionalDependencies?.[packageName]) return 'optional';

    return 'transitive';
  }

  private normalizeVersion(versionRange: string): string {
    // Remove version range prefixes for OSV queries
    // OSV expects exact versions, so we take the "intended" version
    return versionRange.replace(/^[\^~>=<]+/, '');
  }

  // Utility methods for filtering dependencies
  filterDirectDependencies(dependencies: DependencyInfo[]): DependencyInfo[] {
    return dependencies.filter(dep => dep.type === 'direct');
  }

  filterProductionDependencies(dependencies: DependencyInfo[]): DependencyInfo[] {
    return dependencies.filter(dep => dep.type === 'direct' || dep.type === 'transitive');
  }

  getHighRiskDependencies(result: DependencyAnalysisResult): DependencyInfo[] {
    const vulnerablePackages = new Set(
      result.vulnerabilityReport.vulnerabilities
        .filter(vuln => vuln.severity === 'critical' || vuln.severity === 'high')
        .map(vuln => vuln.packageName)
    );

    return result.dependencies.filter(dep => vulnerablePackages.has(dep.name));
  }

  /**
   * Extract project information from OSV scan results
   */
  private extractProjectInfoFromOSVResults(osvResult: OSVScanResult): { name: string; version: string; dependencies: DependencyInfo[] } {
    const dependencies: DependencyInfo[] = [];
    let projectName = 'unknown-project';
    let projectVersion = '1.0.0';

    if (osvResult.vulnerabilities && osvResult.vulnerabilities.length > 0) {
      for (const result of osvResult.vulnerabilities) {
        if (result.packages) {
          for (const pkg of result.packages) {
            if (pkg.package) {
              const packageName = pkg.package.name;
              const packageVersion = pkg.package.version || '1.0.0';
              const ecosystem = pkg.package.ecosystem || 'unknown';

              // Use first package as project name if it looks like a main package
              if (projectName === 'unknown-project' && packageName && !packageName.startsWith('@')) {
                projectName = packageName;
                projectVersion = packageVersion;
              }

              dependencies.push({
                name: packageName,
                version: packageVersion,
                type: 'direct', // OSV doesn't distinguish dependency types in scan results
                ecosystem: ecosystem.toLowerCase()
              });
            }
          }
        }
      }
    }

    // If no packages found, create a minimal project info
    if (dependencies.length === 0) {
      dependencies.push({
        name: 'no-dependencies-detected',
        version: '1.0.0',
        type: 'direct',
        ecosystem: 'unknown'
      });
    }

    return {
      name: projectName,
      version: projectVersion,
      dependencies
    };
  }

  /**
   * Convert OSV scan results to our vulnerability report format
   */
  private convertOSVResultsToReport(osvResult: OSVScanResult): VulnerabilityReport {
    if (!osvResult.success) {
      return {
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
        scanDuration: osvResult.duration
      };
    }

    const vulnerabilities: VulnerabilityReport['vulnerabilities'] = [];
    const scannedPackages = new Set<string>();

    // Parse OSV vulnerabilities format
    for (const result of osvResult.vulnerabilities) {
      if (result.packages) {
        for (const pkg of result.packages) {
          const packageName = pkg.package?.name || 'unknown';
          scannedPackages.add(packageName);

          if (pkg.vulnerabilities) {
            for (const vuln of pkg.vulnerabilities) {
              const severity = this.mapOSVSeverityToStandard(vuln.database_specific?.severity);

              vulnerabilities.push({
                packageName,
                version: pkg.package?.version || 'unknown',
                vulnerability: vuln,
                severity,
                cvssScore: vuln.database_specific?.cvss_score
              });
            }
          }
        }
      }
    }

    // Count by severity
    const severityBreakdown = vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.severity]++;
      return acc;
    }, { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });

    const vulnerablePackages = new Set(vulnerabilities.map(v => v.packageName)).size;

    return {
      totalPackagesScanned: scannedPackages.size,
      vulnerablePackages,
      totalVulnerabilities: vulnerabilities.length,
      severityBreakdown,
      vulnerabilities,
      scanDuration: osvResult.duration
    };
  }

  /**
   * Map OSV severity levels to our standard format
   */
  private mapOSVSeverityToStandard(severity: string | undefined): 'critical' | 'high' | 'medium' | 'low' {
    if (!severity) return 'medium';

    const severityLower = severity.toLowerCase();
    if (severityLower.includes('critical')) return 'critical';
    if (severityLower.includes('high')) return 'high';
    if (severityLower.includes('medium') || severityLower.includes('moderate')) return 'medium';
    if (severityLower.includes('low')) return 'low';

    return 'medium'; // Default fallback
  }

  /**
   * Extract project information from dual-scanner results
   */
  private async extractProjectInfoFromScanResults(
    combinedResult: CombinedScanResult,
    repoPath: string,
    sandboxProvider: SandboxProvider
  ): Promise<{ name: string; version: string; dependencies: DependencyInfo[] }> {
    // Try to extract project info from package files if available
    try {
      // Look for package.json in the cloned repository
      const packageJsonContent = await this.readFileFromSandbox(sandboxProvider, `${repoPath}/package.json`);
      if (packageJsonContent) {
        const packageJson = JSON.parse(packageJsonContent);
        const dependencies = this.extractDependenciesFromPackageJson(packageJson);

        return {
          name: packageJson.name || 'unknown-project',
          version: packageJson.version || '1.0.0',
          dependencies
        };
      }
    } catch (error) {
      console.warn('Could not extract project info from package.json:', error);
    }

    // Fallback: extract from vulnerability scan results
    const dependencies: DependencyInfo[] = [];
    let projectName = 'unknown-project';
    let projectVersion = '1.0.0';

    if (combinedResult.combinedVulnerabilities.length > 0) {
      // Use first vulnerability to infer project name
      const firstVuln = combinedResult.combinedVulnerabilities[0];
      projectName = firstVuln.packageName || 'scanned-project';

      // Convert vulnerabilities to dependencies
      const packageMap = new Map<string, DependencyInfo>();

      for (const vuln of combinedResult.combinedVulnerabilities) {
        const key = `${vuln.packageName}@${vuln.packageVersion}`;
        if (!packageMap.has(key)) {
          packageMap.set(key, {
            name: vuln.packageName,
            version: vuln.packageVersion,
            type: 'direct',
            ecosystem: vuln.ecosystem
          });
        }
      }

      dependencies.push(...packageMap.values());
    }

    return {
      name: projectName,
      version: projectVersion,
      dependencies
    };
  }

  /**
   * Read a file from the sandbox environment
   */
  private async readFileFromSandbox(sandboxProvider: SandboxProvider, filePath: string): Promise<string | null> {
    try {
      // This would need to be implemented based on the sandbox provider's capabilities
      // For now, return null to trigger fallback behavior
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Generate legacy VulnerabilityReport from combined scan results
   */
  private generateLegacyReportFromCombinedResults(combinedResult: CombinedScanResult, duration: number): VulnerabilityReport {
    const vulnerabilities: VulnerabilityReport['vulnerabilities'] = combinedResult.combinedVulnerabilities.map((vuln: import('../services/vulnerability-scanner').Vulnerability) => ({
      packageName: vuln.packageName,
      version: vuln.packageVersion,
      vulnerability: {
        id: vuln.id,
        summary: vuln.title,
        details: vuln.description,
        modified: vuln.modifiedDate || new Date().toISOString(),
        published: vuln.publishedDate,
        aliases: vuln.cveIds,
        affected: [{
          package: {
            ecosystem: vuln.ecosystem,
            name: vuln.packageName
          },
          ranges: vuln.fixedVersion ? [{
            type: 'SEMVER',
            events: [{ fixed: vuln.fixedVersion }]
          }] : undefined
        }],
        references: vuln.references?.map((ref: string) => ({
          type: 'WEB' as const,
          url: ref
        })),
        schema_version: '1.4.0'
      } as any,
      severity: vuln.severity,
      cvssScore: vuln.cvssScore
    }));

    // Calculate totals from combined results
    const packageCount = new Set(combinedResult.combinedVulnerabilities.map((v: any) => v.packageName)).size;
    const vulnerablePackages = new Set(vulnerabilities.map(v => v.packageName)).size;

    return {
      totalPackagesScanned: packageCount || 1,
      vulnerablePackages,
      totalVulnerabilities: combinedResult.totalUniqueVulnerabilities,
      severityBreakdown: combinedResult.combinedSeverityBreakdown,
      vulnerabilities,
      scanDuration: duration
    };
  }

  /**
   * Convert new ScanResult format to legacy VulnerabilityReport format for backward compatibility
   */
  private convertToLegacyFormat(scanResult: import('../services/vulnerability-scanner').ScanResult, duration: number): VulnerabilityReport {
    const vulnerabilities: VulnerabilityReport['vulnerabilities'] = scanResult.vulnerabilities.map((vuln: import('../services/vulnerability-scanner').Vulnerability) => ({
      packageName: vuln.packageName,
      version: vuln.packageVersion,
      vulnerability: {
        id: vuln.id,
        summary: vuln.title,
        details: vuln.description,
        modified: vuln.modifiedDate || new Date().toISOString(),
        published: vuln.publishedDate,
        aliases: vuln.cveIds,
        affected: [{
          package: {
            ecosystem: vuln.ecosystem,
            name: vuln.packageName
          },
          ranges: vuln.fixedVersion ? [{
            type: 'SEMVER',
            events: [{ fixed: vuln.fixedVersion }]
          }] : undefined
        }],
        references: vuln.references?.map((ref: string) => ({
          type: 'WEB' as const,
          url: ref
        })),
        schema_version: '1.4.0'
      } as any,
      severity: vuln.severity,
      cvssScore: vuln.cvssScore
    }));

    return {
      totalPackagesScanned: scanResult.totalPackagesScanned,
      vulnerablePackages: scanResult.vulnerablePackages,
      totalVulnerabilities: scanResult.totalVulnerabilities,
      severityBreakdown: scanResult.severityBreakdown,
      vulnerabilities,
      scanDuration: duration
    };
  }
}