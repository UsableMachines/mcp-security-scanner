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
}

export interface SandboxedAnalysisResult extends DependencyAnalysisResult {
  cloneResult: GitCloneResult;
  osvScanResult: OSVScanResult;
  sandboxProvider: string;
}

export class DependencyAnalyzer {
  private osvService: OSVService;

  constructor(osvService?: OSVService) {
    this.osvService = osvService || new OSVService();
  }

  /**
   * Analyze a remote repository by cloning it in a sandbox and running OSV scan
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

    // Step 2: Run OSV scan in sandbox
    const osvScanResult = await sandboxProvider.runOSVScan('/tmp/repo');

    // Step 3: Parse package.json from volume using a simple container
    let projectInfo: { name: string; version: string; dependencies: DependencyInfo[] };

    try {
      // Since we're using Docker volumes, we need to access files differently
      // The volume is stored in the provider, we need to use it to read files
      const volumeName = (sandboxProvider as any)._currentVolume;

      if (!volumeName) {
        throw new Error('No Docker volume available for reading project files');
      }

      // Read package.json using a simple alpine container with volume mounted
      const packageJsonResult = await execAsync(`docker run --rm -v ${volumeName}:/src alpine:latest cat /src/package.json`);
      const packageJson = PackageJsonSchema.parse(JSON.parse(packageJsonResult.stdout));

      // Try to get lockfile data too
      let lockfileData = null;
      try {
        const lockfileResult = await execAsync(`docker run --rm -v ${volumeName}:/src alpine:latest cat /src/package-lock.json`);
        lockfileData = PackageLockJsonSchema.parse(JSON.parse(lockfileResult.stdout));
      } catch {
        // No lockfile - that's okay
      }

      const dependencies = lockfileData
        ? this.extractDependencies(packageJson, lockfileData)
        : this.extractDependenciesFromPackageJson(packageJson);

      projectInfo = {
        name: packageJson.name,
        version: packageJson.version,
        dependencies
      };
    } catch (error) {
      // Clean up volume on error
      if (typeof (sandboxProvider as any).cleanupCurrentVolume === 'function') {
        await (sandboxProvider as any).cleanupCurrentVolume();
      }
      throw new Error(`Failed to parse project metadata: ${error instanceof Error ? error.message : String(error)}`);
    }
    // Don't cleanup here - let source code analysis use the volume first

    // Step 4: Convert OSV scan results to our vulnerability report format
    const vulnerabilityReport = this.convertOSVResultsToReport(osvScanResult);

    const analysisTimestamp = new Date();

    return {
      projectName: projectInfo.name,
      projectVersion: projectInfo.version,
      dependencies: projectInfo.dependencies,
      vulnerabilityReport,
      lockfilePresent: !!osvScanResult.success, // OSV scan would include lockfile info
      analysisTimestamp,
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

    // Scan for vulnerabilities
    const packages = dependencies.map(dep => ({
      name: dep.name,
      version: dep.version,
      ecosystem: dep.ecosystem
    }));

    const scanResults = await this.osvService.scanPackageBatch(packages);
    const scanDuration = Date.now() - startTime;

    const vulnerabilityReport = this.osvService.generateVulnerabilityReport(
      scanResults,
      scanDuration
    );

    return {
      projectName: packageJson.name,
      projectVersion: packageJson.version,
      dependencies,
      vulnerabilityReport,
      lockfilePresent,
      analysisTimestamp: new Date()
    };
  }

  async analyzePackageJson(packageJsonContent: string): Promise<DependencyAnalysisResult> {
    const startTime = Date.now();

    const packageJson = PackageJsonSchema.parse(JSON.parse(packageJsonContent));

    // Extract dependencies (no lockfile available)
    const dependencies = this.extractDependenciesFromPackageJson(packageJson);

    // Scan for vulnerabilities
    const packages = dependencies.map(dep => ({
      name: dep.name,
      version: dep.version,
      ecosystem: dep.ecosystem
    }));

    const scanResults = await this.osvService.scanPackageBatch(packages);
    const scanDuration = Date.now() - startTime;

    const vulnerabilityReport = this.osvService.generateVulnerabilityReport(
      scanResults,
      scanDuration
    );

    return {
      projectName: packageJson.name,
      projectVersion: packageJson.version,
      dependencies,
      vulnerabilityReport,
      lockfilePresent: false,
      analysisTimestamp: new Date()
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
}