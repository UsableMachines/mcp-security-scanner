/**
 * OSV.dev vulnerability database service for static analysis
 * Following official OSV schema: https://ossf.github.io/osv-schema/
 * No fallbacks - fails fast to surface issues during development
 */

import { z } from 'zod';

// Official OSV schema types
const OSVSeverityTypeSchema = z.enum(['CVSS_V2', 'CVSS_V3', 'CVSS_V4', 'Ubuntu']);

const OSVSeverityEntrySchema = z.object({
  type: OSVSeverityTypeSchema,
  score: z.string()
});

const OSVReferenceTypeSchema = z.enum([
  'ADVISORY', 'ARTICLE', 'DETECTION', 'DISCUSSION',
  'REPORT', 'FIX', 'INTRODUCED', 'PACKAGE', 'EVIDENCE', 'WEB'
]);

const OSVReferenceSchema = z.object({
  type: OSVReferenceTypeSchema,
  url: z.string()
});

const OSVRangeEventSchema = z.object({
  introduced: z.string().optional(),
  fixed: z.string().optional(),
  last_affected: z.string().optional(),
  limit: z.string().optional()
});

const OSVVersionRangeSchema = z.object({
  type: z.enum(['SEMVER', 'ECOSYSTEM', 'GIT']),
  repo: z.string().optional(),
  events: z.array(OSVRangeEventSchema),
  database_specific: z.record(z.string(), z.unknown()).optional()
});

const OSVPackageSchema = z.object({
  ecosystem: z.string(),
  name: z.string(),
  purl: z.string().optional()
});

const OSVAffectedPackageSchema = z.object({
  package: OSVPackageSchema,
  severity: z.array(OSVSeverityEntrySchema).optional(),
  ranges: z.array(OSVVersionRangeSchema).optional(),
  versions: z.array(z.string()).optional(),
  ecosystem_specific: z.record(z.string(), z.unknown()).optional(),
  database_specific: z.record(z.string(), z.unknown()).optional()
});

const OSVCreditSchema = z.object({
  name: z.string(),
  contact: z.array(z.string()).optional(),
  type: z.enum([
    'FINDER', 'REPORTER', 'ANALYST', 'COORDINATOR',
    'REMEDIATION_DEVELOPER', 'REMEDIATION_REVIEWER',
    'REMEDIATION_VERIFIER', 'TOOL', 'SPONSOR'
  ]).optional()
});

const OSVVulnerabilitySchema = z.object({
  schema_version: z.string(),
  id: z.string(),
  modified: z.string(),
  published: z.string().optional(),
  withdrawn: z.string().optional(),
  aliases: z.array(z.string()).optional(),
  upstream: z.array(z.string()).optional(),
  related: z.array(z.string()).optional(),
  summary: z.string(),
  details: z.string(),
  severity: z.array(OSVSeverityEntrySchema).optional(),
  affected: z.array(OSVAffectedPackageSchema),
  references: z.array(OSVReferenceSchema).optional(),
  credits: z.array(OSVCreditSchema).optional(),
  database_specific: z.record(z.string(), z.unknown()).optional()
});

// API request/response schemas
const OSVQuerySchema = z.object({
  version: z.string().optional(),
  commit: z.string().optional(),
  package: OSVPackageSchema
});

const OSVVulnerabilityListSchema = z.object({
  vulns: z.array(OSVVulnerabilitySchema)
});

const OSVBatchQuerySchema = z.object({
  queries: z.array(OSVQuerySchema)
});

const OSVBatchVulnerabilityListSchema = z.object({
  results: z.array(OSVVulnerabilityListSchema)
});

export type OSVVulnerability = z.infer<typeof OSVVulnerabilitySchema>;
export type OSVPackage = z.infer<typeof OSVPackageSchema>;
export type OSVQuery = z.infer<typeof OSVQuerySchema>;
export type OSVSeverityEntry = z.infer<typeof OSVSeverityEntrySchema>;

export interface DependencyVulnerability {
  packageName: string;
  version: string;
  vulnerability: OSVVulnerability;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  cvssScore?: number;
}

export interface VulnerabilityReport {
  totalPackagesScanned: number;
  vulnerablePackages: number;
  totalVulnerabilities: number;
  severityBreakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
  };
  vulnerabilities: DependencyVulnerability[];
  scanDuration: number;
}

export class OSVService {
  private static readonly BASE_URL = 'https://api.osv.dev';
  private static readonly BATCH_SIZE = 1000; // API limit
  private cache = new Map<string, OSVVulnerability[]>();

  async scanPackage(packageName: string, version: string, ecosystem = 'npm'): Promise<OSVVulnerability[]> {
    const cacheKey = `${ecosystem}:${packageName}:${version}`;

    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey)!;
    }

    const query: OSVQuery = {
      version,
      package: {
        ecosystem,
        name: packageName
      }
    };

    const response = await fetch(`${OSVService.BASE_URL}/v1/query`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(query)
    });

    if (!response.ok) {
      throw new Error(`OSV API request failed for ${packageName}@${version}: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    const result = OSVVulnerabilityListSchema.parse(data);

    this.cache.set(cacheKey, result.vulns);
    return result.vulns;
  }

  async scanPackageBatch(packages: Array<{ name: string; version: string; ecosystem?: string }>): Promise<Map<string, OSVVulnerability[]>> {
    if (packages.length === 0) {
      throw new Error('Cannot scan empty package list');
    }

    const results = new Map<string, OSVVulnerability[]>();
    const uncachedPackages: Array<{ name: string; version: string; ecosystem: string; key: string }> = [];

    // Check cache first
    for (const pkg of packages) {
      const ecosystem = pkg.ecosystem || 'npm';
      const key = `${ecosystem}:${pkg.name}:${pkg.version}`;

      if (this.cache.has(key)) {
        results.set(`${pkg.name}@${pkg.version}`, this.cache.get(key)!);
      } else {
        uncachedPackages.push({
          ...pkg,
          ecosystem,
          key
        });
      }
    }

    if (uncachedPackages.length === 0) return results;

    // Process in batches
    const batches = this.chunkArray(uncachedPackages, OSVService.BATCH_SIZE);

    for (const batch of batches) {
      const queries = batch.map(pkg => ({
        version: pkg.version,
        package: {
          ecosystem: pkg.ecosystem,
          name: pkg.name
        }
      }));

      const response = await fetch(`${OSVService.BASE_URL}/v1/querybatch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ queries })
      });

      if (!response.ok) {
        throw new Error(`OSV batch API request failed: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      const batchResult = OSVBatchVulnerabilityListSchema.parse(data);

      batch.forEach((pkg, index) => {
        const vulnerabilities = batchResult.results[index]?.vulns || [];
        const packageKey = `${pkg.name}@${pkg.version}`;

        // Cache and store results
        this.cache.set(pkg.key, vulnerabilities);
        results.set(packageKey, vulnerabilities);
      });
    }

    return results;
  }

  generateVulnerabilityReport(
    scanResults: Map<string, OSVVulnerability[]>,
    scanDuration: number
  ): VulnerabilityReport {
    const vulnerabilities: DependencyVulnerability[] = [];
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
        const severity = this.mapSeverity(vuln);
        const cvssScore = this.extractCVSSScore(vuln);

        vulnerabilities.push({
          packageName,
          version,
          vulnerability: vuln,
          severity,
          cvssScore
        });

        severityBreakdown[severity]++;
      }
    }

    return {
      totalPackagesScanned: scanResults.size,
      vulnerablePackages: Array.from(scanResults.values()).filter(vulns => vulns.length > 0).length,
      totalVulnerabilities: vulnerabilities.length,
      severityBreakdown,
      vulnerabilities,
      scanDuration
    };
  }

  private mapSeverity(vulnerability: OSVVulnerability): 'critical' | 'high' | 'medium' | 'low' | 'unknown' {
    // Check vulnerability-level severity first
    let highestScore = this.getHighestCVSSScore(vulnerability.severity);

    // If no vulnerability-level severity, check affected packages
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
    // Check vulnerability-level severity first
    let score = this.getHighestCVSSScore(vulnerability.severity);

    // If no vulnerability-level severity, check affected packages
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

  private getHighestCVSSScore(severityEntries?: OSVSeverityEntry[]): number | null {
    if (!severityEntries || severityEntries.length === 0) {
      return null;
    }

    // Prefer CVSS v3, then v4, then v2
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

  private chunkArray<T>(array: T[], chunkSize: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }

  clearCache(): void {
    this.cache.clear();
  }

  getCacheStats(): { size: number; keys: string[] } {
    return {
      size: this.cache.size,
      keys: Array.from(this.cache.keys())
    };
  }
}