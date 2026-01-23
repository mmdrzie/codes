#!/usr/bin/env node

import * as fs from 'fs';
import * as path from 'path';

interface TimingLeakFinding {
  file: string;
  line: number;
  code: string;
  issue: string;
  suggestedFix: string;
}

/**
 * Scans the codebase for potential timing leak vulnerabilities
 */
class TimingLeakAuditor {
  private findings: TimingLeakFinding[] = [];

  /**
   * Searches for timing leak patterns in source files
   */
  async auditDirectory(directory: string): Promise<TimingLeakFinding[]> {
    this.findings = [];

    const files = await this.getAllTsFiles(directory);
    
    for (const file of files) {
      await this.auditFile(file);
    }

    return this.findings;
  }

  /**
   * Gets all TypeScript files in a directory recursively
   */
  private async getAllTsFiles(dir: string): Promise<string[]> {
    const files: string[] = [];
    
    const items = await fs.promises.readdir(dir, { withFileTypes: true });
    
    for (const item of items) {
      const fullPath = path.join(dir, item.name);
      
      if (item.isDirectory()) {
        files.push(...await this.getAllTsFiles(fullPath));
      } else if (item.isFile() && (item.name.endsWith('.ts') || item.name.endsWith('.tsx'))) {
        files.push(fullPath);
      }
    }
    
    return files;
  }

  /**
   * Audits a single file for timing leak patterns
   */
  private async auditFile(filePath: string): Promise<void> {
    try {
      const content = await fs.promises.readFile(filePath, 'utf8');
      const lines = content.split('\n');
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNumber = i + 1;
        
        // Check for string equality comparisons on potentially sensitive values
        if (line.includes('===') || line.includes('==')) {
          // Look for comparisons that might involve secrets, tokens, passwords, etc.
          const sensitivePatterns = [
            /secret/i, /token/i, /password/i, /key/i, /hash/i, /auth/i, /session/i, 
            /api.*key/i, /jwt/i, /bearer/i, /otp/i, /code/i, /pin/i, /cvv/i, /cvc/i
          ];
          
          const hasSensitiveVar = sensitivePatterns.some(pattern => 
            pattern.test(line) || 
            (lineNumber > 1 && pattern.test(lines[lineNumber - 2])) ||  // Check previous line
            (lineNumber < lines.length && pattern.test(lines[lineNumber]))  // Check next line
          );
          
          if (hasSensitiveVar && (line.includes('===') || line.includes('=='))) {
            this.findings.push({
              file: filePath,
              line: lineNumber,
              code: line.trim(),
              issue: 'Potential timing attack vulnerability: Using regular string comparison for sensitive data',
              suggestedFix: 'Use constant-time comparison (crypto.timingSafeEqual) instead of === or =='
            });
          }
        }
        
        // Check for early return patterns in authentication functions
        if (this.isInAuthFunction(lines, lineNumber - 1) && 
            (line.includes('return') || line.includes('throw')) &&
            this.hasSensitiveComparisonContext(lines, lineNumber - 1)) {
          this.findings.push({
            file: filePath,
            line: lineNumber,
            code: line.trim(),
            issue: 'Early return in authentication function may leak timing information',
            suggestedFix: 'Ensure all authentication paths take the same amount of time or use constant-time operations'
          });
        }
        
        // Check for array.includes or string.indexOf on sensitive data
        if (line.includes('.includes(') || line.includes('.indexOf(')) {
          const hasSensitiveContext = /secret|token|password|key|auth|session|api.*key|jwt|bearer|otp/.test(line);
          if (hasSensitiveContext) {
            this.findings.push({
              file: filePath,
              line: lineNumber,
              code: line.trim(),
              issue: 'Potential timing leak: Using .includes() or .indexOf() on sensitive data',
              suggestedFix: 'Use constant-time alternatives for checking sensitive values'
            });
          }
        }
      }
    } catch (error) {
      console.error(`Error auditing file ${filePath}:`, error);
    }
  }

  /**
   * Checks if the current line is inside an authentication-related function
   */
  private isInAuthFunction(lines: string[], currentLineIndex: number): boolean {
    // Look backwards up to 10 lines to find function declarations
    const startSearch = Math.max(0, currentLineIndex - 10);
    
    for (let i = currentLineIndex; i >= startSearch; i--) {
      const line = lines[i];
      
      // Check if this looks like a function declaration with auth-related name
      if (/(function|const|let|var).*\b(auth|login|verify|validate|authenticate|check|compare|token|password|secret|key)\b/.test(line)) {
        return true;
      }
      
      // If we encounter another function declaration, stop searching
      if (/function\s+\w+|const\s+\w+\s*=|let\s+\w+\s*=|var\s+\w+\s*=/.test(line)) {
        break;
      }
    }
    
    return false;
  }

  /**
   * Checks if the context around the line involves sensitive comparisons
   */
  private hasSensitiveComparisonContext(lines: string[], currentLineIndex: number): boolean {
    const contextRange = 3; // Check 3 lines before and after
    const start = Math.max(0, currentLineIndex - contextRange);
    const end = Math.min(lines.length - 1, currentLineIndex + contextRange);
    
    for (let i = start; i <= end; i++) {
      const line = lines[i];
      if (/(secret|token|password|key|hash|auth|session|api.*key|jwt|bearer|otp|pin|cvv|cvc)/i.test(line)) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Prints the audit results
   */
  printResults(findings: TimingLeakFinding[]): void {
    if (findings.length === 0) {
      console.log('✅ No timing leak vulnerabilities found!');
      return;
    }

    console.log(`⚠️  Found ${findings.length} potential timing leak vulnerabilities:\n`);

    for (const finding of findings) {
      console.log(`File: ${finding.file}:${finding.line}`);
      console.log(`Code: ${finding.code}`);
      console.log(`Issue: ${finding.issue}`);
      console.log(`Suggested Fix: ${finding.suggestedFix}`);
      console.log('');
    }
  }

  /**
   * Generates a summary report
   */
  generateReport(findings: TimingLeakFinding[]): string {
    const totalFindings = findings.length;
    const filesAffected = [...new Set(findings.map(f => f.file))].length;
    
    let report = '# Timing Leak Audit Report\n\n';
    report += `## Summary\n`;
    report += `- Total Issues Found: ${totalFindings}\n`;
    report += `- Files Affected: ${filesAffected}\n\n`;

    if (totalFindings > 0) {
      report += `## Issues\n`;
      for (const finding of findings) {
        report += `- **${finding.file}:${finding.line}**: ${finding.issue}\n`;
        report += `  - Code: \`${finding.code}\`\n`;
        report += `  - Fix: ${finding.suggestedFix}\n\n`;
      }
    } else {
      report += `## Status\n`;
      report += `No timing leak vulnerabilities detected. All sensitive comparisons appear to use constant-time operations.\n`;
    }

    return report;
  }
}

/**
 * Main function
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const directory = args[0] || './src';

  console.log(`Auditing directory: ${directory} for timing leak vulnerabilities\n`);

  const auditor = new TimingLeakAuditor();
  const findings = await auditor.auditDirectory(directory);

  auditor.printResults(findings);

  // Generate and save report
  const report = auditor.generateReport(findings);
  const reportPath = path.join(process.cwd(), 'timing-leak-audit-report.md');
  await fs.promises.writeFile(reportPath, report, 'utf8');
  console.log(`Audit report saved to: ${reportPath}`);
}

// Run the main function
main().catch(error => {
  console.error('Error during audit:', error);
  process.exit(1);
});