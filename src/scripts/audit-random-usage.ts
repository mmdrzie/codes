#!/usr/bin/env node

import * as fs from 'fs';
import * as path from 'path';

interface RandomUsageFinding {
  file: string;
  line: number;
  code: string;
  issue: string;
  suggestedFix: string;
}

/**
 * Scans the codebase for insecure random number usage
 */
class RandomUsageAuditor {
  private findings: RandomUsageFinding[] = [];

  /**
   * Searches for insecure random usage patterns in source files
   */
  async auditDirectory(directory: string): Promise<RandomUsageFinding[]> {
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
   * Audits a single file for insecure random usage
   */
  private async auditFile(filePath: string): Promise<void> {
    try {
      const content = await fs.promises.readFile(filePath, 'utf8');
      const lines = content.split('\n');
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNumber = i + 1;
        
        // Check for Math.random()
        if (line.includes('Math.random()')) {
          this.findings.push({
            file: filePath,
            line: lineNumber,
            code: line.trim(),
            issue: 'Insecure random generation using Math.random()',
            suggestedFix: 'Replace with crypto.randomBytes() or SecureRandom class'
          });
        }
        
        // Check for Date.now() used as random
        if (line.includes('Date.now()') && 
            (line.includes('random') || line.includes('Random') || line.includes('id') || line.includes('ID'))) {
          this.findings.push({
            file: filePath,
            line: lineNumber,
            code: line.trim(),
            issue: 'Predictable random generation using Date.now()',
            suggestedFix: 'Replace with crypto.randomBytes() or SecureRandom class'
          });
        }
        
        // Check for process.hrtime() used as random
        if (line.includes('process.hrtime()') && 
            (line.includes('random') || line.includes('Random') || line.includes('id') || line.includes('ID'))) {
          this.findings.push({
            file: filePath,
            line: lineNumber,
            code: line.trim(),
            issue: 'Predictable random generation using process.hrtime()',
            suggestedFix: 'Replace with crypto.randomBytes() or SecureRandom class'
          });
        }
        
        // Check for other weak random patterns
        if (line.includes('Math.floor(Math.random()') ||
            line.includes('Math.ceil(Math.random()') ||
            line.includes('Math.round(Math.random()')) {
          this.findings.push({
            file: filePath,
            line: lineNumber,
            code: line.trim(),
            issue: 'Insecure random generation using Math.random() with rounding',
            suggestedFix: 'Replace with crypto.randomBytes() or SecureRandom.generateRandomInt()'
          });
        }
      }
    } catch (error) {
      console.error(`Error auditing file ${filePath}:`, error);
    }
  }

  /**
   * Prints the audit results
   */
  printResults(findings: RandomUsageFinding[]): void {
    if (findings.length === 0) {
      console.log('✅ No insecure random usage found!');
      return;
    }

    console.log(`⚠️  Found ${findings.length} potential issues with random number generation:\n`);

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
  generateReport(findings: RandomUsageFinding[]): string {
    const totalFindings = findings.length;
    const filesAffected = [...new Set(findings.map(f => f.file))].length;
    
    let report = '# Random Usage Audit Report\n\n';
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
      report += `No insecure random usage detected. All random generation appears to use secure methods.\n`;
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

  console.log(`Auditing directory: ${directory}\n`);

  const auditor = new RandomUsageAuditor();
  const findings = await auditor.auditDirectory(directory);

  auditor.printResults(findings);

  // Generate and save report
  const report = auditor.generateReport(findings);
  const reportPath = path.join(process.cwd(), 'random-audit-report.md');
  await fs.promises.writeFile(reportPath, report, 'utf8');
  console.log(`Audit report saved to: ${reportPath}`);
}

// Run the main function
main().catch(error => {
  console.error('Error during audit:', error);
  process.exit(1);
});