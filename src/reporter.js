import chalk from 'chalk';
import Table from 'cli-table3';
import fs from 'fs/promises';

export class Reporter {
  constructor() {
    this.vulnerableFiles = [];
  }

  async generateReport(scanResults, outputFormat = 'console') {
    // Handle both old format (array) and new format (object with vulnerableFiles)
    if (Array.isArray(scanResults)) {
      this.vulnerableFiles = scanResults;
      this.fileTree = null;
      this.summary = null;
    } else {
      this.vulnerableFiles = scanResults.vulnerableFiles || [];
      this.fileTree = scanResults.fileTree || null;
      this.summary = scanResults.summary || null;
    }

    switch (outputFormat) {
      case 'console':
        this.printConsoleReport();
        break;
      case 'json':
        await this.generateJSONReport();
        break;
      case 'csv':
        await this.generateCSVReport();
        break;
      case 'markdown':
        await this.generateMarkdownReport();
        break;
      default:
        this.printConsoleReport();
    }
  }

  printConsoleReport() {
    console.log('\n' + chalk.bold.red('🔍 GOOGLE DRIVE SECURITY SCAN RESULTS'));
    console.log(chalk.gray('=' .repeat(60)));

    if (this.vulnerableFiles.length === 0) {
      console.log(chalk.green('✅ No vulnerable files detected!'));
      return;
    }

    const severityCounts = this.getSeverityCounts();
    console.log(chalk.red(`❌ Found ${this.vulnerableFiles.length} potentially vulnerable files:`));
    console.log(chalk.red(`   • HIGH: ${severityCounts.HIGH}`));
    console.log(chalk.yellow(`   • MEDIUM: ${severityCounts.MEDIUM}`));
    console.log(chalk.blue(`   • LOW: ${severityCounts.LOW}`));
    console.log();

    const table = new Table({
      head: [
        chalk.bold('File Path'),
        chalk.bold('File Name'),
        chalk.bold('Risk Type'),
        chalk.bold('Severity')
      ],
      colWidths: [40, 25, 30, 10],
      wordWrap: true
    });

    this.vulnerableFiles.forEach(({ file, risks, folderPath }) => {
      risks.forEach(risk => {
        const severityColor = this.getSeverityColor(risk.severity);
        const displayPath = folderPath && folderPath !== '/' ? folderPath : '/';
        table.push([
          chalk.gray(displayPath),
          file.name,
          risk.type,
          severityColor(risk.severity)
        ]);
      });
    });

    console.log(table.toString());
    console.log();
    
    // Print file tree if available
    if (this.fileTree) {
      console.log(chalk.bold.cyan('\n📁 FILE TREE STRUCTURE:'));
      console.log(chalk.gray('=' .repeat(60)));
      this.printFileTree(this.fileTree);
      console.log();
    }
    
    this.printRecommendations();
  }

  printFileTree(node, prefix = '', isLast = true) {
    if (node.type === 'folder') {
      console.log(prefix + (isLast ? '└── ' : '├── ') + chalk.blue.bold('📁 ' + node.name));
      const children = Object.values(node.children || {});
      children.forEach((child, index) => {
        const isChildLast = index === children.length - 1;
        const newPrefix = prefix + (isLast ? '    ' : '│   ');
        this.printFileTree(child, newPrefix, isChildLast);
      });
    } else {
      const icon = this.getFileIcon(node.name);
      console.log(prefix + (isLast ? '└── ' : '├── ') + icon + ' ' + node.name);
    }
  }

  getFileIcon(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const icons = {
      'env': '🔐',
      'key': '🔑',
      'pem': '🔑',
      'json': '📋',
      'xml': '📋',
      'yml': '📋',
      'yaml': '📋',
      'sql': '🗄️',
      'db': '🗄️',
      'bak': '💾',
      'zip': '📦',
      'tar': '📦',
      'gz': '📦',
      'log': '📝',
      'txt': '📄',
      'doc': '📄',
      'docx': '📄',
      'pdf': '📄',
      'xls': '📊',
      'xlsx': '📊',
      'csv': '📊'
    };
    return icons[ext] || '📄';
  }

  async generateJSONReport() {
    const report = {
      timestamp: new Date().toISOString(),
      summary: {
        totalFiles: this.vulnerableFiles.length,
        severityCounts: this.getSeverityCounts()
      },
      vulnerabilities: this.vulnerableFiles.map(({ file, risks }) => ({
        file: {
          id: file.id,
          name: file.name,
          mimeType: file.mimeType,
          size: file.size,
          modifiedTime: file.modifiedTime
        },
        risks: risks
      }))
    };

    const provider = this.getProviderPrefix();
    const filename = `${provider}-scan-${Date.now()}.json`;
    await fs.writeFile(filename, JSON.stringify(report, null, 2));
    console.log(chalk.green(`📄 JSON report saved to: ${filename}`));
  }

  async generateCSVReport() {
    const headers = 'File Path,File Name,File ID,Risk Type,Severity,Description,Modified Time\n';
    let csvContent = headers;

    this.vulnerableFiles.forEach(({ file, risks, folderPath }) => {
      risks.forEach(risk => {
        const displayPath = folderPath && folderPath !== '/' ? folderPath : '/';
        const row = [
          `"${displayPath.replace(/"/g, '""')}"`,
          `"${file.name.replace(/"/g, '""')}"`,
          file.id,
          `"${risk.type}"`,
          risk.severity,
          `"${risk.description.substring(0, 50).replace(/"/g, '""')}"`,
          file.modifiedTime
        ].join(',');
        csvContent += row + '\n';
      });
    });

    const provider = this.getProviderPrefix();
    const filename = `${provider}-scan-${Date.now()}.csv`;
    await fs.writeFile(filename, csvContent);
    console.log(chalk.green(`📊 CSV report saved to: ${filename}`));
  }

  async generateMarkdownReport() {
    const timestamp = new Date().toISOString();
    const severityCounts = this.getSeverityCounts();
    
    let markdown = `# 🔍 Google Drive Security Scan Report

Generated on: ${new Date().toLocaleString()}

## 📊 Executive Summary

`;

    if (this.vulnerableFiles.length === 0) {
      markdown += `✅ **No vulnerable files detected!**

Your Google Drive appears to be free of commonly risky file types.

`;
    } else {
      markdown += `❌ **Found ${this.vulnerableFiles.length} potentially vulnerable files:**

- 🔴 **HIGH**: ${severityCounts.HIGH} files
- 🟡 **MEDIUM**: ${severityCounts.MEDIUM} files  
- 🔵 **LOW**: ${severityCounts.LOW} files

`;
    }

    if (this.vulnerableFiles.length > 0) {
      markdown += `## 🚨 Vulnerable Files

| File Path | File Name | Risk Type | Severity | Description |
|-----------|-----------|-----------|----------|-------------|
`;

      this.vulnerableFiles.forEach(({ file, risks, folderPath }) => {
        risks.forEach(risk => {
          const displayPath = folderPath && folderPath !== '/' ? folderPath : '/';
          const severityIcon = this.getSeverityIcon(risk.severity);
          markdown += `| ${displayPath} | \`${file.name}\` | ${risk.type} | ${severityIcon} ${risk.severity} | ${risk.description} |\n`;
        });
      });

      markdown += `
## 🛡️ Security Recommendations

### Immediate Actions Required

1. **Review HIGH severity files immediately** - These pose the greatest security risk
2. **Move sensitive files to secure storage** - Consider using encrypted cloud storage or password managers
3. **Remove or secure credential files** - Never store plaintext passwords or API keys in cloud storage
4. **Enable 2FA on your Google Account** - Add an extra layer of security to your account

### Best Practices

- **Environment Variables**: Use environment variables instead of hardcoded secrets
- **Password Managers**: Store passwords in dedicated password managers (1Password, Bitwarden, etc.)
- **File Permissions**: Regularly review and audit file sharing permissions
- **Regular Audits**: Run this scanner periodically to catch new risky files
- **Secure Alternatives**: Use Google Secret Manager or similar services for application secrets

### File-Specific Recommendations

`;

      // Group recommendations by severity
      const highRiskFiles = this.vulnerableFiles.filter(({ risks }) => 
        risks.some(r => r.severity === 'HIGH'));
      const mediumRiskFiles = this.vulnerableFiles.filter(({ risks }) => 
        risks.some(r => r.severity === 'MEDIUM') && !risks.some(r => r.severity === 'HIGH'));
      const lowRiskFiles = this.vulnerableFiles.filter(({ risks }) => 
        risks.every(r => r.severity === 'LOW'));

      if (highRiskFiles.length > 0) {
        markdown += `#### 🔴 HIGH Priority Files (${highRiskFiles.length} files)
These files require immediate attention:

`;
        highRiskFiles.forEach(({ file, folderPath }) => {
          const displayPath = folderPath && folderPath !== '/' ? folderPath : '/';
          markdown += `- **${file.name}** in \`${displayPath}\` - Should be moved to secure storage immediately\n`;
        });
        markdown += '\n';
      }

      if (mediumRiskFiles.length > 0) {
        markdown += `#### 🟡 MEDIUM Priority Files (${mediumRiskFiles.length} files)
Review these files when convenient:

`;
        mediumRiskFiles.forEach(({ file, folderPath }) => {
          const displayPath = folderPath && folderPath !== '/' ? folderPath : '/';
          markdown += `- **${file.name}** in \`${displayPath}\` - Review content and consider if it should be stored elsewhere\n`;
        });
        markdown += '\n';
      }

      if (lowRiskFiles.length > 0) {
        markdown += `#### 🔵 LOW Priority Files (${lowRiskFiles.length} files)
Monitor these files for any sensitive content:

`;
        lowRiskFiles.forEach(({ file, folderPath }) => {
          const displayPath = folderPath && folderPath !== '/' ? folderPath : '/';
          markdown += `- **${file.name}** in \`${displayPath}\` - Generally safe but monitor for sensitive content\n`;
        });
        markdown += '\n';
      }
    }

    markdown += `## 📋 Scan Details

- **Scan Date**: ${new Date().toLocaleString()}
- **Total Files Found**: ${this.vulnerableFiles.length}
- **Scanner Version**: 1.0.0
- **Scan Scope**: All non-trashed files in Google Drive

## 🔐 About This Scan

This security scan analyzes Google Drive file names to identify potentially sensitive files that may pose security risks if compromised. The scanner looks for common patterns associated with:

- Credentials and API keys
- Private keys and certificates  
- Database dumps and backups
- Configuration files
- Personal documents
- System files

**Note**: This scan only analyzes file names and metadata - no file contents are read or transmitted.

---
*Generated by Google Drive Security Scanner*
`;

    const provider = this.getProviderPrefix();
    const filename = `${provider}-scan-report-${Date.now()}.md`;
    await fs.writeFile(filename, markdown);
    console.log(chalk.green(`📄 Markdown report saved to: ${filename}`));
  }

  getSeverityCounts() {
    const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    
    this.vulnerableFiles.forEach(({ risks }) => {
      risks.forEach(risk => {
        counts[risk.severity]++;
      });
    });

    return counts;
  }

  getSeverityColor(severity) {
    switch (severity) {
      case 'HIGH':
        return chalk.red.bold;
      case 'MEDIUM':
        return chalk.yellow.bold;
      case 'LOW':
        return chalk.blue.bold;
      default:
        return chalk.white;
    }
  }

  getSeverityIcon(severity) {
    switch (severity) {
      case 'HIGH':
        return '🔴';
      case 'MEDIUM':
        return '🟡';
      case 'LOW':
        return '🔵';
      default:
        return '⚪';
    }
  }

  getProviderPrefix() {
    // Determine provider from summary or file tree name
    if (this.summary && this.summary.provider) {
      return this.summary.provider.includes('Dropbox') ? 'dropbox' : 'drive';
    }
    
    if (this.fileTree && this.fileTree.name) {
      return this.fileTree.name === 'Dropbox' ? 'dropbox' : 'drive';
    }
    
    // Default to drive for backward compatibility
    return 'drive';
  }

  printRecommendations() {
    console.log(chalk.bold.yellow('🛡️  SECURITY RECOMMENDATIONS:'));
    console.log();
    console.log(chalk.yellow('1. Review all HIGH severity findings immediately'));
    console.log(chalk.yellow('2. Move sensitive files to a secure location'));
    console.log(chalk.yellow('3. Use environment variables for secrets instead of hardcoding'));
    console.log(chalk.yellow('4. Enable 2FA on your Google Account'));
    console.log(chalk.yellow('5. Regularly audit file permissions and sharing settings'));
    console.log(chalk.yellow('6. Consider using a password manager for credentials'));
    console.log();
  }
}