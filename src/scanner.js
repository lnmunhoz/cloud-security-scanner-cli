import { google } from 'googleapis';
import ora from 'ora';

export class DriveScanner {
  constructor(auth) {
    this.drive = google.drive({ version: 'v3', auth });
    this.vulnerableFiles = [];
    this.totalFilesScanned = 0;
    this.totalFilesFetched = 0;
  }

  async scanAllFiles() {
    const spinner = ora('Starting Google Drive scan...').start();
    
    try {
      await this.listFiles(null, spinner);
      
      // Sort vulnerable files by severity (HIGH -> MEDIUM -> LOW)
      this.vulnerableFiles.sort((a, b) => {
        const severityOrder = { 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
        const maxSeverityA = Math.max(...a.risks.map(r => severityOrder[r.severity] || 0));
        const maxSeverityB = Math.max(...b.risks.map(r => severityOrder[r.severity] || 0));
        return maxSeverityB - maxSeverityA;
      });
      
      spinner.succeed(`Scan completed! Fetched ${this.totalFilesFetched} files, analyzed ${this.totalFilesScanned} files, found ${this.vulnerableFiles.length} potentially vulnerable files.`);
      return this.vulnerableFiles;
    } catch (error) {
      spinner.fail('Scan failed');
      throw error;
    }
  }

  async listFiles(pageToken = null, spinner = null) {
    const query = "trashed=false";
    
    const response = await this.drive.files.list({
      q: query,
      fields: 'nextPageToken, files(id, name, mimeType, size, modifiedTime, parents)',
      pageSize: 100,
      pageToken: pageToken,
    });

    const files = response.data.files;
    this.totalFilesFetched += files.length;
    
    if (spinner) {
      spinner.text = `Fetched ${this.totalFilesFetched} files, analyzing ${files.length} files in this batch...`;
    }
    
    for (const file of files) {
      this.totalFilesScanned++;
      const risks = this.analyzeFileName(file);
      if (risks.length > 0) {
        const folderPath = await this.getFolderPath(file.id, file.parents);
        this.vulnerableFiles.push({
          file: file,
          risks: risks,
          folderPath: folderPath
        });
      }
      
      // Update spinner every 10 files to show progress
      if (spinner && this.totalFilesScanned % 10 === 0) {
        spinner.text = `Fetched ${this.totalFilesFetched} files, scanned ${this.totalFilesScanned} files, found ${this.vulnerableFiles.length} vulnerable files...`;
      }
    }

    if (response.data.nextPageToken) {
      if (spinner) {
        spinner.text = `Fetched ${this.totalFilesFetched} files so far, fetching next batch...`;
      }
      await this.listFiles(response.data.nextPageToken, spinner);
    }
  }

  analyzeFileName(file) {
    const risks = [];
    const fileName = file.name.toLowerCase();
    
    const riskPatterns = [
      // Critical Security Files
      {
        patterns: [/\.env$/i, /\.environment$/i, /\.env\.local$/i, /\.env\.prod$/i, /\.env\.production$/i],
        type: 'Environment Configuration File',
        severity: 'HIGH',
        description: 'May contain API keys, database passwords, and other secrets'
      },
      {
        patterns: [/\.key$/i, /\.pem$/i, /\.crt$/i, /\.cer$/i, /\.der$/i],
        type: 'Cryptographic Key/Certificate',
        severity: 'HIGH',
        description: 'Private keys or certificates that could grant unauthorized access'
      },
      {
        patterns: [/\.p12$/i, /\.pfx$/i, /\.jks$/i, /\.keystore$/i, /\.truststore$/i],
        type: 'Certificate Store',
        severity: 'HIGH',
        description: 'Encrypted certificate stores that may contain private keys'
      },
      {
        patterns: [/id_rsa$/i, /id_dsa$/i, /id_ecdsa$/i, /id_ed25519$/i, /known_hosts$/i, /authorized_keys$/i],
        type: 'SSH Keys/Config',
        severity: 'HIGH',
        description: 'SSH private keys or configuration files for server access'
      },
      
      // AWS and Cloud Credentials
      {
        patterns: [/\.aws$/i, /credentials$/i, /aws_credentials$/i, /\.s3cfg$/i],
        type: 'AWS/Cloud Credentials',
        severity: 'HIGH',
        description: 'Cloud service credentials for AWS, S3, or other providers'
      },
      {
        patterns: [/gcloud$/i, /\.gcp$/i, /service[_-]account\.json$/i, /firebase[_-]adminsdk/i],
        type: 'Google Cloud Credentials',
        severity: 'HIGH',
        description: 'Google Cloud Platform or Firebase service account keys'
      },
      {
        patterns: [/\.azure$/i, /azure[_-]credentials$/i, /\.azureProfile$/i],
        type: 'Azure Credentials',
        severity: 'HIGH',
        description: 'Microsoft Azure authentication credentials'
      },
      
      // Password and Authentication Files
      {
        patterns: [/password/i, /passwd/i, /pwd/i, /login/i, /auth/i],
        type: 'Password/Authentication File',
        severity: 'HIGH',
        description: 'Filename suggests it contains passwords or authentication data'
      },
      {
        patterns: [/secret/i, /credential/i, /token/i, /api[_-]key/i],
        type: 'Secrets/API Keys',
        severity: 'HIGH',
        description: 'Filename suggests it contains authentication secrets or API keys'
      },
      {
        patterns: [/\.htpasswd$/i, /\.netrc$/i, /\.pgpass$/i],
        type: 'System Password Files',
        severity: 'HIGH',
        description: 'System files containing authentication credentials'
      },
      
      // Database Files
      {
        patterns: [/\.sql$/i, /\.dump$/i, /\.db$/i, /\.sqlite$/i, /\.sqlite3$/i],
        type: 'Database File',
        severity: 'MEDIUM',
        description: 'Database files may contain sensitive user data'
      },
      {
        patterns: [/\.mdb$/i, /\.accdb$/i, /\.dbf$/i, /\.fdb$/i],
        type: 'Desktop Database',
        severity: 'MEDIUM',
        description: 'Desktop database files may contain sensitive information'
      },
      
      // Backup and Archive Files
      {
        patterns: [/\.bak$/i, /backup/i, /\.old$/i, /\.orig$/i, /\.save$/i],
        type: 'Backup File',
        severity: 'MEDIUM',
        description: 'Backup files may contain outdated but sensitive information'
      },
      {
        patterns: [/\.tar$/i, /\.zip$/i, /\.7z$/i, /\.rar$/i, /\.gz$/i, /\.tgz$/i],
        type: 'Archive File',
        severity: 'LOW',
        description: 'Compressed archives may contain sensitive files'
      },
      
      // Configuration Files
      {
        patterns: [/config$/i, /\.config$/i, /\.conf$/i, /\.ini$/i, /\.cfg$/i],
        type: 'Configuration File',
        severity: 'MEDIUM',
        description: 'Configuration files may contain sensitive settings'
      },
      {
        patterns: [/\.properties$/i, /\.settings$/i, /\.plist$/i],
        type: 'Application Settings',
        severity: 'MEDIUM',
        description: 'Application settings files may contain API keys or passwords'
      },
      
      // Development and Source Code
      {
        patterns: [/\.git$/i, /\.svn$/i, /\.hg$/i],
        type: 'Version Control Directory',
        severity: 'MEDIUM',
        description: 'Version control directories may expose source code history'
      },
      {
        patterns: [/dockerfile$/i, /docker-compose/i, /\.dockerignore$/i],
        type: 'Docker Configuration',
        severity: 'LOW',
        description: 'Docker files may contain build secrets or configuration'
      },
      
      // Financial and Personal Data
      {
        patterns: [/tax/i, /salary/i, /payroll/i, /invoice/i, /receipt/i],
        type: 'Financial Document',
        severity: 'MEDIUM',
        description: 'Financial documents contain sensitive personal/business data'
      },
      {
        patterns: [/social[_-]security/i, /ssn/i, /passport/i, /license/i],
        type: 'Identity Document',
        severity: 'HIGH',
        description: 'Identity documents contain personally identifiable information'
      },
      {
        patterns: [/medical/i, /health/i, /patient/i, /diagnosis/i],
        type: 'Medical Record',
        severity: 'HIGH',
        description: 'Medical records contain protected health information'
      },
      
      // Communication and Email
      {
        patterns: [/\.pst$/i, /\.ost$/i, /\.mbox$/i, /\.eml$/i],
        type: 'Email Archive',
        severity: 'MEDIUM',
        description: 'Email archives may contain sensitive communications'
      },
      {
        patterns: [/\.msg$/i, /mailbox/i, /messages/i],
        type: 'Email/Message File',
        severity: 'MEDIUM',
        description: 'Email or message files may contain private communications'
      },
      
      // Application-Specific
      {
        patterns: [/\.npmrc$/i, /\.pypirc$/i, /\.gemrc$/i, /composer\.json$/i],
        type: 'Package Manager Config',
        severity: 'MEDIUM',
        description: 'Package manager configs may contain registry credentials'
      },
      {
        patterns: [/\.kdbx$/i, /\.kdb$/i, /keychain$/i, /vault/i],
        type: 'Password Manager File',
        severity: 'HIGH',
        description: 'Password manager databases contain encrypted credentials'
      },
      {
        patterns: [/\.rdp$/i, /\.vnc$/i, /\.teamviewer$/i],
        type: 'Remote Access Config',
        severity: 'MEDIUM',
        description: 'Remote access configuration files may contain connection details'
      },
      
      // Log Files
      {
        patterns: [/\.log$/i, /error/i, /debug/i, /trace/i],
        type: 'Log File',
        severity: 'LOW',
        description: 'Log files may accidentally contain sensitive information'
      },
      
      // Miscellaneous Sensitive Files
      {
        patterns: [/private/i, /confidential/i, /internal/i, /restricted/i],
        type: 'Classified File',
        severity: 'MEDIUM',
        description: 'File marked as private/confidential may contain sensitive information'
      },
      {
        patterns: [/\.json$/i, /\.xml$/i, /\.yml$/i, /\.yaml$/i, /\.toml$/i],
        type: 'Structured Config File',
        severity: 'LOW',
        description: 'Structured configuration files may contain sensitive data'
      },
      {
        patterns: [/core$/i, /crash/i, /minidump/i, /\.dmp$/i],
        type: 'System Crash/Core Dump',
        severity: 'MEDIUM',
        description: 'System dumps may contain memory with sensitive data'
      },
      {
        patterns: [/history$/i, /\.bash_history$/i, /\.zsh_history$/i, /\.history$/i],
        type: 'Command History',
        severity: 'MEDIUM',
        description: 'Command history may contain passwords typed in commands'
      }
    ];

    riskPatterns.forEach(({ patterns, type, severity, description }) => {
      if (patterns.some(pattern => pattern.test(file.name))) {
        risks.push({
          type,
          severity,
          description,
          fileName: file.name
        });
      }
    });

    return risks;
  }

  async getFolderPath(fileId, parentIds = []) {
    if (!parentIds || parentIds.length === 0) {
      return '/';
    }

    try {
      const response = await this.drive.files.get({
        fileId: parentIds[0],
        fields: 'name, parents'
      });

      const folder = response.data;
      const path = folder.parents ? 
        await this.getFolderPath(folder.id, folder.parents) + folder.name + '/' :
        folder.name + '/';
      
      return path;
    } catch (error) {
      return '/';
    }
  }
}