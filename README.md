# Cloud Security Scanner

A Node.js tool that scans your cloud storage (Google Drive and Dropbox) for potentially vulnerable files containing passwords, API keys, private keys, and other sensitive information.

## Features

- 🔍 **Comprehensive Scanning**: Detects various types of sensitive data including:

  - AWS Access Keys and Secret Keys
  - Google API Keys
  - GitHub Tokens
  - Private Keys (RSA, EC, DSA, PGP, OpenSSH)
  - Database Connection Strings
  - JWT Tokens
  - Slack Tokens
  - Generic API Keys and Secrets
  - Password fields

- ☁️ **Multi-Cloud Support**:
  - Google Drive
  - Dropbox

- 📊 **Multiple Output Formats**:
  - Console (colored table output)
  - JSON export
  - CSV export
  - Markdown export

- 🌲 **File Tree Visualization**: Generates complete file tree structure
- 💾 **Smart Caching**: Provider-specific caching to avoid re-scanning
- 🛡️ **Security-First**: Read-only access to your cloud storage, no data modification

## Installation

1. Clone or download this project
2. Install dependencies:
   ```bash
   npm install
   ```

## Setup

### Google Drive Setup

1. **Create a Google Cloud Project**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select an existing one

2. **Enable Google Drive API**
   - Navigate to APIs & Services > Library
   - Search for "Google Drive API" and enable it

3. **Create OAuth 2.0 Credentials**
   - Go to APIs & Services > Credentials
   - Click "Create Credentials" > "OAuth client ID"
   - Choose "Desktop application"
   - Download the JSON file

4. **Save Credentials**
   - Create a `config/` folder in the project root
   - Save the downloaded file as `config/google-credentials.json`

### Dropbox Setup

1. **Create a Dropbox App**
   - Go to [Dropbox App Console](https://www.dropbox.com/developers/apps)
   - Click "Create app"

2. **Configure Your App**
   - Choose "Scoped access"
   - Choose "Full Dropbox" access
   - Name your app (e.g., "Security Scanner")

3. **Configure OAuth Settings**
   - In the app settings, under "OAuth 2" section
   - Add this redirect URI: `http://localhost:8080/dropbox/callback`
   - Note your App key and App secret

4. **Save Credentials**
   - Create `config/dropbox-config.json` with:
   ```json
   {
     "clientId": "your-app-key",
     "clientSecret": "your-app-secret"
   }
   ```

### Quick Setup

Run the setup command for guided instructions:

```bash
# Google Drive setup instructions
npm start setup

# Dropbox setup instructions
npm start setup --provider dropbox
```

## Usage

### Provider Selection

If you don't specify a provider, the tool will prompt you to choose:

```bash
npm start scan
```

### Google Drive Scan

```bash
npm start scan --provider google
```

### Dropbox Scan

```bash
npm start scan --provider dropbox
```

### Export Options

```bash
# Export to JSON
npm start scan --output json

# Export to CSV
npm start scan --output csv

# Export to Markdown
npm start scan --output markdown
```

### Caching Options

```bash
# Use cached results (skip new scan)
npm start scan --use-cache

# Disable saving to cache
npm start scan --no-cache
```

### Other Options

```bash
# Disable colored output
npm start scan --no-color
```

## First Run

On the first run for each provider, the tool will:

1. Open your browser for OAuth authentication
2. Ask you to authorize the application
3. Save access tokens for future use
4. Ask for confirmation before starting the scan

## File Organization

The tool organizes files in the following structure:

```
project-root/
├── config/
│   ├── google-credentials.json    # Google OAuth credentials
│   ├── dropbox-config.json        # Dropbox app credentials
│   ├── tokens.json                # Unified token storage
│   ├── google-scan-cache.json     # Google Drive scan cache
│   └── dropbox-scan-cache.json    # Dropbox scan cache
└── reports/
    ├── drive-scan-*.json          # Google Drive reports
    └── dropbox-scan-*.json        # Dropbox reports
```

## Security Considerations

- **Read-Only Access**: This tool only requests read access to your cloud storage
- **Local Processing**: All file analysis happens locally on your machine
- **No Data Transmission**: Sensitive data is not sent to external servers
- **Credential Security**: All credential and token files are gitignored
- **Provider Isolation**: Each provider has separate tokens and cache files

## What It Scans

The tool analyzes file names and paths to identify potentially sensitive files:

- `.env` files and environment configurations
- `.key`, `.pem`, `.p12` certificate files
- Configuration files (`.conf`, `.config`, `.ini`, `.properties`)
- Database files and connection strings
- Files with suspicious names (password, secret, credential, api-key, etc.)
- Backup files and exports
- Development and test files that might contain secrets

## Output

The scanner provides:

- **File Details**: Name, type, size, modification date, full path
- **Vulnerability Type**: Specific type of sensitive data pattern matched
- **Severity Level**: HIGH, MEDIUM, or LOW risk assessment
- **Complete File Tree**: Full directory structure of your cloud storage
- **Scan Summary**: Total files scanned, vulnerabilities found, scan duration

## Example Output

```
🔍 Google Drive Security Scanner
Provider: Google Drive
Output format: CONSOLE

✅ Google Drive authentication successful
📋 Ready to scan your Google Drive

🔍 GOOGLE DRIVE SECURITY SCAN RESULTS
============================================================
❌ Found 3 potentially vulnerable files:
   • HIGH: 2
   • MEDIUM: 1
   • LOW: 0

┌────────────────────────────────┬─────────────────────────┬──────────┬───────────────────────────────────┐
│ File Name                      │ Vulnerability Type      │ Severity │ Path                              │
├────────────────────────────────┼─────────────────────────┼──────────┼───────────────────────────────────┤
│ .env                          │ Environment Config File │ HIGH     │ /projects/.env                    │
│ database-backup.sql           │ Database File           │ HIGH     │ /backups/database-backup.sql      │
│ api-keys.txt                  │ Suspicious Filename     │ MEDIUM   │ /docs/api-keys.txt                │
└────────────────────────────────┴─────────────────────────┴──────────┴───────────────────────────────────┘

📊 Scan completed in 2.3 seconds
📁 File tree and detailed results saved to: reports/drive-scan-1672531200000.json
```

## Report Files

Reports include:
- **Vulnerable Files**: Detailed list of potential security risks
- **File Tree**: Complete directory structure
- **Scan Metadata**: Timestamp, provider, scan duration, file counts

Reports are automatically saved with provider-specific prefixes:
- `reports/drive-scan-[timestamp].json` for Google Drive
- `reports/dropbox-scan-[timestamp].json` for Dropbox

## License

MIT