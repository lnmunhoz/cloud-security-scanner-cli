# Google Drive Security Scanner

A Node.js tool that scans your Google Drive for potentially vulnerable files containing passwords, API keys, private keys, and other sensitive information.

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

- 📊 **Multiple Output Formats**:

  - Console (colored table output)
  - JSON export
  - CSV export

- 🛡️ **Security-First**: Read-only access to your Google Drive, no data modification

## Installation

1. Clone or download this project
2. Install dependencies:
   ```bash
   npm install
   ```

## Setup

Before using the scanner, you need to set up Google Drive API credentials:

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

   - Rename the downloaded file to `credentials.json`
   - Place it in the project root directory

5. **Run Setup Command** (optional)
   ```bash
   npm start setup
   ```

## Usage

### Basic Scan

```bash
npm start scan
```

### Export to JSON

```bash
npm start scan --output json
```

### Export to CSV

```bash
npm start scan --output csv
```

### Disable Colors

```bash
npm start scan --no-color
```

## First Run

On the first run, the tool will:

1. Open your browser for Google OAuth authentication
2. Ask you to authorize the application
3. Save an access token for future use

## Security Considerations

- **Read-Only Access**: This tool only requests read access to your Google Drive
- **Local Processing**: All file analysis happens locally on your machine
- **No Data Transmission**: Sensitive data is not sent to external servers
- **Credential Security**: Your `credentials.json` and `token.json` are gitignored

## What It Scans

The tool focuses on files that commonly contain sensitive information:

- `.env` files
- `.key` files
- `.pem` certificates
- Configuration files (`.conf`, `.config`, `.ini`, `.properties`)
- Text files and documents
- JSON, XML, YAML files
- Files with suspicious names (password, secret, credential, etc.)

## Output

The scanner provides:

- **File Details**: Name, type, size, modification date
- **Vulnerability Type**: Specific type of sensitive data found
- **Severity Level**: HIGH, MEDIUM, or LOW
- **Content Preview**: First few characters of the match
- **Security Recommendations**: Best practices for remediation

## Example Output

```
🔍 GOOGLE DRIVE SECURITY SCAN RESULTS
============================================================
❌ Found 3 potentially vulnerable files:
   • HIGH: 2
   • MEDIUM: 1
   • LOW: 0

┌────────────────────────────────┬─────────────────────────┬──────────┬───────────────────────────────────┐
│ File Name                      │ Vulnerability Type      │ Severity │ Preview                           │
├────────────────────────────────┼─────────────────────────┼──────────┼───────────────────────────────────┤
│ .env                          │ AWS Access Key          │ HIGH     │ AKIA1234567890123456              │
│ config.json                   │ Database Connection     │ HIGH     │ mongodb://user:pass@localhost...  │
│ backup.txt                    │ Password Field          │ MEDIUM   │ password=mySecretPassword123      │
└────────────────────────────────┴─────────────────────────┴──────────┴───────────────────────────────────┘
```

## License

MIT
