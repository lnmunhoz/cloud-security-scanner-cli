#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { authenticate } from './auth.js';
import { DriveScanner } from './scanner.js';
import { Reporter } from './reporter.js';

const program = new Command();

program
  .name('google-drive-scanner')
  .description('Scan Google Drive for potentially vulnerable files containing passwords, API keys, and other sensitive data')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan Google Drive for vulnerable files')
  .option('-o, --output <format>', 'Output format (console, json, csv, markdown)', 'console')
  .option('--no-color', 'Disable colored output')
  .action(async (options) => {
    try {
      console.log(chalk.blue.bold('🔍 Google Drive Security Scanner'));
      console.log(chalk.gray(`Output format: ${options.output.toUpperCase()}`));
      console.log(chalk.gray('Initializing authentication...'));

      const auth = await authenticate();
      console.log(chalk.green('✅ Authentication successful'));

      const scanner = new DriveScanner(auth);
      const vulnerableFiles = await scanner.scanAllFiles();

      const reporter = new Reporter();
      await reporter.generateReport(vulnerableFiles, options.output);

    } catch (error) {
      console.error(chalk.red('❌ Error:'), error.message);
      process.exit(1);
    }
  });

program
  .command('setup')
  .description('Setup Google Drive API credentials')
  .action(() => {
    console.log(chalk.blue.bold('🔧 Setup Instructions'));
    console.log();
    console.log('To use this tool, you need to set up Google Drive API credentials:');
    console.log();
    console.log(chalk.yellow('1. Go to the Google Cloud Console:'));
    console.log('   https://console.cloud.google.com/');
    console.log();
    console.log(chalk.yellow('2. Create a new project or select an existing one'));
    console.log();
    console.log(chalk.yellow('3. Enable the Google Drive API:'));
    console.log('   https://console.cloud.google.com/apis/library/drive.googleapis.com');
    console.log();
    console.log(chalk.yellow('4. Create credentials (OAuth 2.0 Client ID):'));
    console.log('   - Go to APIs & Services > Credentials');
    console.log('   - Click "Create Credentials" > "OAuth client ID"');
    console.log('   - Choose "Desktop application"');
    console.log('   - Name it something like "Drive Scanner"');
    console.log('   - Download the JSON file');
    console.log();
    console.log(chalk.yellow('5. Save the downloaded file as "credentials.json" in this directory'));
    console.log();
    console.log(chalk.yellow('6. Run: npm start scan'));
    console.log();
    console.log(chalk.blue('Usage Examples:'));
    console.log('  npm start scan                    # Console output');
    console.log('  npm start scan --output json      # Export to JSON');
    console.log('  npm start scan --output csv       # Export to CSV');
    console.log('  npm start scan --output markdown  # Generate markdown report');
    console.log();
    console.log(chalk.green('Note: This tool only requires read-only access to your Google Drive.'));
  });

if (process.argv.length === 2) {
  program.help();
}

program.parse();