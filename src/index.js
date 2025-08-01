#!/usr/bin/env node

import { Command } from "commander";
import chalk from "chalk";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { authenticate } from "./google-auth.js";
import { authenticateDropbox } from "./dropbox-auth.js";
import { DriveScanner } from "./google-scanner.js";
import { DropboxScanner } from "./dropbox-scanner.js";
import { Reporter } from "./reporter.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getCachePath(provider) {
  return path.join(__dirname, "..", "config", `${provider}-scan-cache.json`);
}

const program = new Command();

program
  .name("cloud-security-scanner")
  .description(
    "Scan Google Drive or Dropbox for potentially vulnerable files containing passwords, API keys, and other sensitive data"
  )
  .version("1.0.0");

program
  .command("scan")
  .description("Scan cloud storage for vulnerable files")
  .option("-p, --provider <provider>", "Cloud provider (google or dropbox)")
  .option(
    "-o, --output <format>",
    "Output format (console, json, csv, markdown)",
    "console"
  )
  .option("--no-color", "Disable colored output")
  .option(
    "--use-cache",
    "Use cached scan results instead of performing a new scan"
  )
  .option("--no-cache", "Skip saving scan results to cache")
  .action(async (options) => {
    try {
      // If no provider specified, ask user to choose
      if (!options.provider) {
        console.log(chalk.blue.bold("🔍 Cloud Security Scanner"));
        console.log(chalk.yellow("Please select a cloud provider to scan:"));
        console.log();
        console.log(chalk.cyan("1. Google Drive"));
        console.log(chalk.cyan("2. Dropbox"));
        console.log();

        const { default: readline } = await import("readline");
        const rl = readline.createInterface({
          input: process.stdin,
          output: process.stdout,
        });

        const choice = await new Promise((resolve) => {
          rl.question(chalk.bold("Enter your choice (1 or 2): "), (answer) => {
            rl.close();
            resolve(answer.trim());
          });
        });

        if (choice === "1") {
          options.provider = "google";
        } else if (choice === "2") {
          options.provider = "dropbox";
        } else {
          console.log(
            chalk.red(
              "\n❌ Invalid choice. Please run the command again and select 1 or 2."
            )
          );
          process.exit(1);
        }

        console.log(); // Add spacing
      }

      const providerName =
        options.provider === "dropbox" ? "Dropbox" : "Google Drive";
      console.log(chalk.blue.bold(`🔍 ${providerName} Security Scanner`));
      console.log(chalk.gray(`Provider: ${providerName}`));
      console.log(chalk.gray(`Output format: ${options.output.toUpperCase()}`));

      let scanResults;

      // Check if using cached results
      if (options.useCache) {
        try {
          console.log(chalk.gray("Loading cached scan results..."));
          const cachePath = getCachePath(options.provider);
          const cacheContent = await fs.readFile(cachePath, "utf8");
          scanResults = JSON.parse(cacheContent);
          console.log(
            chalk.green(
              `✅ Loaded cached scan from ${new Date(
                scanResults.summary.scanDate
              ).toLocaleString()}`
            )
          );
        } catch (error) {
          console.log(
            chalk.yellow("⚠️  No cache found. Performing new scan...")
          );
          options.useCache = false;
        }
      }

      // Perform new scan if not using cache
      if (!options.useCache) {
        console.log(chalk.gray("Initializing authentication..."));

        let scanner;
        let isNewAuth;

        if (options.provider === "dropbox") {
          const { dbx, isNewAuth: newAuth } = await authenticateDropbox();
          isNewAuth = newAuth;
          console.log(chalk.green("✅ Dropbox authentication successful"));
          scanner = new DropboxScanner(dbx);
        } else {
          const { oAuth2Client, isNewAuth: newAuth } = await authenticate();
          isNewAuth = newAuth;
          console.log(chalk.green("✅ Google Drive authentication successful"));
          scanner = new DriveScanner(oAuth2Client);
        }

        // Only ask for confirmation if this is a new authorization
        if (isNewAuth) {
          console.log(
            "\n" + chalk.yellow(`📋 Ready to scan your ${providerName}`)
          );
          console.log(
            chalk.gray(
              `This will analyze all file names in your ${providerName} to identify potentially sensitive files.`
            )
          );
          console.log(
            chalk.gray("No file contents will be downloaded or analyzed.")
          );

          const { default: readline } = await import("readline");
          const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
          });

          const proceed = await new Promise((resolve) => {
            rl.question(
              "\n" + chalk.bold("Do you want to start the scan? (yes/no): "),
              (answer) => {
                rl.close();
                resolve(
                  answer.toLowerCase() === "yes" || answer.toLowerCase() === "y"
                );
              }
            );
          });

          if (!proceed) {
            console.log(chalk.yellow("\n⚠️  Scan cancelled by user"));
            process.exit(0);
          }
        }

        scanResults = await scanner.scanAllFiles();

        // Save to cache unless disabled
        if (options.cache !== false) {
          try {
            const cachePath = getCachePath(options.provider);
            await fs.writeFile(
              cachePath,
              JSON.stringify(scanResults, null, 2)
            );
            console.log(chalk.gray("💾 Scan results saved to cache"));
          } catch (error) {
            console.warn(
              chalk.yellow("⚠️  Could not save cache:", error.message)
            );
          }
        }
      }

      const reporter = new Reporter();
      await reporter.generateReport(scanResults, options.output);
    } catch (error) {
      console.error(chalk.red("❌ Error:"), error.message);
      process.exit(1);
    }
  });

program
  .command("setup")
  .description("Setup cloud provider API credentials")
  .option(
    "-p, --provider <provider>",
    "Cloud provider (google or dropbox)",
    "google"
  )
  .action((options) => {
    console.log(chalk.blue.bold("🔧 Setup Instructions"));
    console.log();

    if (options.provider === "dropbox") {
      console.log(
        "To use this tool with Dropbox, you need to set up a Dropbox app:"
      );
      console.log();
      console.log(chalk.yellow("1. Go to the Dropbox App Console:"));
      console.log("   https://www.dropbox.com/developers/apps");
      console.log();
      console.log(chalk.yellow('2. Click "Create app"'));
      console.log();
      console.log(chalk.yellow("3. Configure your app:"));
      console.log('   - Choose "Scoped access"');
      console.log('   - Choose "Full Dropbox" access');
      console.log('   - Name your app (e.g., "Security Scanner")');
      console.log();
      console.log(chalk.yellow("4. In the app settings:"));
      console.log('   - Under "OAuth 2" section, add this redirect URI:');
      console.log(chalk.cyan("     http://localhost:8080/dropbox/callback"));
      console.log("   - Note your App key and App secret");
      console.log();
      console.log(
        chalk.yellow(
          '5. Create a file "dropbox-config.json" in the config folder:'
        )
      );
      console.log(chalk.gray("   {"));
      console.log(chalk.gray('     "clientId": "your-app-key",'));
      console.log(chalk.gray('     "clientSecret": "your-app-secret"'));
      console.log(chalk.gray("   }"));
      console.log();
      console.log(chalk.yellow("6. Run: npm start scan --provider dropbox"));
    } else {
      console.log(
        "To use this tool with Google Drive, you need to set up Google Drive API credentials:"
      );
      console.log();
      console.log(chalk.yellow("1. Go to the Google Cloud Console:"));
      console.log("   https://console.cloud.google.com/");
      console.log();
      console.log(
        chalk.yellow("2. Create a new project or select an existing one")
      );
      console.log();
      console.log(chalk.yellow("3. Enable the Google Drive API:"));
      console.log(
        "   https://console.cloud.google.com/apis/library/drive.googleapis.com"
      );
      console.log();
      console.log(chalk.yellow("4. Create credentials (OAuth 2.0 Client ID):"));
      console.log("   - Go to APIs & Services > Credentials");
      console.log('   - Click "Create Credentials" > "OAuth client ID"');
      console.log('   - Choose "Desktop application"');
      console.log('   - Name it something like "Drive Scanner"');
      console.log("   - Download the JSON file");
      console.log();
      console.log(
        chalk.yellow(
          '5. Save the downloaded file as "google-credentials.json" in the config folder'
        )
      );
      console.log();
      console.log(chalk.yellow("6. Run: npm start scan"));
    }

    console.log();
    console.log(chalk.blue("Usage Examples:"));
    console.log(
      "  npm start scan                           # Scan Google Drive"
    );
    console.log("  npm start scan --provider dropbox        # Scan Dropbox");
    console.log("  npm start scan --output json             # Export to JSON");
    console.log("  npm start scan --output csv              # Export to CSV");
    console.log(
      "  npm start scan --output markdown         # Generate markdown report"
    );
    console.log(
      "  npm start scan --use-cache               # Use cached results"
    );
    console.log();
    console.log(
      chalk.green(
        "Note: This tool only requires read-only access to your cloud storage."
      )
    );
  });

if (process.argv.length === 2) {
  program.help();
}

program.parse();
