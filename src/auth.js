import { google } from "googleapis";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import http from "http";
import { URL } from "url";
import { exec } from "child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SCOPES = ["https://www.googleapis.com/auth/drive.readonly"];
const TOKEN_PATH = path.join(__dirname, "..", "token.json");
const CREDENTIALS_PATH = path.join(__dirname, "..", "credentials.json");

export async function authenticate() {
  let credentials;
  try {
    const credentialsContent = await fs.readFile(CREDENTIALS_PATH);
    credentials = JSON.parse(credentialsContent);
  } catch (error) {
    throw new Error(
      `Error loading client secret file: ${error.message}\nPlease ensure you have downloaded your OAuth2 credentials from Google Cloud Console and saved them as 'credentials.json' in the project root.`
    );
  }

  const { client_secret, client_id, redirect_uris } = credentials.installed;
  const oAuth2Client = new google.auth.OAuth2(
    client_id,
    client_secret,
    redirect_uris[0]
  );

  try {
    const tokenContent = await fs.readFile(TOKEN_PATH);
    const token = JSON.parse(tokenContent);
    oAuth2Client.setCredentials(token);
    return { oAuth2Client, isNewAuth: false };
  } catch (error) {
    const oAuth2Client = await getNewToken(credentials);
    return { oAuth2Client, isNewAuth: true };
  }
}

async function getNewToken(credentials) {
  return new Promise((resolve, reject) => {
    // Create a local server to handle the OAuth callback
    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url, "http://localhost:3000");

      if (url.pathname === "/oauth/callback") {
        const code = url.searchParams.get("code");
        const error = url.searchParams.get("error");

        if (error) {
          res.writeHead(400, { "Content-Type": "text/html" });
          res.end(`
            <html>
              <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h2 style="color: red;">❌ Authorization Failed</h2>
                <p>Error: ${error}</p>
                <p>You can close this window and try again.</p>
              </body>
            </html>
          `);
          server.close();
          reject(new Error(`Authorization failed: ${error}`));
          return;
        }

        if (code) {
          try {
            // Get the port from the server address
            const port = server.address().port;
            const redirectUri = `http://localhost:${port}/oauth/callback`;

            // Create OAuth2 client with the dynamic redirect URI
            const { client_secret, client_id } = credentials.installed;
            const oAuth2Client = new google.auth.OAuth2(
              client_id,
              client_secret,
              redirectUri
            );

            const { tokens } = await oAuth2Client.getToken(code);
            oAuth2Client.setCredentials(tokens);
            await fs.writeFile(TOKEN_PATH, JSON.stringify(tokens));

            res.writeHead(200, { "Content-Type": "text/html" });
            res.end(`
              <html>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                  <h2 style="color: green;">Authorization Successful!</h2>
                  <p>You can now close this window and return to the terminal.</p>
                  <p>The Google Drive scanner is ready to use.</p>
                </body>
              </html>
            `);

            console.log(
              "\n✅ Authorization successful! You can close the browser window."
            );
            server.close();
            resolve(oAuth2Client);
          } catch (error) {
            res.writeHead(500, { "Content-Type": "text/html" });
            res.end(`
              <html>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                  <h2 style="color: red;">❌ Token Exchange Failed</h2>
                  <p>Error: ${error.message}</p>
                  <p>You can close this window and try again.</p>
                </body>
              </html>
            `);
            server.close();
            reject(
              new Error(`Error retrieving access token: ${error.message}`)
            );
          }
        } else {
          res.writeHead(400, { "Content-Type": "text/html" });
          res.end(`
            <html>
              <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h2 style="color: red;">❌ No Authorization Code</h2>
                <p>No authorization code received. You can close this window and try again.</p>
              </body>
            </html>
          `);
          server.close();
          reject(new Error("No authorization code received"));
        }
      } else {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("Not found");
      }
    });

    // Start the server on a random available port
    server.listen(0, "localhost", () => {
      const port = server.address().port;
      const redirectUri = `http://localhost:${port}/oauth/callback`;

      // Create OAuth2 client with the dynamic redirect URI
      const { client_secret, client_id } = credentials.installed;
      const oAuth2Client = new google.auth.OAuth2(
        client_id,
        client_secret,
        redirectUri
      );

      const authUrl = oAuth2Client.generateAuthUrl({
        access_type: "offline",
        scope: SCOPES,
      });

      console.log(
        "\n🔐 Opening your browser for Google OAuth authorization..."
      );
      console.log(
        `If the browser doesn't open automatically, visit: ${authUrl}\n`
      );

      // Try to open the browser automatically
      const platform = process.platform;
      let openCmd;

      if (platform === "darwin") openCmd = "open";
      else if (platform === "win32") openCmd = "start";
      else openCmd = "xdg-open";

      exec(`${openCmd} "${authUrl}"`, (error) => {
        if (error) {
          console.log(
            "⚠️  Could not open browser automatically. Please visit the URL above manually."
          );
        }
      });
    });

    // Handle server errors
    server.on("error", (error) => {
      reject(new Error(`Server error: ${error.message}`));
    });
  });
}
