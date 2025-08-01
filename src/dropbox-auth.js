import { Dropbox } from 'dropbox';
import fs from 'fs/promises';
import path from 'path';
import http from 'http';
import { URL } from 'url';
import { exec } from 'child_process';
import { fileURLToPath } from 'url';
import { saveTokens, loadTokens } from './token-manager.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const TOKENS_PATH = path.join(__dirname, '..', 'config', 'tokens.json');
const DROPBOX_CONFIG_PATH = path.join(__dirname, '..', 'config', 'dropbox-config.json');

export async function authenticateDropbox() {
  let config;
  try {
    const configContent = await fs.readFile(DROPBOX_CONFIG_PATH);
    config = JSON.parse(configContent);
  } catch (error) {
    throw new Error(
      `Error loading Dropbox config file: ${error.message}\n` +
      `Please create a 'dropbox-config.json' file in the config folder with your Dropbox app credentials:\n` +
      `{\n` +
      `  "clientId": "your-app-key",\n` +
      `  "clientSecret": "your-app-secret"\n` +
      `}\n` +
      `You can create a Dropbox app at: https://www.dropbox.com/developers/apps`
    );
  }

  try {
    const tokens = await loadTokens('dropbox');
    
    // Create Dropbox client with existing token
    const dbx = new Dropbox({
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      clientId: config.clientId,
      clientSecret: config.clientSecret
    });
    
    return { dbx, isNewAuth: false };
  } catch (error) {
    // No existing token, need to authenticate
    const { dbx, tokenData } = await getNewDropboxToken(config);
    return { dbx, isNewAuth: true };
  }
}

async function getNewDropboxToken(config) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url, 'http://localhost:3000');
      
      if (url.pathname === '/dropbox/callback') {
        const code = url.searchParams.get('code');
        const error = url.searchParams.get('error');

        if (error) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
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
            // Use the fixed port
            const redirectUri = `http://localhost:8080/dropbox/callback`;
            
            // Exchange code for token
            const tokenUrl = 'https://api.dropboxapi.com/oauth2/token';
            const params = new URLSearchParams({
              code: code,
              grant_type: 'authorization_code',
              client_id: config.clientId,
              client_secret: config.clientSecret,
              redirect_uri: redirectUri
            });

            const tokenResponse = await fetch(tokenUrl, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
              },
              body: params.toString()
            });

            const tokenData = await tokenResponse.json();

            if (tokenData.error) {
              throw new Error(tokenData.error_description || tokenData.error);
            }

            // Save token data to unified tokens.json
            await saveTokens('dropbox', tokenData);
            
            // Create Dropbox client
            const dbx = new Dropbox({
              accessToken: tokenData.access_token,
              refreshToken: tokenData.refresh_token,
              clientId: config.clientId,
              clientSecret: config.clientSecret
            });
            
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(`
              <html>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                  <h2 style="color: green;">✅ Dropbox Authorization Successful!</h2>
                  <p>You can now close this window and return to the terminal.</p>
                  <p>The scanner is ready to analyze your Dropbox files.</p>
                </body>
              </html>
            `);
            
            console.log('\n✅ Dropbox authorization successful! You can close the browser window.');
            server.close();
            resolve({ dbx, tokenData });
          } catch (error) {
            res.writeHead(500, { 'Content-Type': 'text/html' });
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
            reject(new Error(`Error retrieving access token: ${error.message}`));
          }
        } else {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end(`
            <html>
              <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h2 style="color: red;">❌ No Authorization Code</h2>
                <p>No authorization code received. You can close this window and try again.</p>
              </body>
            </html>
          `);
          server.close();
          reject(new Error('No authorization code received'));
        }
      } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
      }
    });

    // Start the server on a fixed port for Dropbox compatibility
    const FIXED_PORT = 8080;
    server.listen(FIXED_PORT, 'localhost', () => {
      const redirectUri = `http://localhost:${FIXED_PORT}/dropbox/callback`;
      
      // Build Dropbox OAuth URL
      const authUrl = 'https://www.dropbox.com/oauth2/authorize?' + 
        new URLSearchParams({
          client_id: config.clientId,
          redirect_uri: redirectUri,
          response_type: 'code',
          token_access_type: 'offline'
        }).toString();

      console.log('\n🔐 Opening your browser for Dropbox OAuth authorization...');
      console.log(`If the browser doesn't open automatically, visit: ${authUrl}\n`);
      
      // Try to open the browser automatically
      const platform = process.platform;
      let openCmd;
      
      if (platform === 'darwin') openCmd = 'open';
      else if (platform === 'win32') openCmd = 'start';
      else openCmd = 'xdg-open';
      
      exec(`${openCmd} "${authUrl}"`, (error) => {
        if (error) {
          console.log('⚠️  Could not open browser automatically. Please visit the URL above manually.');
        }
      });
    });

    // Handle server errors
    server.on('error', (error) => {
      reject(new Error(`Server error: ${error.message}`));
    });
  });
}

