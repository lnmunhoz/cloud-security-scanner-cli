import { google } from 'googleapis';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SCOPES = ['https://www.googleapis.com/auth/drive.readonly'];
const TOKEN_PATH = path.join(__dirname, '..', 'token.json');
const CREDENTIALS_PATH = path.join(__dirname, '..', 'credentials.json');

export async function authenticate() {
  let credentials;
  try {
    const credentialsContent = await fs.readFile(CREDENTIALS_PATH);
    credentials = JSON.parse(credentialsContent);
  } catch (error) {
    throw new Error(`Error loading client secret file: ${error.message}\nPlease ensure you have downloaded your OAuth2 credentials from Google Cloud Console and saved them as 'credentials.json' in the project root.`);
  }

  const { client_secret, client_id, redirect_uris } = credentials.installed;
  const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris[0]);

  try {
    const tokenContent = await fs.readFile(TOKEN_PATH);
    const token = JSON.parse(tokenContent);
    oAuth2Client.setCredentials(token);
    return oAuth2Client;
  } catch (error) {
    return await getNewToken(oAuth2Client);
  }
}

async function getNewToken(oAuth2Client) {
  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: SCOPES,
  });

  console.log('Authorize this app by visiting this url:', authUrl);
  console.log('\nAfter clicking "Allow", you will be redirected to a localhost page that fails to load.');
  console.log('That\'s expected! Just copy the "code" parameter from the URL in your browser.');
  console.log('The URL will look like: http://localhost/?code=XXXXXXX&scope=...');
  console.log('Copy everything after "code=" and before "&scope" (or the end if no &scope).');
  console.log('\nPaste the authorization code here:');

  const { default: readline } = await import('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve, reject) => {
    rl.question('Enter the code from that page here: ', async (code) => {
      rl.close();
      try {
        const { tokens } = await oAuth2Client.getToken(code);
        oAuth2Client.setCredentials(tokens);
        await fs.writeFile(TOKEN_PATH, JSON.stringify(tokens));
        console.log('Token stored to', TOKEN_PATH);
        resolve(oAuth2Client);
      } catch (error) {
        reject(new Error(`Error retrieving access token: ${error.message}`));
      }
    });
  });
}