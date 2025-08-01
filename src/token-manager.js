import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const TOKENS_PATH = path.join(__dirname, '..', 'config', 'tokens.json');

export async function saveTokens(provider, tokens) {
  try {
    let allTokens = {};
    
    // Try to read existing tokens
    try {
      const existingContent = await fs.readFile(TOKENS_PATH, 'utf8');
      allTokens = JSON.parse(existingContent);
    } catch (error) {
      // File doesn't exist or is invalid, start with empty object
    }
    
    // Update tokens for the specific provider
    allTokens[provider] = tokens;
    
    // Write back to file
    await fs.writeFile(TOKENS_PATH, JSON.stringify(allTokens, null, 2));
    console.log(`Token stored for ${provider}`);
  } catch (error) {
    throw new Error(`Error saving tokens: ${error.message}`);
  }
}

export async function loadTokens(provider) {
  try {
    const tokensContent = await fs.readFile(TOKENS_PATH, 'utf8');
    const tokens = JSON.parse(tokensContent);
    
    if (tokens[provider]) {
      return tokens[provider];
    } else {
      throw new Error(`No ${provider} tokens found`);
    }
  } catch (error) {
    throw new Error(`Error loading ${provider} tokens: ${error.message}`);
  }
}

export async function clearTokens(provider) {
  try {
    let allTokens = {};
    
    // Try to read existing tokens
    try {
      const existingContent = await fs.readFile(TOKENS_PATH, 'utf8');
      allTokens = JSON.parse(existingContent);
    } catch (error) {
      // File doesn't exist, nothing to clear
      return;
    }
    
    // Remove tokens for the specific provider
    delete allTokens[provider];
    
    // Write back to file
    await fs.writeFile(TOKENS_PATH, JSON.stringify(allTokens, null, 2));
    console.log(`Tokens cleared for ${provider}`);
  } catch (error) {
    throw new Error(`Error clearing tokens: ${error.message}`);
  }
}