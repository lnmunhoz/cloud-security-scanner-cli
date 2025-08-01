import { BaseScanner } from './base-scanner.js';

export class DropboxScanner extends BaseScanner {
  constructor(dbx) {
    super();
    this.dbx = dbx;
    this.fileTree = { name: 'Dropbox', type: 'folder', children: {}, id: 'root' };
  }

  async listFiles(spinner, cursor = null) {
    try {
      let response;
      
      if (cursor) {
        // Continue from cursor
        response = await this.dbx.filesListFolderContinue({ cursor });
      } else {
        // Initial request
        response = await this.dbx.filesListFolder({
          path: '',
          recursive: true,
          include_deleted: false,
          include_has_explicit_shared_members: false,
          include_mounted_folders: false
        });
      }

      const entries = response.result.entries;
      this.totalFilesFetched += entries.length;
      
      if (spinner) {
        spinner.text = `Fetched ${this.totalFilesFetched} files, analyzing ${entries.length} files in this batch...`;
      }
      
      for (const entry of entries) {
        this.totalFilesScanned++;
        
        // Convert Dropbox entry to common format
        const file = {
          id: entry.id,
          name: entry.name,
          path: entry.path_display,
          type: entry['.tag'], // 'file' or 'folder'
          size: entry.size,
          modifiedTime: entry.client_modified || entry.server_modified
        };
        
        // Store all files for file tree generation
        this.allFiles.push(file);
        
        if (file.type === 'file') {
          const risks = this.analyzeFileName(file);
          if (risks.length > 0) {
            const folderPath = this.getDropboxFolderPath(file.path);
            this.vulnerableFiles.push({
              file: file,
              risks: risks,
              folderPath: folderPath
            });
          }
        }
        
        // Update spinner every 10 files to show progress
        if (spinner && this.totalFilesScanned % 10 === 0) {
          spinner.text = `Fetched ${this.totalFilesFetched} files, scanned ${this.totalFilesScanned} files, found ${this.vulnerableFiles.length} vulnerable files...`;
        }
      }

      // Check if there are more files
      if (response.result.has_more) {
        if (spinner) {
          spinner.text = `Fetched ${this.totalFilesFetched} files so far, fetching next batch...`;
        }
        await this.listFiles(spinner, response.result.cursor);
      }
    } catch (error) {
      console.error('Error listing Dropbox files:', error);
      throw error;
    }
  }

  getDropboxFolderPath(fullPath) {
    // Extract folder path from full path
    const parts = fullPath.split('/');
    parts.pop(); // Remove filename
    return parts.join('/') || '/';
  }

  async getFolderPath(fileId, parentPath) {
    // For Dropbox, we already have the full path
    return parentPath || '/';
  }

  async buildFileTree() {
    // Build file tree from paths
    for (const file of this.allFiles) {
      const parts = file.path.split('/').filter(p => p); // Remove empty parts
      let currentNode = this.fileTree;
      
      // Navigate/create path
      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        const isLast = i === parts.length - 1;
        
        if (!currentNode.children[part]) {
          if (isLast && file.type === 'file') {
            // It's a file
            currentNode.children[part] = {
              name: part,
              type: 'file',
              id: file.id,
              size: file.size,
              modifiedTime: file.modifiedTime
            };
          } else {
            // It's a folder
            currentNode.children[part] = {
              name: part,
              type: 'folder',
              children: {},
              id: file.id || `folder-${part}`,
              path: parts.slice(0, i + 1).join('/')
            };
          }
        }
        
        if (!isLast || file.type === 'folder') {
          currentNode = currentNode.children[part];
        }
      }
    }
  }
}