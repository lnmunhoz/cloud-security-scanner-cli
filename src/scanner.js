import { google } from 'googleapis';
import { BaseScanner } from './base-scanner.js';

export class DriveScanner extends BaseScanner {
  constructor(auth) {
    super();
    this.drive = google.drive({ version: 'v3', auth });
    this.fileTree = { name: 'My Drive', type: 'folder', children: {}, id: 'root' };
  }

  async listFiles(spinner, pageToken = null) {
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
      
      // Store all files for file tree generation
      this.allFiles.push(file);
      
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
      await this.listFiles(spinner, response.data.nextPageToken);
    }
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

  async buildFileTree() {
    // First, get all folders and build the folder structure
    const folders = this.allFiles.filter(file => file.mimeType === 'application/vnd.google-apps.folder');
    
    // Create folder entries in the cache
    for (const folder of folders) {
      this.folderCache.set(folder.id, {
        name: folder.name,
        type: 'folder',
        children: {},
        id: folder.id,
        parents: folder.parents || []
      });
    }
    
    // Build folder hierarchy
    for (const folder of folders) {
      const folderNode = this.folderCache.get(folder.id);
      if (folder.parents && folder.parents.length > 0) {
        const parentId = folder.parents[0];
        if (parentId === 'root' || !parentId) {
          this.fileTree.children[folder.name] = folderNode;
        } else {
          const parentNode = this.folderCache.get(parentId);
          if (parentNode) {
            parentNode.children[folder.name] = folderNode;
          }
        }
      } else {
        // No parent means it's in root
        this.fileTree.children[folder.name] = folderNode;
      }
    }
    
    // Add files to their respective folders
    const files = this.allFiles.filter(file => file.mimeType !== 'application/vnd.google-apps.folder');
    for (const file of files) {
      const fileNode = {
        name: file.name,
        type: 'file',
        id: file.id,
        mimeType: file.mimeType,
        size: file.size,
        modifiedTime: file.modifiedTime
      };
      
      if (file.parents && file.parents.length > 0) {
        const parentId = file.parents[0];
        if (parentId === 'root' || !parentId) {
          this.fileTree.children[file.name] = fileNode;
        } else {
          const parentNode = this.folderCache.get(parentId);
          if (parentNode) {
            parentNode.children[file.name] = fileNode;
          }
        }
      } else {
        // No parent means it's in root
        this.fileTree.children[file.name] = fileNode;
      }
    }
  }
}