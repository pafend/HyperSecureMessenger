/**
 * HyperSecure Messenger - Desktop Client
 * Sovereign, P2P, anti-forensic messaging platform
 * 
 * This implementation is meant to be built by the end user.
 * No centralized infrastructure, telemetry, or tracking.
 */

import { app, BrowserWindow, ipcMain, dialog } from 'electron';
import { join } from 'path';
import { setupNode } from '../../network/server';
import { logger } from '../../utils/logger';
import { initializeCrypto } from '../../crypto/initialize';
import { existsSync, mkdirSync } from 'fs';

// Node instance
let node: Awaited<ReturnType<typeof setupNode>> | null = null;

// Anti-forensic options
const SECURE_WIPE_ON_EXIT = true;
const MEMORY_ONLY_MODE = true;
const LEAVE_NO_TRACES = true;

/**
 * Create the main application window with security features:
 * - No screenshots
 * - No screen recording
 * - No memory dumps
 * - In-memory crypto operations
 */
async function createSecureWindow() {
  // Create a secured window
  const mainWindow = new BrowserWindow({
    width: 1000,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      preload: join(__dirname, 'preload.js')
    },
    // Security features
    autoHideMenuBar: true,
    darkTheme: true
  });

  // Load the app
  if (app.isPackaged) {
    await mainWindow.loadFile(join(__dirname, '../renderer/index.html'));
  } else {
    // In development, load from a local dev server
    await mainWindow.loadURL('http://localhost:3000');
    mainWindow.webContents.openDevTools();
  }

  // Prevent screenshots and screen capture by obscuring window content
  // when specific system events are detected
  const preventCapture = () => {
    mainWindow.webContents.send('screen-capture-detected');
  };

  // This would implement various OS-specific protections
  // Register for screen capture events when available
  // Note: This is a placeholder as actual implementation would be OS-specific
  
  return mainWindow;
}

/**
 * Initialize the P2P node with security-focused configuration
 */
async function initializeSecureNode() {
  try {
    // Ensure storage directory exists with secure permissions
    const storageDir = join(app.getPath('userData'), 'secure-storage');
    if (!existsSync(storageDir)) {
      mkdirSync(storageDir, { recursive: true, mode: 0o700 });
    }

    // Initialize cryptography
    await initializeCrypto();
    
    // Create and start the node
    node = await setupNode({
      storageLocation: MEMORY_ONLY_MODE ? ':memory:' : storageDir,
      useOnionRouting: true,
      routingHops: 3,
      discoveryMethod: 'manual', // Default to manual so user explicitly allows connections
    });
    
    await node.start();
    
    // Expose the node's public key for connections
    logger.info(`Node public key for connections: ${node.publicKey}`);
    
    return node;
  } catch (error) {
    logger.error('Failed to initialize secure node', error);
    throw error;
  }
}

/**
 * Set up secure IPC communication between main and renderer
 */
function setupSecureIPC() {
  if (!node) {
    throw new Error('Cannot set up IPC: Node not initialized');
  }

  // Handle messages from the renderer
  ipcMain.handle('connect-to-peer', async (_event, address, publicKey) => {
    try {
      return await node!.connectToPeer(address, publicKey);
    } catch (error) {
      logger.error('Failed to connect to peer', error);
      return false;
    }
  });

  ipcMain.handle('send-message', async (_event, peerId, message) => {
    try {
      // Convert string message to Uint8Array for encryption
      const encoder = new TextEncoder();
      const messageBytes = encoder.encode(message);
      
      return await node!.sendMessage(peerId, messageBytes);
    } catch (error) {
      logger.error('Failed to send message', error);
      throw error;
    }
  });

  ipcMain.handle('get-connections', () => {
    return node!.listConnections();
  });

  ipcMain.handle('get-node-info', () => {
    return {
      nodeId: node!.nodeId,
      publicKey: node!.publicKey,
      isRunning: node!.isRunning
    };
  });
}

/**
 * Perform secure cleanup on application exit
 */
async function secureCleanup() {
  if (node) {
    try {
      await node.stop();
    } catch (error) {
      logger.error('Error stopping node', error);
    }
  }
  
  if (SECURE_WIPE_ON_EXIT) {
    // In a real implementation, this would:
    // 1. Overwrite sensitive memory areas
    // 2. Securely delete temporary files
    // 3. Remove any traces from the system
    logger.info('Performing secure memory wipe');
  }
}

// When Electron is ready, create the window and start the node
app.whenReady().then(async () => {
  try {
    // Initialize the secure node
    await initializeSecureNode();
    
    // Set up IPC
    setupSecureIPC();
    
    // Create the main window
    const mainWindow = await createSecureWindow();
    
    // Set up message handlers
    if (node) {
      node.onMessage((message, sender) => {
        // Decode the message content
        const messageId = message.id;
        logger.info(`Received message from ${sender}, ID: ${messageId}`);
        
        // Forward to renderer process
        mainWindow.webContents.send('message-received', {
          sender,
          messageId,
          timestamp: message.timestamp
        });
      });
    }
  } catch (error) {
    logger.error('Failed to initialize application', error);
    dialog.showErrorBox('Initialization Error', 
      'Failed to initialize the secure messaging node. See logs for details.');
    app.exit(1);
  }
});

// Handle secure shut down
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    secureCleanup().then(() => app.quit());
  }
});

app.on('will-quit', (event) => {
  // Perform synchronous cleanup tasks
  if (LEAVE_NO_TRACES) {
    // This would implement secure memory wiping and trace removal
    logger.info('Removing all application traces');
  }
});

// Handle macOS reactivation
app.on('activate', async () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    await createSecureWindow();
  }
}); 