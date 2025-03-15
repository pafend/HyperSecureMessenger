/**
 * HyperSecure Messenger - Desktop Client Preload Script
 * Provides secure IPC bridge between main and renderer processes
 */

import { contextBridge, ipcRenderer } from 'electron';

// Expose a minimal, secure API to the renderer process
contextBridge.exposeInMainWorld('hyper', {
  // Node information
  getNodeInfo: async (): Promise<{
    nodeId: string;
    publicKey: string;
    isRunning: boolean;
  }> => {
    return await ipcRenderer.invoke('get-node-info');
  },
  
  // Connection management
  connectToPeer: async (address: string, publicKey: string): Promise<boolean> => {
    return await ipcRenderer.invoke('connect-to-peer', address, publicKey);
  },
  
  getConnections: async (): Promise<Array<{
    peerId: string;
    lastSeen: number;
    isDirectConnection: boolean;
  }>> => {
    return await ipcRenderer.invoke('get-connections');
  },
  
  // Messaging
  sendMessage: async (peerId: string, message: string): Promise<string> => {
    return await ipcRenderer.invoke('send-message', peerId, message);
  },
  
  // Event listeners
  onMessageReceived: (callback: (data: {
    sender: string;
    messageId: string;
    timestamp: number;
  }) => void): void => {
    ipcRenderer.on('message-received', (_event, data) => callback(data));
  },
  
  onScreenCaptureDetected: (callback: () => void): void => {
    ipcRenderer.on('screen-capture-detected', () => callback());
  },
  
  // System events
  onDuressDetected: (callback: () => void): void => {
    ipcRenderer.on('duress-detected', () => callback());
  }
});

// Log preload completion (this would be removed in production)
console.log('HyperSecure secure preload script initialized');

// In a production implementation, this would:
// 1. Set up memory protection for the renderer process
// 2. Implement anti-debugging measures
// 3. Detect virtualization or sandboxing
// 4. Set up integrity verification of the renderer 