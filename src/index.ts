/**
 * HyperSecure Messenger
 * The world's most uncompromising secure communications platform
 * 
 * This is the main entry point for the sovereign node implementation
 */

import { initializeCrypto } from './crypto/initialize';
import { setupNode } from './network/server';
import { logger } from './utils/logger';
import { readFileSync, existsSync, writeFileSync } from 'fs';
import { join } from 'path';

// Configuration file path
const CONFIG_PATH = join(process.cwd(), 'node-config.json');

// Default node configuration
const DEFAULT_CONFIG = {
  listenPort: 0, // Zero means pick an available port
  listenAddress: '0.0.0.0',
  useOnionRouting: true,
  routingHops: 3,
  discoveryMethod: 'manual',
  storageLocation: './secure-storage',
  enableMesh: true,
  maxConnections: 50,
  knownPeers: [] // List of known peers to bootstrap connection
};

/**
 * Load configuration from file or create default
 */
function loadConfig() {
  try {
    if (existsSync(CONFIG_PATH)) {
      const configData = readFileSync(CONFIG_PATH, 'utf8');
      const config = JSON.parse(configData);
      logger.info('Loaded configuration from file');
      return config;
    } else {
      // Create default config if none exists
      writeFileSync(CONFIG_PATH, JSON.stringify(DEFAULT_CONFIG, null, 2), 'utf8');
      logger.info('Created default configuration file');
      return DEFAULT_CONFIG;
    }
  } catch (error) {
    logger.error('Failed to load configuration', error);
    return DEFAULT_CONFIG;
  }
}

async function main(): Promise<void> {
  try {
    logger.info('Starting HyperSecure Messenger P2P Node...');
    
    // Initialize cryptographic subsystems
    await initializeCrypto();
    logger.info('Cryptographic subsystems initialized');
    
    // Load node configuration
    const config = loadConfig();
    
    // Setup P2P node
    const node = await setupNode(config);
    logger.info(`Node initialized with ID: ${node.nodeId}`);
    
    // Start the node
    await node.start();
    logger.info('Node started successfully');
    
    // Connect to known peers if any are configured
    if (config.knownPeers && config.knownPeers.length > 0) {
      logger.info(`Connecting to ${config.knownPeers.length} known peers...`);
      
      for (const peer of config.knownPeers) {
        try {
          const connected = await node.connectToPeer(peer.address, peer.publicKey);
          if (connected) {
            logger.info(`Connected to peer: ${peer.address}`);
          } else {
            logger.warn(`Failed to connect to peer: ${peer.address}`);
          }
        } catch (error) {
          logger.error(`Error connecting to peer ${peer.address}`, error);
        }
      }
    }
    
    // Register message handler
    node.onMessage((message, sender) => {
      logger.info(`Received message from ${sender}, ID: ${message.id}`);
      // In a real implementation, this would route the message to the appropriate handler
    });
    
    // Handle shutdown gracefully
    process.on('SIGINT', async () => {
      logger.info('Shutdown signal received, cleaning up...');
      await node.stop();
      process.exit(0);
    });
    
    logger.info('HyperSecure P2P node initialized successfully. Use Ctrl+C to exit.');
    
    // Display connection information
    logger.info(`Node public key: ${node.publicKey}`);
  } catch (error) {
    logger.error('Failed to initialize HyperSecure Messenger', error);
    process.exit(1);
  }
}

// Start the application
main(); 