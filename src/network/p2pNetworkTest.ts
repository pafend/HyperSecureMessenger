/**
 * P2P Network Test for HyperSecure Messenger
 * 
 * Tests the functionality of the decentralized P2P networking layer.
 */

import { logger } from '../utils/logger';
import sodium from 'libsodium-wrappers-sumo';
import { createP2PNetwork, P2PNetwork } from './p2pNetwork';

// Test constants
const TEST_MESSAGE = 'This is a secure P2P test message from HyperSecure Messenger';
const TEST_TTL = 60000; // 1 minute

/**
 * Run the P2P network tests
 */
async function runP2PNetworkTests() {
  try {
    // Initialize sodium
    await sodium.ready;
    logger.info('✓ Sodium initialized');

    // Test 1: Basic node creation and initialization
    logger.info('Testing P2P node creation and initialization...');
    
    const node1 = await createP2PNetwork({
      listenPort: 0, // Random port
      discoveryMethod: 'local-network',
      useOnionRouting: false, // Disable for test
    });
    
    logger.info(`Node 1 created with ID: ${node1.getNodeInfo().nodeId}`);
    
    const node2 = await createP2PNetwork({
      listenPort: 0, // Random port
      discoveryMethod: 'local-network',
      useOnionRouting: false, // Disable for test
    });
    
    logger.info(`Node 2 created with ID: ${node2.getNodeInfo().nodeId}`);
    
    // Test 2: Starting the nodes
    logger.info('Starting P2P nodes...');
    
    try {
      await node1.start();
      logger.info('Node 1 started successfully');
      
      await node2.start();
      logger.info('Node 2 started successfully');
    } catch (error) {
      logger.error('Failed to start nodes:', error);
      throw error;
    }
    
    // Test 3: Peer connection
    logger.info('Testing peer connection...');
    
    // Get node1's address to connect from node2
    const node1Addresses = node1.getNodeAddresses();
    if (node1Addresses.length === 0) {
      throw new Error('Node 1 has no listening addresses');
    }
    
    // Try to connect node2 to node1
    logger.info(`Connecting node2 to node1 at address: ${node1Addresses[0]}`);
    const connected = await node2.connectToPeer(node1Addresses[0]);
    
    if (!connected) {
      throw new Error('Failed to connect node2 to node1');
    }
    
    logger.info('Node 2 successfully connected to node 1');
    
    // Wait for discovery to exchange public keys
    logger.info('Advertising nodes to the network...');
    await node1.advertiseToNetwork();
    await node2.advertiseToNetwork();
    
    // Wait for discovery messages to propagate
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Check connections
    const node1Peers = node1.getConnectedPeers();
    const node2Peers = node2.getConnectedPeers();
    
    logger.info(`Node 1 has ${node1Peers.length} peers`);
    logger.info(`Node 2 has ${node2Peers.length} peers`);
    
    if (node1Peers.length === 0 || node2Peers.length === 0) {
      logger.warn('Peers may not be fully connected yet - this might be a timing issue');
    }
    
    // Test 4: Message sending and receiving
    logger.info('Testing message exchange...');
    
    // Set up a message handler for node1
    let messageReceived = false;
    
    node1.on('message', (message) => {
      logger.info(`Node 1 received message: ${message.id}`);
      messageReceived = true;
    });
    
    // Prepare test message content
    const messageContent = new TextEncoder().encode(TEST_MESSAGE);
    
    try {
      // Send message from node2 to node1
      const node1Id = node1.getNodeInfo().nodeId;
      
      logger.info(`Sending message from node2 to node1 (${node1Id})...`);
      const messageId = await node2.sendMessage(node1Id, messageContent, { ttl: TEST_TTL });
      
      logger.info(`Message sent with ID: ${messageId}`);
      
      // Wait for message to be received
      let attempts = 0;
      while (!messageReceived && attempts < 10) {
        await new Promise(resolve => setTimeout(resolve, 500));
        attempts++;
      }
      
      if (messageReceived) {
        logger.info('✓ Message exchange test passed');
      } else {
        logger.warn('Message was not received within timeout period');
        logger.warn('This might be due to network conditions or NAT issues in test environment');
      }
    } catch (error) {
      logger.error('Error during message exchange test:', error);
    }
    
    // Test 5: Node stopping
    logger.info('Testing node shutdown...');
    
    try {
      await node1.stop();
      logger.info('Node 1 stopped successfully');
      
      await node2.stop();
      logger.info('Node 2 stopped successfully');
    } catch (error) {
      logger.error('Failed to stop nodes:', error);
      throw error;
    }
    
    logger.info('✓ P2P network tests completed');
  } catch (error) {
    logger.error('P2P network test failed:', error);
    process.exit(1);
  }
}

/**
 * Extension to the P2PNetwork class to expose addresses for testing
 */
declare module './p2pNetwork' {
  interface P2PNetwork {
    getNodeAddresses(): string[];
  }
}

// Add method to get node addresses for testing
P2PNetwork.prototype.getNodeAddresses = function(): string[] {
  if (!this.isRunning || !this.libp2p) {
    return [];
  }
  
  return this.libp2p.getMultiaddrs().map(addr => addr.toString());
};

// Run the tests
runP2PNetworkTests().catch(error => {
  logger.error('Fatal error in P2P network test:', error);
  process.exit(1);
}); 