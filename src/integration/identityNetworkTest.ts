import * as sodium from 'libsodium-wrappers';
import { IdentityManager } from '../identity/identityManager';
import { SecureStorage } from '../storage/secureStorage';
import { P2PNetwork } from '../network/p2pNetwork';
import { logger } from '../utils/logger';
import * as crypto from 'crypto';

// Constants for the test
const ALICE_NAME = 'Alice';
const BOB_NAME = 'Bob';
const TEST_MESSAGE = 'Hello, this is a secure message!';
const TEST_PASSWORD = 'test-password';

/**
 * Run an integration test for identity management and P2P networking
 */
async function runIdentityNetworkTest(): Promise<void> {
  logger.info('Starting identity and network integration test');

  try {
    // Initialize sodium
    await sodium.ready;
    logger.info('Sodium initialized');

    // Create secure storage instances for Alice and Bob
    const aliceStorage = new SecureStorage({
      storageDir: '.alice_storage',
      memoryOnly: true
    });
    
    const bobStorage = new SecureStorage({
      storageDir: '.bob_storage',
      memoryOnly: true
    });
    
    // Initialize storage
    await aliceStorage.initialize();
    await bobStorage.initialize();
    logger.info('Secure storage initialized for both users');

    // Create identity managers
    const aliceIdentityManager = new IdentityManager({
      storageKey: 'alice-identities',
      storagePassword: TEST_PASSWORD,
      secureStorage: aliceStorage
    });
    
    const bobIdentityManager = new IdentityManager({
      storageKey: 'bob-identities',
      storagePassword: TEST_PASSWORD,
      secureStorage: bobStorage
    });
    
    // Initialize identity managers
    await aliceIdentityManager.initialize();
    await bobIdentityManager.initialize();
    logger.info('Identity managers initialized');

    // Create identities
    const aliceIdentity = await aliceIdentityManager.createIdentity(ALICE_NAME);
    const bobIdentity = await bobIdentityManager.createIdentity(BOB_NAME);
    
    logger.info('Created identities', {
      alice: aliceIdentity.userId,
      bob: bobIdentity.userId
    });

    // Exchange identities (simulating an in-person key exchange)
    const aliceExport = aliceIdentityManager.exportIdentity(aliceIdentity.userId);
    const bobExport = bobIdentityManager.exportIdentity(bobIdentity.userId);
    
    const importedBobIdentity = await aliceIdentityManager.importIdentity(bobExport);
    const importedAliceIdentity = await bobIdentityManager.importIdentity(aliceExport);
    
    // Trust the imported identities (after verification)
    await aliceIdentityManager.trustIdentity(importedBobIdentity.userId);
    await bobIdentityManager.trustIdentity(importedAliceIdentity.userId);
    
    logger.info('Exchanged and trusted identities');

    // Create P2P network nodes
    const aliceNetwork = new P2PNetwork({
      listenPort: 10001,
      useLocalDiscovery: true,
      useDht: false
    });
    
    const bobNetwork = new P2PNetwork({
      listenPort: 10002,
      useLocalDiscovery: true,
      useDht: false
    });
    
    // Initialize and start the networks
    await aliceNetwork.initialize();
    await bobNetwork.initialize();
    
    await aliceNetwork.start();
    await bobNetwork.start();
    
    logger.info('P2P networks started');

    // Connect the nodes directly (in a real app, discovery would handle this)
    const bobAddress = await bobNetwork.getLocalAddress();
    await aliceNetwork.connectToPeer(bobAddress);
    
    logger.info('P2P nodes connected');

    // Set up message handlers
    bobNetwork.on('message', async (message) => {
      logger.info('Bob received a message', { from: message.senderId });
      
      // Verify the message signature
      const isValid = bobIdentityManager.verifySignature(
        message.senderId,
        message.content,
        message.signature
      );
      
      if (isValid) {
        logger.info('Message signature verified successfully');
        
        // Decode the message
        const decoder = new TextDecoder();
        const decodedMessage = decoder.decode(message.content);
        
        logger.info('Decoded message', { content: decodedMessage });
        
        // Send a response
        const response = new TextEncoder().encode('Message received and verified!');
        const signature = bobIdentityManager.signMessage(response);
        
        await bobNetwork.sendMessage({
          recipientId: message.senderId,
          senderId: bobIdentity.userId,
          content: response,
          signature,
          timestamp: Date.now(),
          ttl: 3600 // 1 hour TTL
        });
        
        logger.info('Bob sent a response');
      } else {
        logger.warn('Invalid message signature detected');
      }
    });
    
    aliceNetwork.on('message', (message) => {
      logger.info('Alice received a response', { from: message.senderId });
      
      // Verify the message signature
      const isValid = aliceIdentityManager.verifySignature(
        message.senderId,
        message.content,
        message.signature
      );
      
      if (isValid) {
        logger.info('Response signature verified successfully');
        
        // Decode the message
        const decoder = new TextDecoder();
        const decodedMessage = decoder.decode(message.content);
        
        logger.info('Decoded response', { content: decodedMessage });
      } else {
        logger.warn('Invalid response signature detected');
      }
    });

    // Alice sends a message to Bob
    logger.info('Alice is sending a message to Bob');
    
    const messageContent = new TextEncoder().encode(TEST_MESSAGE);
    const signature = aliceIdentityManager.signMessage(messageContent);
    
    await aliceNetwork.sendMessage({
      recipientId: bobIdentity.userId,
      senderId: aliceIdentity.userId,
      content: messageContent,
      signature,
      timestamp: Date.now(),
      ttl: 3600 // 1 hour TTL
    });
    
    logger.info('Message sent from Alice to Bob');

    // Wait for message processing
    logger.info('Waiting for message processing...');
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Clean up
    await aliceNetwork.stop();
    await bobNetwork.stop();
    
    await aliceStorage.destroy();
    await bobStorage.destroy();
    
    logger.info('✅ Identity and network integration test completed successfully');
  } catch (error) {
    logger.error('❌ Identity and network integration test failed', error);
    throw error;
  }
}

// Run the test
runIdentityNetworkTest()
  .then(() => {
    logger.info('Integration test completed successfully');
    process.exit(0);
  })
  .catch((error) => {
    logger.error('Integration test failed', error);
    process.exit(1);
  }); 