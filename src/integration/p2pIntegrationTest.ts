/**
 * P2P Network Integration Test for HyperSecure Messenger
 * 
 * This test verifies that the P2P networking layer properly integrates with
 * the cryptographic and storage components to provide a complete secure
 * messaging solution.
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { createP2PNetwork, P2PNetwork } from '../network/p2pNetwork';
import { MessageStorage } from '../storage/messageStorage';
import * as TrustedRatchet from '../crypto/trustedRatchet';

// Test User IDs
const ALICE_ID = 'alice@hypersecure.chat';
const BOB_ID = 'bob@hypersecure.chat';

/**
 * Run the P2P integration test
 */
async function runP2PIntegrationTest() {
  try {
    await sodium.ready;
    logger.info('✓ Sodium initialized');

    // Step 1: Create two P2P network nodes (Alice and Bob)
    logger.info('Creating P2P network nodes...');
    
    const aliceNode = await createP2PNetwork({
      listenPort: 0, // Random port
      discoveryMethod: 'local-network',
      useOnionRouting: false // Disable for test
    });
    
    const bobNode = await createP2PNetwork({
      listenPort: 0, // Random port
      discoveryMethod: 'local-network',
      useOnionRouting: false // Disable for test
    });
    
    logger.info(`Alice's node ID: ${aliceNode.getNodeInfo().nodeId}`);
    logger.info(`Bob's node ID: ${bobNode.getNodeInfo().nodeId}`);
    
    // Step 2: Initialize secure storage for both nodes
    logger.info('Initializing secure storage...');
    
    const aliceStorage = new MessageStorage(undefined, true); // Memory-only for test
    await aliceStorage.initialize();
    
    const bobStorage = new MessageStorage(undefined, true); // Memory-only for test
    await bobStorage.initialize();
    
    // Step 3: Set up trusted ratchet for secure messaging
    logger.info('Setting up trusted ratchet for secure messaging...');
    
    // Generate a shared secret (in a real app, this would be exchanged securely)
    const sharedSecret = sodium.randombytes_buf(32);
    
    // Initialize sessions for Alice and Bob
    let aliceSession = await TrustedRatchet.initSession(sharedSecret, ALICE_ID, BOB_ID);
    let bobSession = await TrustedRatchet.initSession(sharedSecret, BOB_ID, ALICE_ID);
    
    // Step 4: Start the P2P network nodes
    logger.info('Starting P2P network nodes...');
    
    await aliceNode.start();
    await bobNode.start();
    
    logger.info('P2P nodes started successfully');
    
    // Step 5: Connect the nodes to each other
    logger.info('Connecting Alice and Bob...');
    
    const aliceAddresses = aliceNode.getNodeAddresses?.() || [];
    if (aliceAddresses.length === 0) {
      throw new Error('Alice has no listening addresses');
    }
    
    const connectResult = await bobNode.connectToPeer(aliceAddresses[0]);
    if (!connectResult) {
      throw new Error('Failed to connect Bob to Alice');
    }
    
    logger.info('Bob connected to Alice');
    
    // Exchange public keys via network advertisement
    await aliceNode.advertiseToNetwork();
    await bobNode.advertiseToNetwork();
    
    // Wait for discovery messages to propagate
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Step 6: Create a message flow between Alice and Bob
    logger.info('Setting up secure message flow...');
    
    // Create conversation in both storages
    const aliceConversation = aliceStorage.createConversation(
      [ALICE_ID, BOB_ID],
      'Secure Chat',
      false
    );
    if (!aliceConversation.metadata) {
      aliceConversation.metadata = { isGroup: false };
    }
    await aliceStorage.storeConversation(aliceConversation);
    
    const bobConversation = bobStorage.createConversation(
      [ALICE_ID, BOB_ID],
      'Secure Chat',
      false
    );
    if (!bobConversation.metadata) {
      bobConversation.metadata = { isGroup: false };
    }
    await bobStorage.storeConversation(bobConversation);
    
    // Set up message reception handlers
    bobNode.on('message', async (p2pMessage) => {
      try {
        logger.info(`Bob received P2P message from ${p2pMessage.sender}`);
        
        // In a real app, we'd need to know which TrustedRatchet session to use
        // based on the sender, but for this test we know it's Alice
        
        // Extract encrypted message data
        const messageData = {
          ciphertext: p2pMessage.encryptedContent,
          counter: p2pMessage.counter,
          sender: ALICE_ID,
          receiver: BOB_ID,
          nonce: p2pMessage.nonce
        };
        
        // Decrypt the message
        const [decryptedBytes, newSession] = await TrustedRatchet.decrypt(bobSession, messageData);
        bobSession = newSession; // Update Bob's session
        
        // Process decrypted message
        const messageText = new TextDecoder().decode(decryptedBytes);
        logger.info(`Bob decrypted message: "${messageText}"`);
        
        // Store the message
        const message = bobStorage.createMessage(
          bobConversation.id,
          ALICE_ID,
          p2pMessage.encryptedContent
        );
        
        // Add metadata for later decryption if needed
        if (!message.metadata) {
          message.metadata = {};
        }
        message.metadata['counter'] = p2pMessage.counter;
        message.metadata['nonce'] = Array.from(p2pMessage.nonce);
        message.metadata['sender'] = ALICE_ID;
        message.metadata['receiver'] = BOB_ID;
        
        await bobStorage.storeMessage(message);
        logger.info('Bob stored the message');
        
        // Send a reply to Alice
        const replyText = `Thanks for your message: "${messageText}"`;
        const replyBytes = new TextEncoder().encode(replyText);
        
        // Encrypt reply with the ratchet
        const [encryptedReply, newerSession] = await TrustedRatchet.encrypt(bobSession, replyBytes);
        bobSession = newerSession; // Update Bob's session again
        
        // Send the reply via P2P network
        logger.info('Bob sending reply to Alice...');
        
        await bobNode.sendMessage(
          aliceNode.getNodeInfo().nodeId,
          encryptedReply.ciphertext,
          { 
            counter: encryptedReply.counter,
            nonce: encryptedReply.nonce 
          }
        );
        
        logger.info('Bob sent encrypted reply');
      } catch (error) {
        logger.error('Bob failed to process message:', error);
      }
    });
    
    aliceNode.on('message', async (p2pMessage) => {
      try {
        logger.info(`Alice received P2P message from ${p2pMessage.sender}`);
        
        // Extract encrypted message data
        const messageData = {
          ciphertext: p2pMessage.encryptedContent,
          counter: p2pMessage.counter,
          sender: BOB_ID,
          receiver: ALICE_ID,
          nonce: p2pMessage.nonce
        };
        
        // Decrypt the message
        const [decryptedBytes, newSession] = await TrustedRatchet.decrypt(aliceSession, messageData);
        aliceSession = newSession; // Update Alice's session
        
        // Process decrypted message
        const messageText = new TextDecoder().decode(decryptedBytes);
        logger.info(`Alice decrypted message: "${messageText}"`);
        
        // Store the message
        const message = aliceStorage.createMessage(
          aliceConversation.id,
          BOB_ID,
          p2pMessage.encryptedContent
        );
        
        // Add metadata for later decryption if needed
        if (!message.metadata) {
          message.metadata = {};
        }
        message.metadata['counter'] = p2pMessage.counter;
        message.metadata['nonce'] = Array.from(p2pMessage.nonce);
        message.metadata['sender'] = BOB_ID;
        message.metadata['receiver'] = ALICE_ID;
        
        await aliceStorage.storeMessage(message);
        logger.info('Alice stored the message');
        
        // Signal test completion
        logger.info('✓ Full message exchange completed successfully');
      } catch (error) {
        logger.error('Alice failed to process message:', error);
      }
    });
    
    // Step 7: Alice sends a message to Bob
    logger.info('Alice composing message to Bob...');
    const messageText = 'Hello Bob! This is a secure P2P message via HyperSecure Messenger.';
    const messageBytes = new TextEncoder().encode(messageText);
    
    // Encrypt the message with the ratchet
    const [encryptedMsg, newAliceSession] = await TrustedRatchet.encrypt(aliceSession, messageBytes);
    aliceSession = newAliceSession; // Update Alice's session
    
    // Store the outgoing message in Alice's storage
    const outgoingMessage = aliceStorage.createMessage(
      aliceConversation.id,
      ALICE_ID,
      encryptedMsg.ciphertext
    );
    
    // Add metadata for later reference
    if (!outgoingMessage.metadata) {
      outgoingMessage.metadata = {};
    }
    outgoingMessage.metadata['counter'] = encryptedMsg.counter;
    outgoingMessage.metadata['nonce'] = Array.from(encryptedMsg.nonce);
    outgoingMessage.metadata['sender'] = ALICE_ID;
    outgoingMessage.metadata['receiver'] = BOB_ID;
    
    await aliceStorage.storeMessage(outgoingMessage);
    
    // Send via P2P network
    logger.info('Alice sending message to Bob...');
    
    await aliceNode.sendMessage(
      bobNode.getNodeInfo().nodeId,
      encryptedMsg.ciphertext,
      { 
        counter: encryptedMsg.counter,
        nonce: encryptedMsg.nonce 
      }
    );
    
    logger.info('Alice sent encrypted message to Bob');
    
    // Wait for message exchange to complete
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Step 8: Clean up
    logger.info('Cleaning up resources...');
    
    await aliceNode.stop();
    await bobNode.stop();
    await aliceStorage.destroy();
    await bobStorage.destroy();
    
    logger.info('✓ P2P integration test completed successfully');
  } catch (error) {
    logger.error('P2P integration test failed:', error);
    throw error;
  }
}

/**
 * Extension to the interface for the P2P message
 */
declare module '../network/p2pNetwork' {
  interface P2PMessage {
    counter?: number;
    nonce?: Uint8Array;
  }
  
  interface P2PNetwork {
    getNodeAddresses(): string[];
  }
}

// Add method to get node addresses for testing
if (!P2PNetwork.prototype.getNodeAddresses) {
  P2PNetwork.prototype.getNodeAddresses = function(): string[] {
    if (!this.isRunning || !this.libp2p) {
      return [];
    }
    
    return this.libp2p.getMultiaddrs().map(addr => addr.toString());
  };
}

// Run the integration test
runP2PIntegrationTest().catch(error => {
  logger.error('Fatal error in P2P integration test:', error);
  process.exit(1);
}); 