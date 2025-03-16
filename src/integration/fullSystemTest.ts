/**
 * Comprehensive Integration Test for HyperSecure Messenger
 * 
 * This test verifies that all core components work together correctly,
 * including cryptography, secure storage, and message management.
 */

import sodium from 'libsodium-wrappers-sumo';
import { randomBytes } from 'crypto';
import { logger } from '../utils/logger';
import { SecureStorage } from '../storage/secureStorage';
import { MessageStorage, Message, Conversation } from '../storage/messageStorage';
import * as TrustedRatchet from '../crypto/trustedRatchet';

// Test User IDs
const ALICE_ID = 'alice@hypersecure.chat';
const BOB_ID = 'bob@hypersecure.chat';

/**
 * Run the comprehensive integration test
 */
async function runFullSystemTest() {
  try {
    // Step 1: Initialize sodium
    await sodium.ready;
    logger.info('✓ Sodium initialized');

    // Step 2: Test the secure storage system
    logger.info('Testing secure storage...');
    await testSecureStorage();
    logger.info('✓ Secure storage test passed');

    // Step 3: Test message storage
    logger.info('Testing message storage...');
    await testMessageStorage();
    logger.info('✓ Message storage test passed');

    // Step 4: Test the trusted ratchet with storage
    logger.info('Testing trusted ratchet with storage...');
    await testTrustedRatchetWithStorage();
    logger.info('✓ Trusted ratchet with storage test passed');

    // Step 5: Test message expiration
    logger.info('Testing message expiration...');
    await testMessageExpiration();
    logger.info('✓ Message expiration test passed');

    logger.info('🎉 Full system integration test completed successfully!');
  } catch (error) {
    logger.error('Integration test failed:', error);
    throw error;
  }
}

/**
 * Test basic secure storage operations
 */
async function testSecureStorage() {
  // Create storage in memory only mode
  const storage = new SecureStorage({ memoryOnly: true });
  await storage.initialize();

  // Store an item
  const testData = new Uint8Array(randomBytes(100));
  const item = {
    id: 'test-item',
    type: 'test',
    data: testData,
    createdAt: Date.now(),
    expiresAt: 0
  };

  await storage.store(item);

  // Retrieve the item
  const retrieved = await storage.retrieve(item.id);
  if (!retrieved) {
    throw new Error('Failed to retrieve stored item');
  }

  // Verify item data
  if (retrieved.data.length !== testData.length) {
    throw new Error('Retrieved data size mismatch');
  }

  // Compare byte-by-byte
  for (let i = 0; i < testData.length; i++) {
    if (retrieved.data[i] !== testData[i]) {
      throw new Error(`Data mismatch at index ${i}`);
    }
  }

  // Delete the item
  const deleteResult = await storage.secureDelete(item.id);
  if (!deleteResult) {
    throw new Error('Failed to delete item');
  }

  // Verify it's gone
  const afterDelete = await storage.retrieve(item.id);
  if (afterDelete) {
    throw new Error('Item still exists after deletion');
  }

  // Clean up
  await storage.destroy();
}

/**
 * Test message storage operations
 */
async function testMessageStorage() {
  // Create message storage in memory only mode
  const storage = new MessageStorage(undefined, true);
  await storage.initialize();

  // Create a direct conversation
  const directConversation = storage.createConversation(
    [ALICE_ID, BOB_ID],
    'Direct Conversation',
    false
  );
  
  // Ensure metadata is set to avoid type errors
  if (!directConversation.metadata) {
    directConversation.metadata = { isGroup: false };
  } else {
    directConversation.metadata.isGroup = false;
  }

  await storage.storeConversation(directConversation);

  // Create a group conversation
  const groupConversation = storage.createConversation(
    [ALICE_ID, BOB_ID, 'charlie@hypersecure.chat'],
    'Project X Team',
    true
  );
  
  // Ensure metadata is set to avoid type errors
  if (!groupConversation.metadata) {
    groupConversation.metadata = { isGroup: true };
  } else {
    groupConversation.metadata.isGroup = true;
  }

  await storage.storeConversation(groupConversation);

  // Verify conversations were stored
  const allConversations = await storage.getAllConversations();
  if (allConversations.length !== 2) {
    throw new Error(`Expected 2 conversations, got ${allConversations.length}`);
  }

  // Store messages in direct conversation
  const message1 = storage.createMessage(
    directConversation.id,
    ALICE_ID,
    new TextEncoder().encode('Hello Bob!')
  );
  await storage.storeMessage(message1);

  const message2 = storage.createMessage(
    directConversation.id,
    BOB_ID,
    new TextEncoder().encode('Hi Alice, how are you?')
  );
  await storage.storeMessage(message2);

  // Store message in group conversation
  const message3 = storage.createMessage(
    groupConversation.id,
    ALICE_ID,
    new TextEncoder().encode('Meeting at 3pm')
  );
  await storage.storeMessage(message3);

  // Verify messages were stored correctly
  const directMessages = await storage.getMessagesForConversation(directConversation.id);
  if (directMessages.length !== 2) {
    throw new Error(`Expected 2 direct messages, got ${directMessages.length}`);
  }

  const groupMessages = await storage.getMessagesForConversation(groupConversation.id);
  if (groupMessages.length !== 1) {
    throw new Error(`Expected 1 group message, got ${groupMessages.length}`);
  }

  // Clean up
  await storage.destroy();
}

/**
 * Test the trusted ratchet with storage integration
 */
async function testTrustedRatchetWithStorage() {
  // Create message storage
  const storage = new MessageStorage(undefined, true);
  await storage.initialize();

  // Create a conversation
  const conversation = storage.createConversation(
    [ALICE_ID, BOB_ID],
    'Secure Chat',
    false
  );
  
  // Ensure metadata exists
  if (!conversation.metadata) {
    conversation.metadata = { isGroup: false };
  } else {
    conversation.metadata.isGroup = false;
  }
  
  await storage.storeConversation(conversation);

  // Simulate trusted initial handshake with a shared secret
  const sharedSecret = sodium.randombytes_buf(32);

  // Initialize sessions for Alice and Bob
  logger.info('Initializing secure sessions...');
  let aliceSession = await TrustedRatchet.initSession(sharedSecret, ALICE_ID, BOB_ID);
  let bobSession = await TrustedRatchet.initSession(sharedSecret, BOB_ID, ALICE_ID);

  // Simulate message exchange (5 messages each way)
  logger.info('Testing secure message exchange...');
  
  // Alice to Bob messages
  const aliceToBobMessages = [];
  for (let i = 0; i < 5; i++) {
    // Alice encrypts a message
    const plaintext = `Alice to Bob, message ${i + 1}`;
    const plaintextBytes = new TextEncoder().encode(plaintext);
    
    const [encryptedMsg, newAliceSession] = await TrustedRatchet.encrypt(aliceSession, plaintextBytes);
    aliceSession = newAliceSession; // Update Alice's session
    
    // Store the encrypted message
    const message = storage.createMessage(
      conversation.id,
      ALICE_ID,
      encryptedMsg.ciphertext
    );
    
    // Add encrypted message details as metadata
    if (!message.metadata) {
      message.metadata = {};
    }
    message.metadata['counter'] = encryptedMsg.counter;
    message.metadata['nonce'] = Array.from(encryptedMsg.nonce);
    message.metadata['sender'] = encryptedMsg.sender;
    message.metadata['receiver'] = encryptedMsg.receiver;
    
    await storage.storeMessage(message);
    aliceToBobMessages.push(message);
    
    // Bob receives and decrypts the message
    const storedMsg: TrustedRatchet.Message = {
      ciphertext: message.content,
      counter: message.metadata['counter'],
      sender: message.metadata['sender'],
      receiver: message.metadata['receiver'],
      nonce: new Uint8Array(message.metadata['nonce'])
    };
    
    const [decryptedBytes, newBobSession] = await TrustedRatchet.decrypt(bobSession, storedMsg);
    bobSession = newBobSession; // Update Bob's session
    
    const decryptedText = new TextDecoder().decode(decryptedBytes);
    
    if (decryptedText !== plaintext) {
      throw new Error(`Decryption failed for message ${i + 1}. Expected: "${plaintext}", got: "${decryptedText}"`);
    }
  }
  
  // Bob to Alice messages
  const bobToAliceMessages = [];
  for (let i = 0; i < 5; i++) {
    // Bob encrypts a message
    const plaintext = `Bob to Alice, message ${i + 1}`;
    const plaintextBytes = new TextEncoder().encode(plaintext);
    
    const [encryptedMsg, newBobSession] = await TrustedRatchet.encrypt(bobSession, plaintextBytes);
    bobSession = newBobSession; // Update Bob's session
    
    // Store the encrypted message
    const message = storage.createMessage(
      conversation.id,
      BOB_ID,
      encryptedMsg.ciphertext
    );
    
    // Add encrypted message details as metadata
    if (!message.metadata) {
      message.metadata = {};
    }
    message.metadata['counter'] = encryptedMsg.counter;
    message.metadata['nonce'] = Array.from(encryptedMsg.nonce);
    message.metadata['sender'] = encryptedMsg.sender;
    message.metadata['receiver'] = encryptedMsg.receiver;
    
    await storage.storeMessage(message);
    bobToAliceMessages.push(message);
    
    // Alice receives and decrypts the message
    const storedMsg: TrustedRatchet.Message = {
      ciphertext: message.content,
      counter: message.metadata['counter'],
      sender: message.metadata['sender'],
      receiver: message.metadata['receiver'],
      nonce: new Uint8Array(message.metadata['nonce'])
    };
    
    const [decryptedBytes, newAliceSession] = await TrustedRatchet.decrypt(aliceSession, storedMsg);
    aliceSession = newAliceSession; // Update Alice's session
    
    const decryptedText = new TextDecoder().decode(decryptedBytes);
    
    if (decryptedText !== plaintext) {
      throw new Error(`Decryption failed for message ${i + 1}. Expected: "${plaintext}", got: "${decryptedText}"`);
    }
  }
  
  // Verify stored messages
  const allMessages = await storage.getMessagesForConversation(conversation.id);
  if (allMessages.length !== 10) {
    throw new Error(`Expected 10 messages total, got ${allMessages.length}`);
  }
  
  // Clean up
  await storage.destroy();
}

/**
 * Test message expiration with encrypted content
 */
async function testMessageExpiration() {
  // Create message storage
  const storage = new MessageStorage(undefined, true);
  await storage.initialize();
  
  // Create a conversation
  const conversation = storage.createConversation([ALICE_ID, BOB_ID]);
  await storage.storeConversation(conversation);

  // Initialize secure sessions
  const sharedSecret = sodium.randombytes_buf(32);
  let aliceSession = await TrustedRatchet.initSession(sharedSecret, ALICE_ID, BOB_ID);
  let bobSession = await TrustedRatchet.initSession(sharedSecret, BOB_ID, ALICE_ID);
  
  // Create messages with different expiration times
  const expiringSoon = 'This message will expire soon';
  const permanent = 'This message will not expire';
  
  // Encrypt the messages
  const [encryptedExpiring, aliceSession2] = await TrustedRatchet.encrypt(
    aliceSession, 
    new TextEncoder().encode(expiringSoon)
  );
  aliceSession = aliceSession2;
  
  const [encryptedPermanent, aliceSession3] = await TrustedRatchet.encrypt(
    aliceSession,
    new TextEncoder().encode(permanent)
  );
  aliceSession = aliceSession3;
  
  // Create message that expires in 1 second
  const expiringMessage = storage.createMessage(
    conversation.id,
    ALICE_ID,
    encryptedExpiring.ciphertext,
    1000 // Expire after 1 second
  );
  
  // Add metadata for decryption
  if (!expiringMessage.metadata) {
    expiringMessage.metadata = {};
  }
  expiringMessage.metadata['counter'] = encryptedExpiring.counter;
  expiringMessage.metadata['nonce'] = Array.from(encryptedExpiring.nonce);
  expiringMessage.metadata['sender'] = encryptedExpiring.sender;
  expiringMessage.metadata['receiver'] = encryptedExpiring.receiver;
  
  // Create message that doesn't expire
  const permanentMessage = storage.createMessage(
    conversation.id,
    ALICE_ID,
    encryptedPermanent.ciphertext
  );
  
  // Add metadata for decryption
  if (!permanentMessage.metadata) {
    permanentMessage.metadata = {};
  }
  permanentMessage.metadata['counter'] = encryptedPermanent.counter;
  permanentMessage.metadata['nonce'] = Array.from(encryptedPermanent.nonce);
  permanentMessage.metadata['sender'] = encryptedPermanent.sender;
  permanentMessage.metadata['receiver'] = encryptedPermanent.receiver;
  
  // Store both messages
  await storage.storeMessage(expiringMessage);
  await storage.storeMessage(permanentMessage);
  
  // Verify both exist initially
  const initialMessages = await storage.getMessagesForConversation(conversation.id);
  if (initialMessages.length !== 2) {
    throw new Error(`Expected 2 messages initially, got ${initialMessages.length}`);
  }
  
  // Wait for expiration
  logger.info('Waiting for message expiration...');
  await new Promise(resolve => setTimeout(resolve, 1500));
  
  // Check messages after expiration
  const remainingMessages = await storage.getMessagesForConversation(conversation.id);
  if (remainingMessages.length !== 1) {
    throw new Error(`Expected 1 message after expiration, got ${remainingMessages.length}`);
  }
  
  // Verify the permanent message can still be decrypted
  const permanentMessageAfter = await storage.retrieveMessage(permanentMessage.id);
  if (!permanentMessageAfter) {
    throw new Error('Permanent message was incorrectly deleted');
  }
  
  if (!permanentMessageAfter.metadata) {
    throw new Error('Missing metadata from permanent message');
  }
  
  const storedMsg: TrustedRatchet.Message = {
    ciphertext: permanentMessageAfter.content,
    counter: permanentMessageAfter.metadata['counter'],
    sender: permanentMessageAfter.metadata['sender'],
    receiver: permanentMessageAfter.metadata['receiver'],
    nonce: new Uint8Array(permanentMessageAfter.metadata['nonce'])
  };
  
  const [decryptedBytes, newBobSession] = await TrustedRatchet.decrypt(bobSession, storedMsg);
  const decryptedText = new TextDecoder().decode(decryptedBytes);
  
  if (decryptedText !== permanent) {
    throw new Error(`Decryption failed. Expected: "${permanent}", got: "${decryptedText}"`);
  }
  
  // Clean up
  await storage.destroy();
}

// Run the full system test
runFullSystemTest().catch(error => {
  logger.error('Fatal integration test error:', error);
  process.exit(1);
}); 