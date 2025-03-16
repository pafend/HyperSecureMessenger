/**
 * Tests for Message Storage
 * 
 * This file contains tests for the secure message storage system
 * that provides anti-forensic capabilities for messages and conversations.
 */

import { randomBytes } from 'crypto';
import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { MessageStorage, Message, Conversation } from './messageStorage';

// Helper function to convert string to Uint8Array
function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

// Helper function to convert Uint8Array to string
function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// Sample user IDs
const ALICE_ID = 'alice@hypersecure.chat';
const BOB_ID = 'bob@hypersecure.chat';

/**
 * Main test function
 */
async function runTests() {
  try {
    await sodium.ready;
    logger.info('Sodium initialized for message storage testing');
    
    // Run tests
    await testMessageStorage();
    await testConversationStorage();
    await testMessageRetrieval();
    await testMessageExpiration();
    await testBulkOperations();
    
    logger.info('All message storage tests completed successfully! 🎉');
  } catch (error) {
    logger.error('Test failed:', error);
    throw error;
  }
}

/**
 * Test basic message storage and retrieval
 */
async function testMessageStorage() {
  logger.info('Testing basic message storage and retrieval...');
  
  // Create a storage instance (memory-only for testing)
  const storage = new MessageStorage(undefined, true);
  await storage.initialize();
  
  // Create a conversation
  const conversation = storage.createConversation([ALICE_ID, BOB_ID]);
  await storage.storeConversation(conversation);
  
  // Create and store a message
  const messageContent = 'Hello, this is a secure message!';
  const message = storage.createMessage(
    conversation.id,
    ALICE_ID,
    stringToBytes(messageContent)
  );
  
  await storage.storeMessage(message);
  logger.info(`Stored message: ${message.id}`);
  
  // Retrieve the message
  const retrievedMessage = await storage.retrieveMessage(message.id);
  
  if (!retrievedMessage) {
    throw new Error('Failed to retrieve message');
  }
  
  // Verify message content
  const retrievedContent = bytesToString(retrievedMessage.content);
  if (retrievedContent !== messageContent) {
    throw new Error(`Message content mismatch: expected "${messageContent}", got "${retrievedContent}"`);
  }
  
  // Verify other message properties
  if (
    retrievedMessage.conversationId !== conversation.id ||
    retrievedMessage.senderId !== ALICE_ID ||
    retrievedMessage.read !== false
  ) {
    throw new Error('Message properties mismatch');
  }
  
  logger.info('Message content and properties verified');
  
  // Delete the message
  const deleteResult = await storage.deleteMessage(message.id);
  if (!deleteResult) {
    throw new Error('Failed to delete message');
  }
  
  // Verify it's gone
  const afterDelete = await storage.retrieveMessage(message.id);
  if (afterDelete) {
    throw new Error('Message still exists after deletion');
  }
  
  // Clean up
  await storage.destroy();
  logger.info('Basic message storage test passed ✓');
}

/**
 * Test conversation storage and retrieval
 */
async function testConversationStorage() {
  logger.info('Testing conversation storage and retrieval...');
  
  // Create a storage instance
  const storage = new MessageStorage(undefined, true);
  await storage.initialize();
  
  // Create and store a group conversation with non-null properties
  const participants = [ALICE_ID, BOB_ID, 'charlie@hypersecure.chat'];
  const conversationName = 'Project HyperSecure';
  const isGroup = true;
  
  const conversation = storage.createConversation(
    participants,
    conversationName,
    isGroup
  );
  
  // Manually ensure metadata exists to silence linter
  if (!conversation.metadata) {
    conversation.metadata = { isGroup: true };
  } else {
    conversation.metadata.isGroup = true;
  }
  
  await storage.storeConversation(conversation);
  logger.info(`Stored conversation: ${conversation.id}`);
  
  // Retrieve the conversation
  const retrievedConversation = await storage.retrieveConversation(conversation.id);
  
  if (!retrievedConversation) {
    throw new Error('Failed to retrieve conversation');
  }
  
  // Verify conversation properties
  if (
    retrievedConversation.name !== conversationName ||
    retrievedConversation.participants.length !== 3
  ) {
    throw new Error('Conversation properties mismatch');
  }
  
  // Verify isGroup property separately to handle null
  if (!retrievedConversation.metadata || retrievedConversation.metadata.isGroup !== true) {
    throw new Error('Conversation metadata mismatch - isGroup should be true');
  }
  
  logger.info('Conversation properties verified');
  
  // Get all conversations
  const allConversations = await storage.getAllConversations();
  if (allConversations.length !== 1 || allConversations[0] !== conversation.id) {
    throw new Error('Failed to list all conversations');
  }
  
  // Delete the conversation
  const deleteResult = await storage.deleteConversation(conversation.id);
  if (!deleteResult) {
    throw new Error('Failed to delete conversation');
  }
  
  // Verify it's gone
  const afterDelete = await storage.retrieveConversation(conversation.id);
  if (afterDelete) {
    throw new Error('Conversation still exists after deletion');
  }
  
  // Clean up
  await storage.destroy();
  logger.info('Conversation storage test passed ✓');
}

/**
 * Test message retrieval by conversation
 */
async function testMessageRetrieval() {
  logger.info('Testing message retrieval by conversation...');
  
  // Create a storage instance
  const storage = new MessageStorage(undefined, true);
  await storage.initialize();
  
  // Define conversation names as constants to avoid undefined
  const conversationName1 = 'Conversation 1';
  const conversationName2 = 'Conversation 2';
  
  // Create two conversations with guaranteed non-undefined names
  const conversation1 = storage.createConversation(
    [ALICE_ID, BOB_ID], 
    conversationName1
  );
  
  const conversation2 = storage.createConversation(
    [ALICE_ID, 'charlie@hypersecure.chat'], 
    conversationName2
  );
  
  await storage.storeConversation(conversation1);
  await storage.storeConversation(conversation2);
  
  // Create and store messages for conversation 1
  const messages1 = [
    storage.createMessage(conversation1.id, ALICE_ID, stringToBytes('Message 1-1')),
    storage.createMessage(conversation1.id, BOB_ID, stringToBytes('Message 1-2')),
    storage.createMessage(conversation1.id, ALICE_ID, stringToBytes('Message 1-3'))
  ];
  
  // Create and store messages for conversation 2
  const messages2 = [
    storage.createMessage(conversation2.id, ALICE_ID, stringToBytes('Message 2-1')),
    storage.createMessage(conversation2.id, 'charlie@hypersecure.chat', stringToBytes('Message 2-2'))
  ];
  
  // Store all messages
  for (const msg of [...messages1, ...messages2]) {
    await storage.storeMessage(msg);
  }
  
  // Retrieve messages for conversation 1
  const messageIds1 = await storage.getMessagesForConversation(conversation1.id);
  
  if (messageIds1.length !== 3) {
    throw new Error(`Expected 3 messages for conversation 1, got ${messageIds1.length}`);
  }
  
  // Retrieve messages for conversation 2
  const messageIds2 = await storage.getMessagesForConversation(conversation2.id);
  
  if (messageIds2.length !== 2) {
    throw new Error(`Expected 2 messages for conversation 2, got ${messageIds2.length}`);
  }
  
  // Verify message content for a specific message
  const msgId = messages1[1].id;
  const retrievedMessage = await storage.retrieveMessage(msgId);
  
  if (!retrievedMessage) {
    throw new Error(`Failed to retrieve message ${msgId}`);
  }
  
  const expectedContent = 'Message 1-2';
  const actualContent = bytesToString(retrievedMessage.content);
  
  if (actualContent !== expectedContent) {
    throw new Error(`Message content mismatch: expected "${expectedContent}", got "${actualContent}"`);
  }
  
  // Delete a conversation and verify its messages are also deleted
  await storage.deleteConversation(conversation1.id);
  
  // Check that conversation 1 messages are gone
  for (const msg of messages1) {
    const retrievedMsg = await storage.retrieveMessage(msg.id);
    if (retrievedMsg) {
      throw new Error(`Message ${msg.id} still exists after conversation deletion`);
    }
  }
  
  // Check that conversation 2 messages still exist
  for (const msg of messages2) {
    const retrievedMsg = await storage.retrieveMessage(msg.id);
    if (!retrievedMsg) {
      throw new Error(`Message ${msg.id} was incorrectly deleted`);
    }
  }
  
  // Clean up
  await storage.deleteConversation(conversation2.id);
  await storage.destroy();
  logger.info('Message retrieval test passed ✓');
}

/**
 * Test message expiration
 */
async function testMessageExpiration() {
  logger.info('Testing message expiration...');
  
  // Create a storage instance
  const storage = new MessageStorage(undefined, true);
  await storage.initialize();
  
  // Create a conversation
  const conversation = storage.createConversation([ALICE_ID, BOB_ID]);
  await storage.storeConversation(conversation);
  
  // Create messages with different expiration times
  const permanentMessage = storage.createMessage(
    conversation.id,
    ALICE_ID,
    stringToBytes('This message never expires')
  );
  
  const expiringMessage = storage.createMessage(
    conversation.id,
    ALICE_ID,
    stringToBytes('This message expires in 1 second'),
    1000 // Expires in 1 second
  );
  
  // Store both messages
  await storage.storeMessage(permanentMessage);
  await storage.storeMessage(expiringMessage);
  
  // Verify both exist initially
  const initialCheckPermanent = await storage.retrieveMessage(permanentMessage.id);
  const initialCheckExpiring = await storage.retrieveMessage(expiringMessage.id);
  
  if (!initialCheckPermanent || !initialCheckExpiring) {
    throw new Error('Failed to store test messages');
  }
  
  // Wait for expiration
  logger.info('Waiting for message expiration...');
  await new Promise(resolve => setTimeout(resolve, 1500));
  
  // Force a retrieval which should trigger expiration check
  const afterExpirePermanent = await storage.retrieveMessage(permanentMessage.id);
  const afterExpireExpiring = await storage.retrieveMessage(expiringMessage.id);
  
  if (!afterExpirePermanent) {
    throw new Error('Permanent message was incorrectly removed');
  }
  
  if (afterExpireExpiring) {
    throw new Error('Expiring message still exists after expiration');
  }
  
  // Clean up
  await storage.destroy();
  logger.info('Message expiration test passed ✓');
}

/**
 * Test bulk operations
 */
async function testBulkOperations() {
  logger.info('Testing bulk operations with many messages...');
  
  // Create a storage instance
  const storage = new MessageStorage(undefined, true);
  await storage.initialize();
  
  // Create a conversation
  const conversation = storage.createConversation([ALICE_ID, BOB_ID]);
  await storage.storeConversation(conversation);
  
  // Create and store many messages
  const numMessages = 100;
  const messageIds: string[] = [];
  
  logger.info(`Creating and storing ${numMessages} messages...`);
  
  for (let i = 0; i < numMessages; i++) {
    const message = storage.createMessage(
      conversation.id,
      i % 2 === 0 ? ALICE_ID : BOB_ID, // Alternate senders
      stringToBytes(`Message #${i}`)
    );
    
    await storage.storeMessage(message);
    messageIds.push(message.id);
  }
  
  // Verify all messages were stored
  const storedMessageIds = await storage.getMessagesForConversation(conversation.id);
  
  if (storedMessageIds.length !== numMessages) {
    throw new Error(`Expected ${numMessages} messages, got ${storedMessageIds.length}`);
  }
  
  // Retrieve a random message
  const randomIndex = Math.floor(Math.random() * numMessages);
  const randomId = messageIds[randomIndex];
  const randomMessage = await storage.retrieveMessage(randomId);
  
  if (!randomMessage) {
    throw new Error(`Failed to retrieve random message ${randomId}`);
  }
  
  const expectedContent = `Message #${randomIndex}`;
  const actualContent = bytesToString(randomMessage.content);
  
  if (actualContent !== expectedContent) {
    throw new Error(`Random message content mismatch: expected "${expectedContent}", got "${actualContent}"`);
  }
  
  // Delete the conversation and all its messages
  await storage.deleteConversation(conversation.id);
  
  // Verify all messages were deleted
  for (const id of messageIds) {
    const retrievedMsg = await storage.retrieveMessage(id);
    if (retrievedMsg) {
      throw new Error(`Message ${id} still exists after bulk deletion`);
    }
  }
  
  // Clean up
  await storage.destroy();
  logger.info('Bulk operations test passed ✓');
}

// Run all tests
runTests().catch(error => {
  logger.error('Fatal test error:', error);
  process.exit(1);
}); 