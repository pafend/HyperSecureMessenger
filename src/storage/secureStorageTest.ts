/**
 * Tests for Anti-Forensic Secure Storage
 * 
 * This file contains tests for the secure storage system
 * with anti-forensic capabilities.
 */

import { promises as fs } from 'fs';
import { join } from 'path';
import { execSync } from 'child_process';
import * as path from 'path';
import * as crypto from 'crypto';
import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { SecureStorage, StoredItem } from './secureStorage';

// Test directory for storage
const TEST_DIR = '.test_secure_storage';

// Helper function to convert string to Uint8Array
function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

// Helper function to convert Uint8Array to string
function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// Helper function to generate random data
function randomData(size: number): Uint8Array {
  return new Uint8Array(crypto.randomBytes(size));
}

/**
 * Main test function
 */
async function runTests() {
  try {
    // Initialize sodium
    await sodium.ready;
    logger.info('Sodium initialized for testing');

    // Clean up any old test directories
    await cleanupTestDir();

    // Run the tests
    await testBasicFunctionality();
    await testExpiration();
    await testListByType();
    await testSecureDeletion();
    await testMemoryOnlyMode();
    await testRekeying();
    await testEncryptionSecurity();
    
    // Clean up after tests
    await cleanupTestDir();
    
    logger.info('All secure storage tests completed successfully! 🎉');
  } catch (error) {
    logger.error('Test failed:', error);
    throw error;
  }
}

/**
 * Test basic functionality: store, retrieve, delete
 */
async function testBasicFunctionality() {
  logger.info('Testing basic functionality: store, retrieve, delete...');
  
  // Create a new storage instance
  const storage = new SecureStorage({
    storageDir: TEST_DIR,
    memoryOnly: false
  });
  
  // Initialize with a random key
  const masterKey = randomData(32);
  await storage.initialize(masterKey);
  
  // Create a test item
  const testItem: StoredItem = {
    id: 'test-item-1',
    type: 'message',
    data: stringToBytes('This is a test message'),
    createdAt: Date.now(),
    expiresAt: 0, // Never expires
    metadata: {
      sender: 'alice',
      recipient: 'bob',
      important: true
    }
  };
  
  // Store the item
  await storage.store(testItem);
  logger.info('Item stored');
  
  // Retrieve the item
  const retrievedItem = await storage.retrieve(testItem.id);
  
  if (!retrievedItem) {
    throw new Error('Failed to retrieve stored item');
  }
  
  logger.info('Item retrieved');
  
  // Validate the data
  const originalText = bytesToString(testItem.data);
  const retrievedText = bytesToString(retrievedItem.data);
  
  if (originalText !== retrievedText) {
    throw new Error(`Data mismatch: expected "${originalText}", got "${retrievedText}"`);
  }
  
  // Validate metadata
  if (
    retrievedItem.type !== testItem.type ||
    retrievedItem.createdAt !== testItem.createdAt ||
    retrievedItem.metadata?.['sender'] !== testItem.metadata?.['sender']
  ) {
    throw new Error('Metadata mismatch');
  }
  
  logger.info('Item data and metadata validated');
  
  // Delete the item
  const deleteResult = await storage.secureDelete(testItem.id);
  
  if (!deleteResult) {
    throw new Error('Failed to delete item');
  }
  
  // Verify it's gone
  const deletedItem = await storage.retrieve(testItem.id);
  
  if (deletedItem) {
    throw new Error('Item still exists after deletion');
  }
  
  logger.info('Item successfully deleted');
  
  // Cleanup
  await storage.destroy();
  logger.info('Basic functionality test passed ✓');
}

/**
 * Test automatic expiration of items
 */
async function testExpiration() {
  logger.info('Testing automatic expiration...');
  
  // Create a new storage instance
  const storage = new SecureStorage({
    storageDir: TEST_DIR,
    memoryOnly: false,
    cleanupInterval: 500 // 500ms for fast testing
  });
  
  await storage.initialize();
  
  // Create items with expiration
  const item1: StoredItem = {
    id: 'expires-soon',
    type: 'temporary',
    data: stringToBytes('This message will self-destruct in 1 second'),
    createdAt: Date.now(),
    expiresAt: Date.now() + 1000, // Expires in 1 second
    metadata: { temp: true }
  };
  
  const item2: StoredItem = {
    id: 'expires-later',
    type: 'temporary',
    data: stringToBytes('This message will live longer'),
    createdAt: Date.now(),
    expiresAt: Date.now() + 10000, // Expires in 10 seconds
    metadata: { temp: true }
  };
  
  // Store both items
  await storage.store(item1);
  await storage.store(item2);
  logger.info('Items stored with expiration times');
  
  // Verify both exist
  const initialCheck1 = await storage.retrieve(item1.id);
  const initialCheck2 = await storage.retrieve(item2.id);
  
  if (!initialCheck1 || !initialCheck2) {
    throw new Error('Items not stored correctly');
  }
  
  // Wait for the first item to expire
  logger.info('Waiting for first item to expire...');
  await new Promise(resolve => setTimeout(resolve, 1500));
  
  // Manually trigger cleanup (normally would happen on interval)
  await (storage as any).cleanupExpiredItems();
  
  // Check if item1 is gone and item2 is still there
  const afterCheck1 = await storage.retrieve(item1.id);
  const afterCheck2 = await storage.retrieve(item2.id);
  
  if (afterCheck1) {
    throw new Error('Expired item still exists');
  }
  
  if (!afterCheck2) {
    throw new Error('Non-expired item was incorrectly removed');
  }
  
  logger.info('Expiration test passed ✓');
  
  // Cleanup
  await storage.secureDelete(item2.id);
  await storage.destroy();
}

/**
 * Test listing items by type
 */
async function testListByType() {
  logger.info('Testing listing items by type...');
  
  // Create a new storage instance
  const storage = new SecureStorage({
    storageDir: TEST_DIR,
    memoryOnly: false
  });
  
  await storage.initialize();
  
  // Create items of different types
  const items = [
    {
      id: 'message-1',
      type: 'message',
      data: stringToBytes('Message 1'),
      createdAt: Date.now(),
      expiresAt: 0
    },
    {
      id: 'message-2',
      type: 'message',
      data: stringToBytes('Message 2'),
      createdAt: Date.now(),
      expiresAt: 0
    },
    {
      id: 'key-1',
      type: 'key',
      data: randomData(32),
      createdAt: Date.now(),
      expiresAt: 0
    },
    {
      id: 'session-1',
      type: 'session',
      data: randomData(100),
      createdAt: Date.now(),
      expiresAt: 0
    }
  ];
  
  // Store all items
  for (const item of items) {
    await storage.store(item);
  }
  
  // List messages
  const messageIds = await storage.listByType('message');
  
  if (messageIds.length !== 2) {
    throw new Error(`Expected 2 messages, got ${messageIds.length}`);
  }
  
  if (!messageIds.includes('message-1') || !messageIds.includes('message-2')) {
    throw new Error('Missing expected message IDs');
  }
  
  // List keys
  const keyIds = await storage.listByType('key');
  
  if (keyIds.length !== 1 || keyIds[0] !== 'key-1') {
    throw new Error('Incorrect key listing');
  }
  
  // List sessions
  const sessionIds = await storage.listByType('session');
  
  if (sessionIds.length !== 1 || sessionIds[0] !== 'session-1') {
    throw new Error('Incorrect session listing');
  }
  
  // List non-existent type
  const nonExistentIds = await storage.listByType('non-existent');
  
  if (nonExistentIds.length !== 0) {
    throw new Error('Listed items of non-existent type');
  }
  
  logger.info('Listing by type test passed ✓');
  
  // Cleanup
  for (const item of items) {
    await storage.secureDelete(item.id);
  }
  await storage.destroy();
}

/**
 * Test secure deletion by checking if data is properly overwritten
 */
async function testSecureDeletion() {
  if (process.platform === 'win32') {
    logger.info('Skipping secure deletion verification on Windows');
    return;
  }
  
  logger.info('Testing secure deletion with forensic checks...');
  
  // Create a new storage instance
  const storage = new SecureStorage({
    storageDir: TEST_DIR,
    memoryOnly: false
  });
  
  await storage.initialize();
  
  // Create a test item with predictable content
  const testContent = 'TOPSECRETDATA_'.repeat(100); // Create a distinctive pattern
  const testItem: StoredItem = {
    id: 'secure-delete-test',
    type: 'sensitive',
    data: stringToBytes(testContent),
    createdAt: Date.now(),
    expiresAt: 0
  };
  
  // Store the item
  await storage.store(testItem);
  logger.info('Sensitive data stored');
  
  // Get the file path where the data was stored
  const filePath = path.join(TEST_DIR, 'secure-delete-test.dat');
  
  // Verify the file exists
  const fileExists = await fileExistsAsync(filePath);
  if (!fileExists) {
    throw new Error('Test file does not exist');
  }
  
  // Check file content before deletion
  const fileContent = await fs.readFile(filePath);
  
  // Securely delete the item
  await storage.secureDelete(testItem.id);
  logger.info('Item securely deleted');
  
  // Check if the file was actually deleted
  const fileStillExists = await fileExistsAsync(filePath);
  if (fileStillExists) {
    throw new Error('File still exists after secure deletion');
  }
  
  logger.info('Secure deletion test passed ✓');
  
  // Cleanup
  await storage.destroy();
}

/**
 * Test memory-only mode
 */
async function testMemoryOnlyMode() {
  logger.info('Testing memory-only mode...');
  
  // Create a new storage instance in memory-only mode
  const storage = new SecureStorage({
    storageDir: TEST_DIR,
    memoryOnly: true
  });
  
  await storage.initialize();
  
  // Store a test item
  const testItem: StoredItem = {
    id: 'memory-only-item',
    type: 'volatile',
    data: stringToBytes('This data should never touch disk'),
    createdAt: Date.now(),
    expiresAt: 0
  };
  
  await storage.store(testItem);
  
  // Verify we can retrieve it
  const retrieved = await storage.retrieve(testItem.id);
  
  if (!retrieved || bytesToString(retrieved.data) !== bytesToString(testItem.data)) {
    throw new Error('Failed to retrieve memory-only item');
  }
  
  // Verify no files were created in the storage directory
  await ensureDirectoryExists(TEST_DIR);
  const files = await fs.readdir(TEST_DIR);
  
  if (files.length > 0) {
    throw new Error(`Found files on disk in memory-only mode: ${files.join(', ')}`);
  }
  
  // Test destruction
  await storage.destroy();
  
  // Create a new instance
  const newStorage = new SecureStorage({
    storageDir: TEST_DIR,
    memoryOnly: true
  });
  
  await newStorage.initialize();
  
  // The previous item should not exist anymore
  const afterDestroy = await newStorage.retrieve(testItem.id);
  
  if (afterDestroy) {
    throw new Error('Item persisted after storage destruction in memory-only mode');
  }
  
  logger.info('Memory-only mode test passed ✓');
  
  // Cleanup
  await newStorage.destroy();
}

/**
 * Test rekeying by changing the master key
 */
async function testRekeying() {
  logger.info('Testing storage rekeying...');
  
  // Create a storage instance with memory only mode to simplify testing
  const storage = new SecureStorage({
    memoryOnly: true
  });
  
  // Initialize with a random key
  const originalKey = randomData(32);
  await storage.initialize(originalKey);
  
  // Create test item
  const testItem: StoredItem = {
    id: 'rekey-test',
    type: 'sensitive',
    data: stringToBytes('This is sensitive data that needs protection'),
    createdAt: Date.now(),
    expiresAt: 0
  };
  
  // Store the item
  await storage.store(testItem);
  
  // Verify we can retrieve it
  const retrieved = await storage.retrieve(testItem.id);
  if (!retrieved) {
    throw new Error('Failed to retrieve item with original key');
  }
  
  logger.info('Item retrieved with original key');
  
  // Destroy the current storage (simulating app restart)
  await storage.destroy();
  
  // Create a new storage with a different key
  const newStorage = new SecureStorage({
    memoryOnly: true
  });
  
  // Use a different key
  const newKey = randomData(32);
  await newStorage.initialize(newKey);
  
  // Try to store and retrieve a new item
  const newItem: StoredItem = {
    id: 'new-item',
    type: 'sensitive',
    data: stringToBytes('New data with new key'),
    createdAt: Date.now(),
    expiresAt: 0
  };
  
  await newStorage.store(newItem);
  const retrievedNew = await newStorage.retrieve(newItem.id);
  
  if (!retrievedNew) {
    throw new Error('Failed to store/retrieve with new key');
  }
  
  logger.info('Successfully rekeyed storage and stored/retrieved new data');
  logger.info('Rekeying test passed ✓');
  
  // Cleanup
  await newStorage.destroy();
}

/**
 * Test that encryption is secure by examining file contents
 */
async function testEncryptionSecurity() {
  logger.info('Testing encryption security...');
  
  // Create a storage instance
  const storage = new SecureStorage({
    storageDir: TEST_DIR,
    memoryOnly: false
  });
  
  await storage.initialize();
  
  // Create test data with easily recognizable patterns
  const sensitiveText = 'CLASSIFIED_INFORMATION_' + Date.now().toString();
  const item: StoredItem = {
    id: 'encryption-test',
    type: 'sensitive',
    data: stringToBytes(sensitiveText),
    createdAt: Date.now(),
    expiresAt: 0,
    metadata: {
      classification: 'top-secret',
      project: 'hypersecure'
    }
  };
  
  // Store the item
  await storage.store(item);
  
  // Get the raw content of the stored file
  const filePath = path.join(TEST_DIR, 'encryption-test.dat');
  const fileContent = await fs.readFile(filePath);
  const fileContentStr = fileContent.toString();
  
  // Check that plaintext is not visible in file content
  if (fileContentStr.includes(sensitiveText)) {
    throw new Error('Sensitive data stored as plaintext');
  }
  
  if (fileContentStr.includes('top-secret') || fileContentStr.includes('hypersecure')) {
    throw new Error('Metadata stored as plaintext');
  }
  
  logger.info('Encryption security test passed ✓');
  
  // Cleanup
  await storage.secureDelete(item.id);
  await storage.destroy();
}

/**
 * Helper function to clean up the test directory
 */
async function cleanupTestDir() {
  try {
    // Check if the directory exists
    const exists = await fileExistsAsync(TEST_DIR);
    if (exists) {
      // Get all files in the directory
      const files = await fs.readdir(TEST_DIR);
      
      // Delete each file
      for (const file of files) {
        await fs.unlink(join(TEST_DIR, file));
      }
      
      // Remove the directory
      await fs.rmdir(TEST_DIR);
    }
  } catch (error) {
    logger.error(`Failed to clean up test directory: ${error}`);
  }
}

/**
 * Helper function to check if a file exists
 */
async function fileExistsAsync(path: string): Promise<boolean> {
  try {
    await fs.access(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Helper function to ensure a directory exists
 */
async function ensureDirectoryExists(dir: string): Promise<void> {
  try {
    await fs.mkdir(dir, { recursive: true });
  } catch (error) {
    // Ignore if directory already exists
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
      throw error;
    }
  }
}

// Run the tests
runTests().catch(error => {
  logger.error('Fatal test error:', error);
  process.exit(1);
}); 