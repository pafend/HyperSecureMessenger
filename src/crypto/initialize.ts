/**
 * Cryptographic subsystem initialization
 * Sets up all cryptographic primitives and verifies their integrity
 */

import * as sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';

/**
 * Initialize all cryptographic components
 * This ensures all required crypto primitives are available and working correctly
 */
export async function initializeCrypto(): Promise<void> {
  try {
    // Wait for sodium to be ready
    await sodium.ready;
    logger.info('Libsodium initialized successfully');
    
    // Verify that the implementation is working correctly
    const testMessage = new Uint8Array([1, 2, 3, 4, 5]);
    const keyPair = sodium.crypto_box_keypair();
    const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    
    // Test encryption/decryption
    const encrypted = sodium.crypto_box_easy(
      testMessage,
      nonce,
      keyPair.publicKey,
      keyPair.privateKey
    );
    
    const decrypted = sodium.crypto_box_open_easy(
      encrypted,
      nonce,
      keyPair.publicKey,
      keyPair.privateKey
    );
    
    // Verify that decryption works
    const isEqual = sodium.memcmp(testMessage, decrypted);
    if (!isEqual) {
      throw new Error('Cryptographic self-test failed: decryption mismatch');
    }
    
    // Test hash function
    const hash = sodium.crypto_hash(testMessage);
    if (hash.length !== sodium.crypto_hash_BYTES) {
      throw new Error('Cryptographic self-test failed: hash length incorrect');
    }
    
    // Test secure random number generation
    const random1 = sodium.randombytes_buf(32);
    const random2 = sodium.randombytes_buf(32);
    if (sodium.memcmp(random1, random2)) {
      throw new Error('Cryptographic self-test failed: RNG producing identical values');
    }
    
    logger.info('Cryptographic self-tests completed successfully');
    
    // Check if secure memory is available
    if (sodium.sodium_malloc && typeof sodium.sodium_malloc === 'function') {
      logger.info('Secure memory allocation available');
    } else {
      logger.warn('Secure memory allocation not available');
    }
    
    return;
  } catch (error) {
    logger.error('Failed to initialize cryptographic subsystem', error);
    throw new Error('Cryptographic initialization failed');
  }
} 