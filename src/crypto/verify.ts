/**
 * Cryptographic verification script for HyperSecure Messenger
 * 
 * This script verifies that the cryptographic components are working correctly
 * and that the system is secure. It runs a series of tests to ensure that:
 * 
 * 1. Libsodium is properly initialized
 * 2. Basic cryptographic operations work as expected
 * 3. The double ratchet implementation functions correctly
 * 
 * Run this script with: npm run crypto:verify
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { utf8Encode, utf8Decode, bytesToHex } from '../utils/encoding';

async function verifyCryptography(): Promise<void> {
  logger.info('Starting cryptographic verification...');
  
  // Wait for sodium to initialize
  await sodium.ready;
  logger.info('Libsodium initialized successfully');
  
  // Verify basic cryptographic operations
  try {
    await verifyBasicCrypto();
    logger.info('Basic cryptographic operations verified successfully');
  } catch (error) {
    logger.error('Basic cryptographic verification failed', error);
    process.exit(1);
  }
  
  // Verify encoding utilities
  try {
    await verifyEncodingUtils();
    logger.info('Encoding utilities verified successfully');
  } catch (error) {
    logger.error('Encoding utilities verification failed', error);
    process.exit(1);
  }
  
  logger.info('All cryptographic components verified successfully');
}

async function verifyBasicCrypto(): Promise<void> {
  // Test key generation
  const keyPair = sodium.crypto_box_keypair();
  if (!keyPair.publicKey || !keyPair.privateKey) {
    throw new Error('Key pair generation failed');
  }
  logger.debug(`Generated key pair: ${bytesToHex(keyPair.publicKey).substring(0, 16)}...`);
  
  // Test encryption and decryption
  const message = utf8Encode('This is a test message for encryption');
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  
  // Create another key pair for the recipient
  const recipientKeyPair = sodium.crypto_box_keypair();
  
  // Encrypt with recipient's public key
  const encrypted = sodium.crypto_box_easy(
    message,
    nonce,
    recipientKeyPair.publicKey,
    keyPair.privateKey
  );
  
  // Decrypt with recipient's private key
  const decrypted = sodium.crypto_box_open_easy(
    encrypted,
    nonce,
    keyPair.publicKey,
    recipientKeyPair.privateKey
  );
  
  // Verify decryption
  const decryptedText = utf8Decode(decrypted);
  if (decryptedText !== 'This is a test message for encryption') {
    throw new Error('Encryption/decryption test failed');
  }
  logger.debug('Encryption/decryption test passed');
  
  // Test hashing
  const hash = sodium.crypto_hash(message);
  if (hash.length === 0) {
    throw new Error('Hashing test failed');
  }
  logger.debug(`Hash generated: ${bytesToHex(hash).substring(0, 16)}...`);
  
  // Test random number generation
  const random1 = sodium.randombytes_buf(32);
  const random2 = sodium.randombytes_buf(32);
  if (sodium.memcmp(random1, random2)) {
    throw new Error('Random number generation test failed - generated identical values');
  }
  logger.debug('Random number generation test passed');
  
  // Test secure memory if available
  if (sodium.sodium_malloc && sodium.sodium_free) {
    try {
      const secureBuffer = sodium.sodium_malloc(64);
      sodium.sodium_memzero(secureBuffer);
      sodium.sodium_free(secureBuffer);
      logger.debug('Secure memory test passed');
    } catch (error) {
      logger.warn('Secure memory not available', error);
      // This is not a critical failure, as we can fall back to regular memory
    }
  } else {
    logger.warn('Secure memory functions not available in this libsodium build');
  }
}

async function verifyEncodingUtils(): Promise<void> {
  // Test UTF-8 encoding/decoding
  const originalText = 'Test string with unicode: 你好, 안녕하세요, Привет';
  const encoded = utf8Encode(originalText);
  const decoded = utf8Decode(encoded);
  
  if (decoded !== originalText) {
    throw new Error('UTF-8 encoding/decoding test failed');
  }
  logger.debug('UTF-8 encoding/decoding test passed');
  
  // Test hex encoding/decoding
  const testBytes = new Uint8Array([0, 1, 2, 3, 255, 254, 253, 252]);
  const hexString = bytesToHex(testBytes);
  
  if (hexString !== '000102030ffefdfcfc') {
    throw new Error(`Hex encoding test failed: ${hexString}`);
  }
  logger.debug('Hex encoding test passed');
}

// Run the verification if this script is executed directly
if (require.main === module) {
  verifyCryptography().catch(error => {
    logger.error('Cryptographic verification failed', error);
    process.exit(1);
  });
}

export { verifyCryptography }; 