/**
 * Tests for the TrustedRatchet module
 * 
 * This test verifies the trusted ratchet implementation
 * with in-person key exchange and symmetric chain derivation.
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import * as TrustedRatchet from './trustedRatchet';

// Test User IDs
const ALICE_ID = 'alice@hypersecure.chat';
const BOB_ID = 'bob@hypersecure.chat';

/**
 * Run all tests for the trusted ratchet
 */
async function runTests() {
  try {
    // Initialize sodium
    await sodium.ready;
    logger.info('Sodium initialized for testing trusted ratchet');

    // Run tests
    await testBasicEncryptionDecryption();
    await testChainKeyDerivation();
    await testRekeying();
    await testOutOfOrderMessages();

    logger.info('All trusted ratchet tests completed successfully! 🎉');
  } catch (error) {
    logger.error('Test failed:', error);
    throw error;
  }
}

/**
 * Test basic encryption and decryption
 */
async function testBasicEncryptionDecryption() {
  logger.info('Testing basic encryption and decryption...');

  // Simulate an in-person exchange of a shared secret
  const sharedSecret = sodium.randombytes_buf(32);

  // Initialize sessions for Alice and Bob
  const aliceSession = TrustedRatchet.initSession(ALICE_ID, BOB_ID, sharedSecret);
  const bobSession = TrustedRatchet.initSession(BOB_ID, ALICE_ID, sharedSecret);

  // Alice encrypts a message for Bob
  const plaintext = 'Hello Bob, this is a secure message!';
  const plaintextBytes = new TextEncoder().encode(plaintext);

  const encrypted = TrustedRatchet.encrypt(aliceSession, plaintextBytes);
  logger.info(`Alice encrypted message of ${plaintextBytes.length} bytes`);

  // Bob decrypts the message from Alice
  const decryptedBytes = TrustedRatchet.decrypt(bobSession, encrypted);
  const decryptedText = new TextDecoder().decode(decryptedBytes);

  if (decryptedText !== plaintext) {
    throw new Error(`Decryption failed. Expected: "${plaintext}", got: "${decryptedText}"`);
  }

  logger.info('Basic encryption/decryption test passed ✓');
}

/**
 * Test that chain keys advance properly
 */
async function testChainKeyDerivation() {
  logger.info('Testing chain key derivation...');

  // Shared secret
  const sharedSecret = sodium.randombytes_buf(32);

  // Initialize sessions
  const aliceSession = TrustedRatchet.initSession(ALICE_ID, BOB_ID, sharedSecret);
  const bobSession = TrustedRatchet.initSession(BOB_ID, ALICE_ID, sharedSecret);

  // Exchange 5 messages from Alice to Bob
  for (let i = 0; i < 5; i++) {
    const message = `Message ${i + 1} from Alice to Bob`;
    const messageBytes = new TextEncoder().encode(message);

    // Alice encrypts
    const encrypted = TrustedRatchet.encrypt(aliceSession, messageBytes);

    // Bob decrypts
    const decrypted = TrustedRatchet.decrypt(bobSession, encrypted);
    const decryptedText = new TextDecoder().decode(decrypted);

    if (decryptedText !== message) {
      throw new Error(`Message ${i + 1} decryption failed`);
    }

    logger.info(`Message ${i + 1} exchanged successfully`);
  }

  // Now exchange 5 messages from Bob to Alice
  for (let i = 0; i < 5; i++) {
    const message = `Message ${i + 1} from Bob to Alice`;
    const messageBytes = new TextEncoder().encode(message);

    // Bob encrypts
    const encrypted = TrustedRatchet.encrypt(bobSession, messageBytes);

    // Alice decrypts
    const decrypted = TrustedRatchet.decrypt(aliceSession, encrypted);
    const decryptedText = new TextDecoder().decode(decrypted);

    if (decryptedText !== message) {
      throw new Error(`Message ${i + 1} decryption failed`);
    }

    logger.info(`Message ${i + 1} exchanged successfully`);
  }

  logger.info('Chain key derivation test passed ✓');
}

/**
 * Test rekeying functionality
 */
async function testRekeying() {
  logger.info('Testing rekeying...');

  // Shared secret
  const sharedSecret = sodium.randombytes_buf(32);

  // Initialize sessions
  const aliceSession = TrustedRatchet.initSession(ALICE_ID, BOB_ID, sharedSecret);
  const bobSession = TrustedRatchet.initSession(BOB_ID, ALICE_ID, sharedSecret);

  // Send a message before rekeying
  const beforeMessage = 'Message before rekeying';
  const beforeBytes = new TextEncoder().encode(beforeMessage);
  
  const encryptedBefore = TrustedRatchet.encrypt(aliceSession, beforeBytes);
  const decryptedBefore = TrustedRatchet.decrypt(bobSession, encryptedBefore);
  
  if (new TextDecoder().decode(decryptedBefore) !== beforeMessage) {
    throw new Error('Pre-rekey message decryption failed');
  }

  // Rekey both sessions
  TrustedRatchet.rekeySession(aliceSession);
  TrustedRatchet.rekeySession(bobSession);
  logger.info('Sessions rekeyed');

  // Send a message after rekeying
  const afterMessage = 'Message after rekeying';
  const afterBytes = new TextEncoder().encode(afterMessage);
  
  const encryptedAfter = TrustedRatchet.encrypt(aliceSession, afterBytes);
  const decryptedAfter = TrustedRatchet.decrypt(bobSession, encryptedAfter);
  
  if (new TextDecoder().decode(decryptedAfter) !== afterMessage) {
    throw new Error('Post-rekey message decryption failed');
  }

  logger.info('Rekeying test passed ✓');
}

/**
 * Test handling of out-of-order messages
 */
async function testOutOfOrderMessages() {
  logger.info('Testing out-of-order message handling...');

  // Shared secret
  const sharedSecret = sodium.randombytes_buf(32);

  // Initialize sessions
  const aliceSession = TrustedRatchet.initSession(ALICE_ID, BOB_ID, sharedSecret);
  const bobSession = TrustedRatchet.initSession(BOB_ID, ALICE_ID, sharedSecret);

  // Alice encrypts 3 messages
  const message1 = 'Message 1: This should arrive first';
  const message2 = 'Message 2: This might be delayed';
  const message3 = 'Message 3: This could arrive before message 2';

  const encrypted1 = TrustedRatchet.encrypt(aliceSession, new TextEncoder().encode(message1));
  const encrypted2 = TrustedRatchet.encrypt(aliceSession, new TextEncoder().encode(message2));
  const encrypted3 = TrustedRatchet.encrypt(aliceSession, new TextEncoder().encode(message3));

  // Bob receives and decrypts messages in a different order: 1, 3, 2
  const decrypted1 = TrustedRatchet.decrypt(bobSession, encrypted1);
  if (new TextDecoder().decode(decrypted1) !== message1) {
    throw new Error('First message decryption failed');
  }

  // Decrypt message 3 before message 2
  const decrypted3 = TrustedRatchet.decrypt(bobSession, encrypted3);
  if (new TextDecoder().decode(decrypted3) !== message3) {
    throw new Error('Third message decryption failed');
  }

  // Finally decrypt message 2
  const decrypted2 = TrustedRatchet.decrypt(bobSession, encrypted2);
  if (new TextDecoder().decode(decrypted2) !== message2) {
    throw new Error('Second message decryption failed');
  }

  logger.info('Out-of-order message test passed ✓');
}

// Run all tests
runTests().catch(error => {
  logger.error('Fatal test error:', error);
  process.exit(1);
}); 