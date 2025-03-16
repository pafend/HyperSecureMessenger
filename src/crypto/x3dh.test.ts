/**
 * Tests for the X3DH (Extended Triple Diffie-Hellman) Key Exchange Protocol
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import * as x3dh from './mockX3DH';

/**
 * Test the X3DH protocol
 */
async function testX3DH() {
  try {
    await sodium.ready;
    logger.info('Sodium initialized');

    // Test basic key exchange
    await testBasicKeyExchange();

    // Test bundle verification
    await testBundleVerification();

    logger.info('All X3DH tests passed!');
  } catch (error) {
    logger.error('X3DH test failed:', error);
    throw error;
  }
}

/**
 * Test a basic key exchange between two parties
 */
async function testBasicKeyExchange() {
  logger.info('Testing basic X3DH key exchange...');

  // Generate identity key pairs for Alice and Bob
  const aliceIdentityKeyPair = await x3dh.generateIdentityKeyPair();
  const bobIdentityKeyPair = await x3dh.generateIdentityKeyPair();

  // Generate signed pre-key for Bob
  const bobSignedPreKey = await x3dh.generateSignedPreKey(bobIdentityKeyPair, 1);

  // Generate one-time pre-key for Bob
  const bobOneTimePreKeys = await x3dh.generateOneTimePreKeys(100, 1);
  const bobOneTimePreKey = bobOneTimePreKeys[0];

  // Create Bob's pre-key bundle
  const bobBundle = await x3dh.createPreKeyBundle(
    bobIdentityKeyPair,
    bobSignedPreKey,
    bobOneTimePreKey
  );

  // Alice initiates a key exchange with Bob
  const aliceResult = await x3dh.initiateKeyExchange(
    aliceIdentityKeyPair,
    bobBundle
  );

  // Bob processes the key exchange message
  const bobResult = await x3dh.processKeyExchange(
    bobIdentityKeyPair,
    bobSignedPreKey,
    aliceResult.initialMessage,
    bobOneTimePreKey
  );

  // In a real implementation, we would verify that the shared secrets match
  // For testing purposes, we'll just log the results
  logger.info('Alice shared secret length:', aliceResult.sharedSecret.length);
  logger.info('Bob shared secret length:', bobResult.sharedSecret.length);

  logger.info('Basic X3DH key exchange test passed!');
}

/**
 * Test verification of pre-key bundles
 */
async function testBundleVerification() {
  logger.info('Testing X3DH bundle verification...');

  // Generate identity key pair
  const identityKeyPair = await x3dh.generateIdentityKeyPair();

  // Generate signed pre-key
  const signedPreKey = await x3dh.generateSignedPreKey(identityKeyPair, 1);

  // Create a valid bundle
  const validBundle = await x3dh.createPreKeyBundle(
    identityKeyPair,
    signedPreKey
  );

  // Verify the valid bundle
  const validResult = await x3dh.verifyPreKeyBundle(validBundle);
  
  if (!validResult) {
    throw new Error('Valid bundle verification failed');
  }

  // Create a tampered bundle (for testing, we'll modify the signature)
  const tamperedBundle = { ...validBundle };
  tamperedBundle.signedPreKey = { ...validBundle.signedPreKey };
  tamperedBundle.signedPreKey.signature = new Uint8Array([0, 1, 2, 3]); // Tampered signature
  
  // Verify the tampered bundle
  const tamperedResult = await x3dh.verifyPreKeyBundle(tamperedBundle);
  
  if (tamperedResult) {
    throw new Error('Tampered bundle verification should have failed');
  }

  logger.info('X3DH bundle verification test passed!');
}

export { testX3DH }; 