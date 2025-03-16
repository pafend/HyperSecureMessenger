/**
 * Secure Integration Example for X3DH and Double Ratchet
 * 
 * This file demonstrates how to use the X3DH Key Exchange Protocol
 * together with the Secure Double Ratchet Algorithm to create a complete
 * secure messaging protocol with proper AEAD encryption.
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import * as x3dh from './x3dh';
import * as secureDoubleRatchet from './secureDoubleRatchet';
import { utf8Encode, utf8Decode } from '../utils/encoding';
import { bytesToHex } from '../utils/encoding';

/**
 * Setup a secure messaging session between two users
 * 
 * This function demonstrates the complete flow from key exchange to
 * message encryption and decryption using proper AEAD encryption.
 */
export async function demonstrateSecureMessagingSetup(): Promise<void> {
  await sodium.ready;
  logger.info('Sodium initialized');
  
  // Step 1: Generate identity keys for Alice and Bob
  logger.info('Generating identity keys');
  const aliceIdentityKeyPair = await x3dh.generateIdentityKeyPair();
  const bobIdentityKeyPair = await x3dh.generateIdentityKeyPair();
  
  // Step 2: Generate signed pre-key and one-time pre-key for Bob
  logger.info('Generating pre-keys');
  const bobSignedPreKey = await x3dh.generateSignedPreKey(bobIdentityKeyPair, 1);
  const bobOneTimePreKeys = await x3dh.generateOneTimePreKeys(100, 1);
  const bobOneTimePreKey = bobOneTimePreKeys[0];
  
  // Step 3: Create Bob's pre-key bundle
  logger.info('Creating pre-key bundle');
  const bobBundle = await x3dh.createPreKeyBundle(
    bobIdentityKeyPair,
    bobSignedPreKey,
    bobOneTimePreKey
  );
  
  // Step 4: Alice initiates a key exchange with Bob
  logger.info('Initiating key exchange');
  const aliceX3DHResult = await x3dh.initiateKeyExchange(
    aliceIdentityKeyPair,
    bobBundle
  );
  
  // Step 5: Bob processes the key exchange message
  logger.info('Processing key exchange');
  const bobX3DHResult = await x3dh.processKeyExchange(
    bobIdentityKeyPair,
    bobSignedPreKey,
    aliceX3DHResult.initialMessage,
    bobOneTimePreKey
  );
  
  // Step 6: Initialize Secure Double Ratchet for Bob using the shared secret from X3DH
  logger.info('Initializing Secure Double Ratchet for Bob');
  const bobDRState = await secureDoubleRatchet.initializeReceiver(
    bobX3DHResult.sharedSecret,
    aliceX3DHResult.initialMessage.ephemeralKey,
    'alice'
  );
  
  // Step 7: Initialize Secure Double Ratchet for Alice using the shared secret from X3DH
  logger.info('Initializing Secure Double Ratchet for Alice');
  const aliceDRState = await secureDoubleRatchet.initializeSender(
    aliceX3DHResult.sharedSecret,
    'bob'
  );
  
  // Set Bob's public key in Alice's state
  logger.info('Setting Bob\'s public key in Alice\'s state');
  aliceDRState.DHr = bobDRState.DHs!.publicKey;
  
  // Step 8: Alice encrypts a message to Bob
  const aliceMessage = utf8Encode('Hello Bob! This is a secure message.');
  logger.info('Alice encrypting message');
  const [aliceEncryptedMsg, updatedAliceDRState] = await secureDoubleRatchet.encrypt(
    aliceDRState,
    aliceMessage
  );
  
  // Step 9: Bob decrypts Alice's message
  logger.info('Bob decrypting message');
  try {
    const [bobDecryptedMsg, updatedBobDRState] = await secureDoubleRatchet.decrypt(
      bobDRState,
      aliceEncryptedMsg
    );
    
    // Compare the original message bytes with the decrypted bytes
    const originalMsgHex = bytesToHex(aliceMessage);
    const decryptedMsgHex = bytesToHex(bobDecryptedMsg);
    
    logger.info(`Original message bytes: ${originalMsgHex}`);
    logger.info(`Decrypted message bytes: ${decryptedMsgHex}`);
    
    // Verify that the decryption was successful
    const decryptedText = utf8Decode(bobDecryptedMsg);
    logger.info(`Original message: ${utf8Decode(aliceMessage)}`);
    logger.info(`Decrypted message: ${decryptedText}`);
    
    if (utf8Decode(aliceMessage) !== decryptedText) {
      logger.error('Message decryption failed!');
      logger.error(`Expected: "${utf8Decode(aliceMessage)}"`);
      logger.error(`Got: "${decryptedText}"`);
    } else {
      logger.info('Message successfully decrypted!');
    }
    
    // Step 10: Bob responds to Alice
    const bobResponse = utf8Encode('Hello Alice! I received your secure message.');
    logger.info('Bob encrypting response');
    const [bobEncryptedMsg, _updatedBobDRState2] = await secureDoubleRatchet.encrypt(
      updatedBobDRState,
      bobResponse
    );
    
    // Step 11: Alice decrypts Bob's response
    logger.info('Alice decrypting response');
    const [aliceDecryptedMsg, _updatedAliceDRState2] = await secureDoubleRatchet.decrypt(
      updatedAliceDRState,
      bobEncryptedMsg
    );
    
    // Verify that the decryption was successful
    const decryptedResponse = utf8Decode(aliceDecryptedMsg);
    logger.info(`Original response: ${utf8Decode(bobResponse)}`);
    logger.info(`Decrypted response: ${decryptedResponse}`);
    
    if (utf8Decode(bobResponse) !== decryptedResponse) {
      logger.error('Response decryption failed!');
      logger.error(`Expected: "${utf8Decode(bobResponse)}"`);
      logger.error(`Got: "${decryptedResponse}"`);
    } else {
      logger.info('Response successfully decrypted!');
    }
    
    logger.info('Secure messaging session established successfully!');
  } catch (error) {
    logger.error('Error during secure messaging:', error);
  }
}

/**
 * A more complete secure messaging session would include:
 * - Secure storage of keys and session states
 * - Proper serialization/deserialization of messages and states
 * - Session management (creating, updating, and destroying sessions)
 * - Identity verification
 * - Anti-forensic measures
 * - Post-quantum protection
 * - Metadata protection
 * 
 * Future improvements:
 * 1. Implement proper AEAD encryption for message content
 * 2. Add support for group messaging
 * 3. Implement session management
 * 4. Add secure persistence of keys and states
 * 5. Implement perfect forward secrecy for stored messages
 */

// If this file is executed directly, run the demo
if (require.main === module) {
  demonstrateSecureMessagingSetup()
    .then(() => logger.info('Demo completed successfully!'))
    .catch(error => {
      logger.error('Demo failed:', error);
      process.exit(1);
    });
} 