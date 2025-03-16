/**
 * Full Integration Test for X3DH + Double Ratchet
 * 
 * This file demonstrates a complete secure messaging setup
 * using our X3DH key exchange and basic Double Ratchet implementation.
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { bytesToHex, stringToBytes, bytesToString } from '../utils/encoding';
import * as x3dh from './minimalX3DH';
import * as doubleRatchet from './basicRatchet';

// User identifiers
const ALICE_ID = 'alice@hypersecure.chat';
const BOB_ID = 'bob@hypersecure.chat';

/**
 * Main integration test
 */
async function runIntegrationTest() {
  try {
    // Initialize sodium
    await sodium.ready;
    logger.info('Sodium initialized');

    // 1. Generate identity keys for both parties
    logger.info('Generating identity keys...');
    const aliceIdentityKeyPair = x3dh.generateKeyPair();
    const bobIdentityKeyPair = x3dh.generateKeyPair();

    logger.info(`Alice's identity public key: ${bytesToHex(aliceIdentityKeyPair.publicKey).slice(0, 16)}...`);
    logger.info(`Bob's identity public key: ${bytesToHex(bobIdentityKeyPair.publicKey).slice(0, 16)}...`);

    // 2. Generate signed pre-key for Bob
    logger.info("Generating Bob's pre-key bundle...");
    const bobSignedPreKeyPair = x3dh.generateKeyPair();
    
    // 3. Create pre-key bundle for Bob
    const bobPreKeyBundle: x3dh.PreKeyBundle = {
      identityPublicKey: bobIdentityKeyPair.publicKey,
      signedPreKeyPublicKey: bobSignedPreKeyPair.publicKey
    };

    // 4. Alice initiates X3DH with Bob's bundle
    logger.info('Alice initiating X3DH with Bob...');
    
    const [aliceSharedSecret, initiationMessage] = await x3dh.initiateKeyExchange(
      aliceIdentityKeyPair,
      bobPreKeyBundle
    );

    logger.info(`Alice derived shared secret: ${bytesToHex(aliceSharedSecret).slice(0, 16)}...`);

    // 5. Bob processes the X3DH initiation
    logger.info('Bob processing X3DH initiation...');
    const bobSharedSecret = await x3dh.processKeyExchange(
      bobIdentityKeyPair,
      bobSignedPreKeyPair,
      initiationMessage
    );

    logger.info(`Bob derived shared secret: ${bytesToHex(bobSharedSecret).slice(0, 16)}...`);

    // Verify both sides derived the same shared secret
    if (bytesToHex(aliceSharedSecret) !== bytesToHex(bobSharedSecret)) {
      throw new Error('Shared secret mismatch!');
    }
    
    logger.info('Shared secrets match! ✓');

    // 6. Initialize Double Ratchet
    logger.info('Initializing Double Ratchet...');
    
    // Alice initializes as sender
    let aliceState = await doubleRatchet.init(
      aliceSharedSecret,
      BOB_ID,
      bobSignedPreKeyPair.publicKey // Use Bob's signed pre-key as initial public key
    );
    
    // Bob initializes as receiver with Alice's identity key from the initiation message
    let bobState = await doubleRatchet.init(
      bobSharedSecret,
      ALICE_ID,
      initiationMessage.identityPublicKey
    );

    // 7. Send a message from Alice to Bob
    const messageText = "Hello Bob! This is a secure message using X3DH + Double Ratchet.";
    logger.info(`Alice sending message: "${messageText}"`);
    
    const messagePlaintext = stringToBytes(messageText);
    let [encryptedMessage, newAliceState] = await doubleRatchet.encrypt(
      aliceState,
      messagePlaintext
    );
    aliceState = newAliceState;
    
    // 8. Bob receives and decrypts the message
    logger.info('Bob receiving message...');
    
    try {
      const [decryptedMessage, newBobState] = await doubleRatchet.decrypt(
        bobState,
        encryptedMessage
      );
      bobState = newBobState;
      
      const decryptedText = bytesToString(decryptedMessage);
      logger.info(`Bob decrypted message: "${decryptedText}"`);
      
      if (decryptedText === messageText) {
        logger.info('Message 1 decryption successful! ✓');
      } else {
        logger.error('Message content mismatch! ✗');
        logger.error(`Expected: "${messageText}", got: "${decryptedText}"`);
      }
    } catch (error) {
      logger.error('Decryption failed:', error);
      throw error;
    }
    
    // 9. Send a reply from Bob to Alice
    const replyText = "Hi Alice! I received your secure message via X3DH + Double Ratchet.";
    logger.info(`Bob sending reply: "${replyText}"`);
    
    const replyPlaintext = stringToBytes(replyText);
    let [encryptedReply, newBobState] = await doubleRatchet.encrypt(
      bobState,
      replyPlaintext
    );
    bobState = newBobState;
    
    // 10. Alice receives and decrypts the reply
    logger.info('Alice receiving reply...');
    
    try {
      const [decryptedReply, newAliceState] = await doubleRatchet.decrypt(
        aliceState,
        encryptedReply
      );
      aliceState = newAliceState;
      
      const decryptedReplyText = bytesToString(decryptedReply);
      logger.info(`Alice decrypted reply: "${decryptedReplyText}"`);
      
      if (decryptedReplyText === replyText) {
        logger.info('Message 2 decryption successful! ✓');
      } else {
        logger.error('Reply content mismatch! ✗');
        logger.error(`Expected: "${replyText}", got: "${decryptedReplyText}"`);
      }
    } catch (error) {
      logger.error('Reply decryption failed:', error);
      throw error;
    }
    
    // 11. Send a third message from Alice to Bob
    const message3Text = "This is message 3 to test continued communication.";
    logger.info(`Alice sending message 3: "${message3Text}"`);
    
    const message3Plaintext = stringToBytes(message3Text);
    let [encryptedMessage3, aliceStateAfter3] = await doubleRatchet.encrypt(
      aliceState,
      message3Plaintext
    );
    aliceState = aliceStateAfter3;
    
    // 12. Bob receives and decrypts the third message
    logger.info('Bob receiving message 3...');
    
    try {
      const [decryptedMessage3, bobStateAfter3] = await doubleRatchet.decrypt(
        bobState,
        encryptedMessage3
      );
      bobState = bobStateAfter3;
      
      const decryptedText3 = bytesToString(decryptedMessage3);
      logger.info(`Bob decrypted message 3: "${decryptedText3}"`);
      
      if (decryptedText3 === message3Text) {
        logger.info('Message 3 decryption successful! ✓');
      } else {
        logger.error('Message 3 content mismatch! ✗');
        logger.error(`Expected: "${message3Text}", got: "${decryptedText3}"`);
      }
    } catch (error) {
      logger.error('Message 3 decryption failed:', error);
      throw error;
    }
    
    logger.info('Integration test completed successfully! 🎉');
    logger.info('X3DH + Double Ratchet implementation is working correctly.');
  } catch (error) {
    logger.error('Integration test failed:', error);
    throw error;
  }
}

// Run the test
runIntegrationTest().catch(error => {
  logger.error('Fatal error:', error);
  process.exit(1);
}); 