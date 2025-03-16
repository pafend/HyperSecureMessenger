/**
 * Minimal Integration Test
 * 
 * This file demonstrates a minimal secure messaging setup
 * using our basic Double Ratchet implementation.
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { bytesToHex, stringToBytes, bytesToString } from '../utils/encoding';
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

    // 1. Generate a shared secret (in a real app, this would come from X3DH)
    logger.info('Generating shared secret...');
    const sharedSecret = sodium.randombytes_buf(32);
    logger.info(`Shared secret: ${bytesToHex(sharedSecret).slice(0, 16)}...`);

    // 2. Generate identity keys for both parties
    logger.info('Generating identity keys...');
    const aliceKeyPair = sodium.crypto_box_keypair();
    const bobKeyPair = sodium.crypto_box_keypair();

    logger.info(`Alice's public key: ${bytesToHex(aliceKeyPair.publicKey).slice(0, 16)}...`);
    logger.info(`Bob's public key: ${bytesToHex(bobKeyPair.publicKey).slice(0, 16)}...`);

    // 3. Initialize Double Ratchet
    logger.info('Initializing Double Ratchet...');
    
    // Alice initializes as sender
    let aliceState = await doubleRatchet.init(
      sharedSecret,
      BOB_ID,
      bobKeyPair.publicKey
    );
    
    // Bob initializes as receiver
    let bobState = await doubleRatchet.init(
      sharedSecret,
      ALICE_ID,
      aliceKeyPair.publicKey
    );

    // 4. Send a message from Alice to Bob
    const messageText = "Hello Bob! This is a secure message.";
    logger.info(`Alice sending message: "${messageText}"`);
    
    const messagePlaintext = stringToBytes(messageText);
    let [encryptedMessage, newAliceState] = await doubleRatchet.encrypt(
      aliceState,
      messagePlaintext
    );
    aliceState = newAliceState;
    
    // 5. Bob receives and decrypts the message
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
    
    // 6. Send a reply from Bob to Alice
    const replyText = "Hi Alice! I received your message securely.";
    logger.info(`Bob sending reply: "${replyText}"`);
    
    const replyPlaintext = stringToBytes(replyText);
    let [encryptedReply, newBobState] = await doubleRatchet.encrypt(
      bobState,
      replyPlaintext
    );
    bobState = newBobState;
    
    // 7. Alice receives and decrypts the reply
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
    
    // 8. Send another message from Alice to Bob (to test ratchet rotation)
    const message3Text = "This is another message to test ratchet rotation.";
    logger.info(`Alice sending message 3: "${message3Text}"`);
    
    const message3Plaintext = stringToBytes(message3Text);
    let [encryptedMessage3, newAliceState3] = await doubleRatchet.encrypt(
      aliceState,
      message3Plaintext
    );
    aliceState = newAliceState3;
    
    // 9. Bob receives and decrypts the third message
    logger.info('Bob receiving message 3...');
    
    try {
      const [decryptedMessage3, newBobState3] = await doubleRatchet.decrypt(
        bobState,
        encryptedMessage3
      );
      bobState = newBobState3;
      
      const decryptedMessage3Text = bytesToString(decryptedMessage3);
      logger.info(`Bob decrypted message 3: "${decryptedMessage3Text}"`);
      
      if (decryptedMessage3Text === message3Text) {
        logger.info('Message 3 decryption successful! ✓');
      } else {
        logger.error('Message 3 content mismatch! ✗');
        logger.error(`Expected: "${message3Text}", got: "${decryptedMessage3Text}"`);
      }
    } catch (error) {
      logger.error('Message 3 decryption failed:', error);
      throw error;
    }
    
    logger.info('Integration test completed successfully! 🎉');
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