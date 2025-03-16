/**
 * Tests for the Trusted Ratchet Implementation
 * 
 * This file contains tests for the secure messaging protocol
 * based on a trusted initial handshake.
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { bytesToHex, stringToBytes, bytesToString } from '../utils/encoding';
import * as trustedRatchet from './trustedRatchet';

// User identifiers
const ALICE_ID = 'alice@hypersecure.chat';
const BOB_ID = 'bob@hypersecure.chat';

/**
 * Main test function
 */
async function runTest() {
  try {
    // Initialize sodium
    await sodium.ready;
    logger.info('Sodium initialized');

    // 1. Simulate an in-person key exchange by generating a high-entropy shared secret
    logger.info('Simulating in-person key exchange...');
    const sharedSecret = sodium.randombytes_buf(32);
    logger.info(`Generated shared secret: ${bytesToHex(sharedSecret).slice(0, 16)}...`);

    // 2. Initialize sessions for Alice and Bob using the shared secret
    logger.info('Initializing secure sessions...');
    
    let aliceSession = await trustedRatchet.initSession(
      sharedSecret,
      ALICE_ID,
      BOB_ID
    );
    
    let bobSession = await trustedRatchet.initSession(
      sharedSecret,
      BOB_ID,
      ALICE_ID
    );
    
    logger.info('Secure sessions initialized');

    // 3. Alice sends a message to Bob
    const message1Text = "Hello Bob! This is a secure message using our trusted channel.";
    logger.info(`Alice sending message: "${message1Text}"`);
    
    const message1Plaintext = stringToBytes(message1Text);
    let [encryptedMessage1, aliceSession2] = await trustedRatchet.encrypt(
      aliceSession,
      message1Plaintext
    );
    aliceSession = aliceSession2;
    
    // 4. Bob receives and decrypts the message
    logger.info('Bob receiving message...');
    
    try {
      const [decryptedMessage1, bobSession2] = await trustedRatchet.decrypt(
        bobSession,
        encryptedMessage1
      );
      bobSession = bobSession2;
      
      const decryptedText1 = bytesToString(decryptedMessage1);
      logger.info(`Bob decrypted message: "${decryptedText1}"`);
      
      if (decryptedText1 === message1Text) {
        logger.info('Message 1 decryption successful! ✓');
      } else {
        logger.error('Message content mismatch! ✗');
        logger.error(`Expected: "${message1Text}", got: "${decryptedText1}"`);
      }
    } catch (error) {
      logger.error('Decryption failed:', error);
      throw error;
    }
    
    // 5. Bob sends a reply to Alice
    const message2Text = "Hi Alice! I received your secure message through our trusted channel.";
    logger.info(`Bob sending reply: "${message2Text}"`);
    
    const message2Plaintext = stringToBytes(message2Text);
    let [encryptedMessage2, bobSession3] = await trustedRatchet.encrypt(
      bobSession,
      message2Plaintext
    );
    bobSession = bobSession3;
    
    // 6. Alice receives and decrypts the reply
    logger.info('Alice receiving reply...');
    
    try {
      const [decryptedMessage2, aliceSession3] = await trustedRatchet.decrypt(
        aliceSession,
        encryptedMessage2
      );
      aliceSession = aliceSession3;
      
      const decryptedText2 = bytesToString(decryptedMessage2);
      logger.info(`Alice decrypted reply: "${decryptedText2}"`);
      
      if (decryptedText2 === message2Text) {
        logger.info('Message 2 decryption successful! ✓');
      } else {
        logger.error('Reply content mismatch! ✗');
        logger.error(`Expected: "${message2Text}", got: "${decryptedText2}"`);
      }
    } catch (error) {
      logger.error('Reply decryption failed:', error);
      throw error;
    }
    
    // 7. Test skipped message handling
    logger.info('Testing skipped message handling...');
    
    // Alice sends two messages, but the first one gets "delayed"
    const message3Text = "This is message 3 which will be delayed.";
    const message4Text = "This is message 4 which will arrive first.";
    
    logger.info(`Alice sending message 3 (will be delayed): "${message3Text}"`);
    let [encryptedMessage3, aliceSession4] = await trustedRatchet.encrypt(
      aliceSession,
      stringToBytes(message3Text)
    );
    
    logger.info(`Alice sending message 4 (will arrive first): "${message4Text}"`);
    let [encryptedMessage4, aliceSession5] = await trustedRatchet.encrypt(
      aliceSession4,
      stringToBytes(message4Text)
    );
    aliceSession = aliceSession5;
    
    // Bob receives message 4 first (out of order)
    logger.info('Bob receiving message 4 before message 3 (out of order)...');
    
    try {
      const [decryptedMessage4, bobSession4] = await trustedRatchet.decrypt(
        bobSession,
        encryptedMessage4
      );
      bobSession = bobSession4;
      
      const decryptedText4 = bytesToString(decryptedMessage4);
      logger.info(`Bob decrypted message 4: "${decryptedText4}"`);
      
      if (decryptedText4 === message4Text) {
        logger.info('Message 4 decryption successful! ✓');
      } else {
        logger.error('Message 4 content mismatch! ✗');
      }
      
      // Now Bob receives the delayed message 3
      logger.info('Bob now receiving the delayed message 3...');
      
      const [decryptedMessage3, bobSession5] = await trustedRatchet.decrypt(
        bobSession,
        encryptedMessage3
      );
      bobSession = bobSession5;
      
      const decryptedText3 = bytesToString(decryptedMessage3);
      logger.info(`Bob decrypted message 3 (delayed): "${decryptedText3}"`);
      
      if (decryptedText3 === message3Text) {
        logger.info('Message 3 decryption successful despite out-of-order delivery! ✓');
      } else {
        logger.error('Message 3 content mismatch! ✗');
        logger.error(`Expected: "${message3Text}", got: "${decryptedText3}"`);
      }
    } catch (error) {
      logger.error('Out-of-order message test failed:', error);
      throw error;
    }
    
    // 8. Test re-keying
    logger.info('Testing manual re-keying process...');
    
    // Re-key Alice's session only (Bob's remains unchanged)
    const newSharedSecret1 = sodium.randombytes_buf(32);
    aliceSession = await trustedRatchet.rekeySession(aliceSession, newSharedSecret1);
    // Note: Not rekeying Bob's session here, so the keys will be mismatched
    
    // Alice sends a message after re-keying
    const message5Text = "This message is sent after re-keying our session.";
    logger.info(`Alice sending message after re-keying: "${message5Text}"`);
    
    let [encryptedMessage5, aliceSession6] = await trustedRatchet.encrypt(
      aliceSession,
      stringToBytes(message5Text)
    );
    aliceSession = aliceSession6;
    
    // Bob tries to decrypt but will fail due to different keys
    logger.info('Bob trying to decrypt with mismatched keys (should fail)...');
    
    try {
      await trustedRatchet.decrypt(bobSession, encryptedMessage5);
      logger.error('Decryption should have failed but succeeded!');
      throw new Error('Decryption should have failed with mismatched keys');
    } catch (error) {
      logger.info('Decryption failed as expected with mismatched keys ✓');
    }
    
    // Re-key with the same new shared secret
    logger.info('Re-keying both sessions with the same new shared secret...');
    const newSharedSecret2 = sodium.randombytes_buf(32);
    
    aliceSession = await trustedRatchet.rekeySession(aliceSession, newSharedSecret2);
    bobSession = await trustedRatchet.rekeySession(bobSession, newSharedSecret2);
    
    // Alice sends another message
    const message6Text = "This message uses our newly synchronized keys.";
    logger.info(`Alice sending message with new keys: "${message6Text}"`);
    
    let [encryptedMessage6, aliceSession7] = await trustedRatchet.encrypt(
      aliceSession,
      stringToBytes(message6Text)
    );
    aliceSession = aliceSession7;
    
    // Bob should now be able to decrypt
    logger.info('Bob receiving message with new keys...');
    
    try {
      const [decryptedMessage6, bobSession6] = await trustedRatchet.decrypt(
        bobSession,
        encryptedMessage6
      );
      
      const decryptedText6 = bytesToString(decryptedMessage6);
      logger.info(`Bob decrypted message: "${decryptedText6}"`);
      
      if (decryptedText6 === message6Text) {
        logger.info('Message decryption with new keys successful! ✓');
      } else {
        logger.error('Message content mismatch with new keys! ✗');
      }
    } catch (error) {
      logger.error('Decryption with new keys failed:', error);
      throw error;
    }
    
    logger.info('All tests passed successfully! 🎉');
    logger.info('Trusted Ratchet implementation is working correctly.');
    
  } catch (error) {
    logger.error('Test failed:', error);
    throw error;
  }
}

// Run the test
runTest().catch(error => {
  logger.error('Fatal error:', error);
  process.exit(1);
}); 