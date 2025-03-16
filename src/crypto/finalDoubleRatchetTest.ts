/**
 * Test for the final Double Ratchet implementation
 * 
 * This file tests the basic functionality of the Double Ratchet algorithm
 * without dependencies on X3DH or other components.
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { bytesToHex, stringToBytes, bytesToString } from '../utils/encoding';
import * as doubleRatchet from './finalDoubleRatchet';

/**
 * Main test function
 */
async function runTest() {
  try {
    // Initialize sodium
    await sodium.ready;
    logger.info('Sodium initialized');

    // Generate a shared secret (simulating the result of X3DH)
    const sharedSecret = sodium.randombytes_buf(32);
    logger.info('Generated shared secret:', bytesToHex(sharedSecret).slice(0, 16) + '...');

    // Generate identity key pairs for Alice and Bob
    const aliceKeyPair = sodium.crypto_box_keypair();
    const bobKeyPair = sodium.crypto_box_keypair();
    
    logger.info('Generated key pairs for Alice and Bob');
    logger.info('Alice public key:', bytesToHex(aliceKeyPair.publicKey).slice(0, 16) + '...');
    logger.info('Bob public key:', bytesToHex(bobKeyPair.publicKey).slice(0, 16) + '...');

    // Alice initializes as sender with Bob's public key
    let aliceState = await doubleRatchet.initSender(
      sharedSecret,
      'bob',
      bobKeyPair.publicKey
    );
    logger.info('Alice initialized ratchet state with Bob\'s public key');
    
    // Bob initializes as receiver with Alice's public key
    let bobState = await doubleRatchet.initReceiver(
      sharedSecret,
      aliceKeyPair.publicKey,
      'alice'
    );
    logger.info('Bob initialized ratchet state with Alice\'s public key');
    
    // Now we can test message exchange
    
    // 1. Alice sends a message to Bob
    const message1Text = "Hello Bob! This is a secure message from Alice.";
    logger.info(`Alice sending message: "${message1Text}"`);
    
    const message1Plaintext = stringToBytes(message1Text);
    let [message1Encrypted, aliceStateAfterMsg1] = await doubleRatchet.encrypt(
      aliceState,
      message1Plaintext
    );
    aliceState = aliceStateAfterMsg1;
    
    // Bob receives and decrypts the message
    logger.info('Bob receiving message...');
    
    try {
      const [message1Decrypted, bobStateAfterMsg1] = await doubleRatchet.decrypt(
        bobState,
        message1Encrypted
      );
      bobState = bobStateAfterMsg1;
      
      const message1DecryptedText = bytesToString(message1Decrypted);
      logger.info(`Bob decrypted message: "${message1DecryptedText}"`);
      
      if (message1DecryptedText === message1Text) {
        logger.info('Message 1 decryption successful! ✓');
      } else {
        logger.error('Message 1 content mismatch! ✗');
        logger.error(`Expected: "${message1Text}", got: "${message1DecryptedText}"`);
      }
    } catch (error) {
      logger.error('Message 1 decryption failed:', error);
      throw error;
    }
    
    // 2. Bob sends a reply to Alice
    const message2Text = "Hello Alice! This is a secure reply from Bob.";
    logger.info(`Bob sending message: "${message2Text}"`);
    
    const message2Plaintext = stringToBytes(message2Text);
    let [message2Encrypted, bobStateAfterMsg2] = await doubleRatchet.encrypt(
      bobState,
      message2Plaintext
    );
    bobState = bobStateAfterMsg2;
    
    // Alice receives and decrypts the message
    logger.info('Alice receiving message...');
    
    try {
      const [message2Decrypted, aliceStateAfterMsg2] = await doubleRatchet.decrypt(
        aliceState,
        message2Encrypted
      );
      aliceState = aliceStateAfterMsg2;
      
      const message2DecryptedText = bytesToString(message2Decrypted);
      logger.info(`Alice decrypted message: "${message2DecryptedText}"`);
      
      if (message2DecryptedText === message2Text) {
        logger.info('Message 2 decryption successful! ✓');
      } else {
        logger.error('Message 2 content mismatch! ✗');
        logger.error(`Expected: "${message2Text}", got: "${message2DecryptedText}"`);
      }
    } catch (error) {
      logger.error('Message 2 decryption failed:', error);
      throw error;
    }
    
    // 3. Alice sends another message to test ratchet rotation
    const message3Text = "This is another message to test ratchet rotation.";
    logger.info(`Alice sending message: "${message3Text}"`);
    
    const message3Plaintext = stringToBytes(message3Text);
    let [message3Encrypted, aliceStateAfterMsg3] = await doubleRatchet.encrypt(
      aliceState,
      message3Plaintext
    );
    aliceState = aliceStateAfterMsg3;
    
    // Bob receives and decrypts the message
    logger.info('Bob receiving message...');
    
    try {
      const [message3Decrypted, bobStateAfterMsg3] = await doubleRatchet.decrypt(
        bobState,
        message3Encrypted
      );
      bobState = bobStateAfterMsg3;
      
      const message3DecryptedText = bytesToString(message3Decrypted);
      logger.info(`Bob decrypted message: "${message3DecryptedText}"`);
      
      if (message3DecryptedText === message3Text) {
        logger.info('Message 3 decryption successful! ✓');
      } else {
        logger.error('Message 3 content mismatch! ✗');
        logger.error(`Expected: "${message3Text}", got: "${message3DecryptedText}"`);
      }
    } catch (error) {
      logger.error('Message 3 decryption failed:', error);
      throw error;
    }
    
    // 4. Test out-of-order messages
    logger.info('Testing out-of-order messages...');
    
    // Alice sends 3 messages in a row
    const outOfOrderMsg1 = "Message 1 (will be received in order)";
    const outOfOrderMsg2 = "Message 2 (will be delayed)";
    const outOfOrderMsg3 = "Message 3 (will be received before message 2)";
    
    logger.info(`Alice sending message 1: "${outOfOrderMsg1}"`);
    const outOfOrderPlaintext1 = stringToBytes(outOfOrderMsg1);
    let [outOfOrderEncrypted1, aliceStateAfterOoo1] = await doubleRatchet.encrypt(
      aliceState,
      outOfOrderPlaintext1
    );
    aliceState = aliceStateAfterOoo1;
    
    logger.info(`Alice sending message 2: "${outOfOrderMsg2}"`);
    const outOfOrderPlaintext2 = stringToBytes(outOfOrderMsg2);
    let [outOfOrderEncrypted2, aliceStateAfterOoo2] = await doubleRatchet.encrypt(
      aliceState,
      outOfOrderPlaintext2
    );
    aliceState = aliceStateAfterOoo2;
    
    logger.info(`Alice sending message 3: "${outOfOrderMsg3}"`);
    const outOfOrderPlaintext3 = stringToBytes(outOfOrderMsg3);
    let [outOfOrderEncrypted3, aliceStateAfterOoo3] = await doubleRatchet.encrypt(
      aliceState,
      outOfOrderPlaintext3
    );
    aliceState = aliceStateAfterOoo3;
    
    // Bob receives message 1
    logger.info('Bob receiving message 1...');
    const [outOfOrderDecrypted1, bobStateAfterOoo1] = await doubleRatchet.decrypt(
      bobState,
      outOfOrderEncrypted1
    );
    bobState = bobStateAfterOoo1;
    
    const outOfOrderDecryptedText1 = bytesToString(outOfOrderDecrypted1);
    logger.info(`Bob decrypted message 1: "${outOfOrderDecryptedText1}"`);
    
    if (outOfOrderDecryptedText1 === outOfOrderMsg1) {
      logger.info('Out-of-order message 1 decryption successful! ✓');
    } else {
      logger.error('Out-of-order message 1 content mismatch! ✗');
    }
    
    // Bob receives message 3 (out of order)
    logger.info('Bob receiving message 3 (out of order)...');
    const [outOfOrderDecrypted3, bobStateAfterOoo3] = await doubleRatchet.decrypt(
      bobState,
      outOfOrderEncrypted3
    );
    bobState = bobStateAfterOoo3;
    
    const outOfOrderDecryptedText3 = bytesToString(outOfOrderDecrypted3);
    logger.info(`Bob decrypted message 3: "${outOfOrderDecryptedText3}"`);
    
    if (outOfOrderDecryptedText3 === outOfOrderMsg3) {
      logger.info('Out-of-order message 3 decryption successful! ✓');
    } else {
      logger.error('Out-of-order message 3 content mismatch! ✗');
    }
    
    // Finally, Bob receives message 2 (delayed)
    logger.info('Bob receiving message 2 (delayed)...');
    const [outOfOrderDecrypted2, bobStateAfterOoo2] = await doubleRatchet.decrypt(
      bobState,
      outOfOrderEncrypted2
    );
    bobState = bobStateAfterOoo2;
    
    const outOfOrderDecryptedText2 = bytesToString(outOfOrderDecrypted2);
    logger.info(`Bob decrypted message 2: "${outOfOrderDecryptedText2}"`);
    
    if (outOfOrderDecryptedText2 === outOfOrderMsg2) {
      logger.info('Out-of-order message 2 decryption successful! ✓');
    } else {
      logger.error('Out-of-order message 2 content mismatch! ✗');
    }
    
    // Test successful
    logger.info('All tests passed! 🎉');
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