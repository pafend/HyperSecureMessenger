/**
 * Simple integration test for X3DH + Double Ratchet
 * 
 * This file demonstrates the basic flow of establishing a secure
 * communication channel using our simple X3DH for initial key exchange
 * and our basic Double Ratchet for message encryption.
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { bytesToHex, stringToBytes, bytesToString } from '../utils/encoding';
import * as x3dh from './simpleX3DH';
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
    const aliceIdentityKeyPair = sodium.crypto_box_keypair();
    const bobIdentityKeyPair = sodium.crypto_box_keypair();

    const aliceIdentity: x3dh.IdentityKey = {
      id: ALICE_ID,
      keyPair: aliceIdentityKeyPair
    };

    const bobIdentity: x3dh.IdentityKey = {
      id: BOB_ID,
      keyPair: bobIdentityKeyPair
    };

    // 2. Bob generates his pre-key bundle
    logger.info("Generating Bob's pre-key bundle...");
    const bobSignedPreKey = sodium.crypto_box_keypair();
    const bobOneTimePreKey = sodium.crypto_box_keypair();
    
    // For demonstration, we'll use a simple signature
    // Create a random signature for testing purposes
    const bobPreKeySignature = sodium.randombytes_buf(32);

    const bobPreKeyBundle: x3dh.PreKeyBundle = {
      identity: {
        id: BOB_ID,
        publicKey: bobIdentityKeyPair.publicKey
      },
      signedPreKey: {
        id: 1,
        publicKey: bobSignedPreKey.publicKey,
        signature: bobPreKeySignature
      },
      oneTimePreKey: {
        id: 100,
        publicKey: bobOneTimePreKey.publicKey
      }
    };

    // Bob's key storage
    const bobKeyStorage: x3dh.KeyStorage = {
      signedPreKey: {
        id: 1,
        keyPair: bobSignedPreKey
      },
      oneTimePreKeys: new Map([
        [100, bobOneTimePreKey]
      ])
    };

    // 3. Alice initiates X3DH with Bob's bundle
    logger.info('Alice initiating X3DH with Bob...');
    
    const [aliceSharedSecret, initiationMessage] = await x3dh.initiateKeyExchange(
      aliceIdentity,
      bobPreKeyBundle
    );

    logger.info('Alice derived shared secret:', bytesToHex(aliceSharedSecret).slice(0, 16) + '...');

    // 4. Bob processes the X3DH initiation
    logger.info('Bob processing X3DH initiation...');
    const bobSharedSecret = await x3dh.processKeyExchange(
      bobIdentity,
      bobKeyStorage,
      initiationMessage
    );

    logger.info('Bob derived shared secret:', bytesToHex(bobSharedSecret).slice(0, 16) + '...');

    // Verify both sides derived the same shared secret
    if (bytesToHex(aliceSharedSecret) !== bytesToHex(bobSharedSecret)) {
      throw new Error('Shared secret mismatch!');
    }
    
    logger.info('Shared secrets match! ✓');

    // 5. Initialize Double Ratchet
    logger.info('Initializing Double Ratchet...');
    
    // Alice initializes as sender
    let aliceState = await doubleRatchet.init(
      aliceSharedSecret,
      BOB_ID,
      bobPreKeyBundle.signedPreKey.publicKey
    );
    
    // Bob initializes as receiver with Alice's public key from the initiation message
    let bobState = await doubleRatchet.init(
      bobSharedSecret,
      ALICE_ID,
      initiationMessage.identityKey
    );

    // 6. Send a message from Alice to Bob
    const messageText = "Hello Bob! This is a secure message.";
    logger.info(`Alice sending message: "${messageText}"`);
    
    const messagePlaintext = stringToBytes(messageText);
    let [encryptedMessage, newAliceState] = await doubleRatchet.encrypt(
      aliceState,
      messagePlaintext
    );
    aliceState = newAliceState;
    
    // 7. Bob receives and decrypts the message
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
        logger.info('Message decryption successful! ✓');
      } else {
        logger.error('Message content mismatch! ✗');
        logger.error(`Expected: "${messageText}", got: "${decryptedText}"`);
      }
    } catch (error) {
      logger.error('Decryption failed:', error);
      throw error;
    }
    
    // 8. Send a reply from Bob to Alice
    const replyText = "Hi Alice! I received your message securely.";
    logger.info(`Bob sending reply: "${replyText}"`);
    
    const replyPlaintext = stringToBytes(replyText);
    let [encryptedReply, newBobState] = await doubleRatchet.encrypt(
      bobState,
      replyPlaintext
    );
    bobState = newBobState;
    
    // 9. Alice receives and decrypts the reply
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
        logger.info('Reply decryption successful! ✓');
      } else {
        logger.error('Reply content mismatch! ✗');
        logger.error(`Expected: "${replyText}", got: "${decryptedReplyText}"`);
      }
    } catch (error) {
      logger.error('Reply decryption failed:', error);
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