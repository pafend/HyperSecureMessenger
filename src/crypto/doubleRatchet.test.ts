/**
 * Tests for the Double Ratchet Algorithm implementation
 */

import sodium from 'libsodium-wrappers-sumo';
import {
  initializeSender,
  initializeReceiver,
  encrypt,
  decrypt,
  cleanup,
  DoubleRatchetKeyPair,
  DoubleRatchetState,
  EncryptedMessage
} from './doubleRatchet';

/**
 * Test the full end-to-end Double Ratchet flow
 */
async function testDoubleRatchet(): Promise<void> {
  console.log('Starting Double Ratchet tests...');
  
  // Wait for sodium to be ready
  await sodium.ready;
  console.log('Sodium initialized successfully');
  
  try {
    // Generate a shared secret (in a real app, this would come from a key exchange)
    const sharedSecret = sodium.randombytes_buf(32);
    console.log('Shared secret generated');
    
    // Generate Bob's initial key pair
    const bobKeyPair = sodium.crypto_box_keypair();
    console.log('Bob key pair generated');
    
    // Initialize Alice and Bob's ratchet states
    const aliceState = await initializeSender(sharedSecret, bobKeyPair.publicKey);
    console.log('Alice state initialized');
    
    const bobState = await initializeReceiver(sharedSecret, bobKeyPair);
    console.log('Bob state initialized');
    
    // Test a basic message exchange
    await testBasicExchange(aliceState, bobState);
    
    // Test out-of-order message delivery
    await testOutOfOrderMessages();
    
    // Test ratchet rotation
    await testRatchetRotation();
    
    console.log('All Double Ratchet tests passed successfully!');
  } catch (error) {
    console.error('Double Ratchet test failed:', error);
    throw error;
  }
}

/**
 * Test a basic message exchange between Alice and Bob
 */
async function testBasicExchange(
  aliceState: DoubleRatchetState,
  bobState: DoubleRatchetState
): Promise<void> {
  console.log('Testing basic message exchange...');
  
  // Alice sends a message to Bob
  const aliceMessage = new TextEncoder().encode('Hello Bob! This is a secure message.');
  const [encryptedMsg, aliceState2] = await encrypt(aliceState, aliceMessage);
  console.log('Alice encrypted message');
  
  // Bob receives and decrypts the message
  const [decryptedMsg, bobState2] = await decrypt(bobState, encryptedMsg);
  console.log('Bob decrypted message');
  
  // Verify that the decrypted message matches the original
  const decryptedText = new TextDecoder().decode(decryptedMsg);
  const originalText = new TextDecoder().decode(aliceMessage);
  
  if (decryptedText !== originalText) {
    throw new Error(`Message decryption failed. Expected: "${originalText}", got: "${decryptedText}"`);
  }
  
  console.log('Basic message exchange test passed');
  
  // Bob sends a response to Alice
  const bobResponse = new TextEncoder().encode('Hello Alice! I received your secure message.');
  const [encryptedResponse, bobState3] = await encrypt(bobState2, bobResponse);
  console.log('Bob encrypted response');
  
  // Alice receives and decrypts the response
  const [decryptedResponse, aliceState3] = await decrypt(aliceState2, encryptedResponse);
  console.log('Alice decrypted response');
  
  // Verify that the decrypted response matches the original
  const decryptedResponseText = new TextDecoder().decode(decryptedResponse);
  const originalResponseText = new TextDecoder().decode(bobResponse);
  
  if (decryptedResponseText !== originalResponseText) {
    throw new Error(`Response decryption failed. Expected: "${originalResponseText}", got: "${decryptedResponseText}"`);
  }
  
  console.log('Response message exchange test passed');
  
  // Clean up sensitive state data
  cleanup(aliceState3);
  cleanup(bobState3);
}

/**
 * Test out-of-order message delivery
 */
async function testOutOfOrderMessages(): Promise<void> {
  console.log('Testing out-of-order message delivery...');
  
  // Generate a shared secret
  const sharedSecret = sodium.randombytes_buf(32);
  
  // Generate Bob's initial key pair
  const bobKeyPair = sodium.crypto_box_keypair();
  
  // Initialize Alice and Bob's ratchet states
  const aliceState = await initializeSender(sharedSecret, bobKeyPair.publicKey);
  const bobState = await initializeReceiver(sharedSecret, bobKeyPair);
  
  // Alice sends multiple messages
  const message1 = new TextEncoder().encode('Message 1');
  const message2 = new TextEncoder().encode('Message 2');
  const message3 = new TextEncoder().encode('Message 3');
  
  // Encrypt the messages
  const [encrypted1, aliceState1] = await encrypt(aliceState, message1);
  const [encrypted2, aliceState2] = await encrypt(aliceState1, message2);
  const [encrypted3, aliceState3] = await encrypt(aliceState2, message3);
  
  console.log('Alice encrypted 3 messages');
  
  // Bob receives them out of order: 3, 1, 2
  const [decrypted3, bobState1] = await decrypt(bobState, encrypted3);
  console.log('Bob decrypted message 3 (out of order)');
  
  const [decrypted1, bobState2] = await decrypt(bobState1, encrypted1);
  console.log('Bob decrypted message 1 (out of order)');
  
  const [decrypted2, bobState3] = await decrypt(bobState2, encrypted2);
  console.log('Bob decrypted message 2 (out of order)');
  
  // Verify that all messages were decrypted correctly
  const text1 = new TextDecoder().decode(decrypted1);
  const text2 = new TextDecoder().decode(decrypted2);
  const text3 = new TextDecoder().decode(decrypted3);
  
  if (text1 !== 'Message 1' || text2 !== 'Message 2' || text3 !== 'Message 3') {
    throw new Error('Out-of-order message decryption failed');
  }
  
  console.log('Out-of-order message delivery test passed');
  
  // Clean up sensitive state data
  cleanup(aliceState3);
  cleanup(bobState3);
}

/**
 * Test ratchet rotation after DH ratchet step
 */
async function testRatchetRotation(): Promise<void> {
  console.log('Testing ratchet rotation...');
  
  // Generate a shared secret
  const sharedSecret = sodium.randombytes_buf(32);
  
  // Generate Bob's initial key pair
  const bobKeyPair = sodium.crypto_box_keypair();
  
  // Initialize Alice and Bob's ratchet states
  const aliceState = await initializeSender(sharedSecret, bobKeyPair.publicKey);
  const bobState = await initializeReceiver(sharedSecret, bobKeyPair);
  
  // Initial message exchange
  const message1 = new TextEncoder().encode('Initial message');
  const [encrypted1, aliceState1] = await encrypt(aliceState, message1);
  const [decrypted1, bobState1] = await decrypt(bobState, encrypted1);
  
  console.log('Initial message exchange successful');
  
  // Bob sends a message to trigger a ratchet rotation in Alice
  const response = new TextEncoder().encode('Response to trigger ratchet');
  const [encryptedResponse, bobState2] = await encrypt(bobState1, response);
  const [decryptedResponse, aliceState2] = await decrypt(aliceState1, encryptedResponse);
  
  console.log('Ratchet rotation triggered');
  
  // Send a new message from Alice to Bob (with new ratchet)
  const message2 = new TextEncoder().encode('Message after ratchet rotation');
  const [encrypted2, aliceState3] = await encrypt(aliceState2, message2);
  const [decrypted2, bobState3] = await decrypt(bobState2, encrypted2);
  
  // Verify message
  const text2 = new TextDecoder().decode(decrypted2);
  if (text2 !== 'Message after ratchet rotation') {
    throw new Error('Ratchet rotation message decryption failed');
  }
  
  console.log('Ratchet rotation test passed');
  
  // Clean up sensitive state data
  cleanup(aliceState3);
  cleanup(bobState3);
}

// Export the test functions for running via npm test
export {
  testDoubleRatchet,
  testBasicExchange,
  testOutOfOrderMessages,
  testRatchetRotation
};

// When running this file directly, execute the tests
if (require.main === module) {
  testDoubleRatchet()
    .then(() => console.log('All tests completed successfully!'))
    .catch(error => {
      console.error('Tests failed:', error);
      process.exit(1);
    });
} 