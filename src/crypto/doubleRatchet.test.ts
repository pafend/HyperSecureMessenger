/**
 * Tests for the Double Ratchet Algorithm implementation
 */

import sodium from 'libsodium-wrappers-sumo';
import {
  initializeSender,
  initializeReceiver,
  encrypt,
  decrypt,
  DoubleRatchetState
} from './mockDoubleRatchet';
import { utf8Encode, utf8Decode } from '../utils/encoding';

/**
 * Test the full end-to-end Double Ratchet flow
 */
export async function testDoubleRatchet(): Promise<void> {
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
    const aliceState = await initializeSender(sharedSecret, 'bob-id');
    console.log('Alice state initialized');
    
    const bobState = await initializeReceiver(sharedSecret, bobKeyPair.publicKey, 'alice-id');
    console.log('Bob state initialized');
    
    // Set Bob's public key in Alice's state
    aliceState.DHr = bobState.DHs?.publicKey || null;
    
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
  const aliceMessage = utf8Encode('Hello Bob! This is a secure message.');
  const [encryptedMsg, updatedAliceState] = await encrypt(aliceState, aliceMessage);
  console.log('Alice encrypted message');
  
  // Bob receives and decrypts the message
  const [decryptedMsg, updatedBobState] = await decrypt(bobState, encryptedMsg);
  console.log('Bob decrypted message');
  
  // Verify that the decrypted message matches the original
  const decryptedText = utf8Decode(decryptedMsg);
  const originalText = utf8Decode(aliceMessage);
  
  if (decryptedText !== originalText) {
    throw new Error(`Message decryption failed. Expected: "${originalText}", got: "${decryptedText}"`);
  }
  
  console.log('Basic message exchange test passed');
  
  // Update the states
  Object.assign(aliceState, updatedAliceState);
  Object.assign(bobState, updatedBobState);
  
  // Bob sends a response to Alice
  const bobResponse = utf8Encode('Hello Alice! I received your secure message.');
  const [responseMsg, _unused1] = await encrypt(bobState, bobResponse);
  console.log('Bob encrypted response');
  
  // Alice receives and decrypts the response
  const [decryptedResponse, _unused2] = await decrypt(aliceState, responseMsg);
  console.log('Alice decrypted response');
  
  // Verify that the decrypted response matches the original
  const decryptedResponseText = utf8Decode(decryptedResponse);
  const originalResponseText = utf8Decode(bobResponse);
  
  if (decryptedResponseText !== originalResponseText) {
    throw new Error(`Response decryption failed. Expected: "${originalResponseText}", got: "${decryptedResponseText}"`);
  }
  
  console.log('Response message exchange test passed');
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
  const aliceState = await initializeSender(sharedSecret, 'bob-id');
  const bobState = await initializeReceiver(sharedSecret, bobKeyPair.publicKey, 'alice-id');
  
  // Set Bob's public key in Alice's state
  aliceState.DHr = bobState.DHs?.publicKey || null;
  
  // Alice sends multiple messages
  const message1 = utf8Encode('Message 1');
  const message2 = utf8Encode('Message 2');
  const message3 = utf8Encode('Message 3');
  
  // Encrypt the messages
  const [encrypted1, updatedAliceState1] = await encrypt(aliceState, message1);
  Object.assign(aliceState, updatedAliceState1);
  
  const [encrypted2, updatedAliceState2] = await encrypt(aliceState, message2);
  Object.assign(aliceState, updatedAliceState2);
  
  const [encrypted3, _unused3] = await encrypt(aliceState, message3);
  
  console.log('Alice encrypted 3 messages');
  
  // Bob receives them out of order: 3, 1, 2
  const [decrypted3, updatedBobState3] = await decrypt(bobState, encrypted3);
  Object.assign(bobState, updatedBobState3);
  console.log('Bob decrypted message 3 (out of order)');
  
  const [decrypted1, updatedBobState1] = await decrypt(bobState, encrypted1);
  Object.assign(bobState, updatedBobState1);
  console.log('Bob decrypted message 1 (out of order)');
  
  const [decrypted2, _unused4] = await decrypt(bobState, encrypted2);
  console.log('Bob decrypted message 2 (out of order)');
  
  // Verify that all messages were decrypted correctly
  const text1 = utf8Decode(decrypted1);
  const text2 = utf8Decode(decrypted2);
  const text3 = utf8Decode(decrypted3);
  
  if (text1 !== 'Message 1' || text2 !== 'Message 2' || text3 !== 'Message 3') {
    throw new Error('Out-of-order message decryption failed');
  }
  
  console.log('Out-of-order message delivery test passed');
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
  const aliceState = await initializeSender(sharedSecret, 'bob-id');
  const bobState = await initializeReceiver(sharedSecret, bobKeyPair.publicKey, 'alice-id');
  
  // Set Bob's public key in Alice's state
  aliceState.DHr = bobState.DHs?.publicKey || null;
  
  // Initial message exchange
  const message1 = utf8Encode('Initial message');
  const [encrypted1, updatedAliceState1] = await encrypt(aliceState, message1);
  Object.assign(aliceState, updatedAliceState1);
  
  const [_unused7, updatedBobState1] = await decrypt(bobState, encrypted1);
  Object.assign(bobState, updatedBobState1);
  
  console.log('Initial message exchange successful');
  
  // Bob sends a message to trigger a ratchet rotation in Alice
  const response = utf8Encode('Response to trigger ratchet');
  const [encryptedResponse, updatedBobState2] = await encrypt(bobState, response);
  Object.assign(bobState, updatedBobState2);
  
  const [_unused8, updatedAliceState2] = await decrypt(aliceState, encryptedResponse);
  Object.assign(aliceState, updatedAliceState2);
  
  console.log('Ratchet rotation triggered');
  
  // Send a new message from Alice to Bob (with new ratchet)
  const message2 = utf8Encode('Message after ratchet rotation');
  const [encrypted2, _unused5] = await encrypt(aliceState, message2);
  
  const [decrypted2, _unused6] = await decrypt(bobState, encrypted2);
  
  // Verify message
  const text2 = utf8Decode(decrypted2);
  if (text2 !== 'Message after ratchet rotation') {
    throw new Error('Ratchet rotation message decryption failed');
  }
  
  console.log('Ratchet rotation test passed');
}

// When running this file directly, execute the tests
if (require.main === module) {
  testDoubleRatchet()
    .then(() => console.log('All tests completed successfully!'))
    .catch(error => {
      console.error('Tests failed:', error);
      process.exit(1);
    });
} 