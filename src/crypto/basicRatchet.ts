/**
 * Basic Double Ratchet Implementation
 * 
 * This is a minimal implementation of the Double Ratchet algorithm
 * designed to demonstrate the core concepts with minimal complexity.
 * It focuses on getting the encryption/decryption working correctly.
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { bytesToHex } from '../utils/encoding';

// Message format
export interface Message {
  header: {
    senderPublicKey: Uint8Array;
    messageNumber: number;
    previousChainLength: number;
  };
  ciphertext: Uint8Array;
}

// State for Double Ratchet
export interface State {
  // My key pair
  keyPair: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  };
  
  // Their public key
  remotePublicKey: Uint8Array | null;
  
  // Root key (from initial shared secret)
  rootKey: Uint8Array;
  
  // Chain keys
  sendingKey: Uint8Array | null;
  receivingKey: Uint8Array | null;
  
  // Message counters
  sendCount: number;
  receiveCount: number;
  previousSendCount: number;
  
  // For debugging
  remoteId: string;
}

/**
 * Initialize a state for a new conversation
 * 
 * @param sharedSecret - Shared secret from key exchange
 * @param remoteId - ID of the remote peer
 * @param remotePublicKey - Remote public key (if known)
 */
export async function init(
  sharedSecret: Uint8Array,
  remoteId: string,
  remotePublicKey?: Uint8Array
): Promise<State> {
  await sodium.ready;
  
  // Generate key pair
  const keyPair = sodium.crypto_box_keypair();
  
  // Create initial state
  const state: State = {
    keyPair,
    remotePublicKey: remotePublicKey ? new Uint8Array(remotePublicKey) : null,
    rootKey: new Uint8Array(sharedSecret),
    sendingKey: null,
    receivingKey: null,
    sendCount: 0,
    receiveCount: 0,
    previousSendCount: 0,
    remoteId
  };
  
  // If we have the remote key, initialize sending chain
  if (remotePublicKey) {
    // For simplicity, just use the shared secret as the initial sending key
    state.sendingKey = new Uint8Array(sharedSecret);
  }
  
  return state;
}

/**
 * Encrypt a message
 * 
 * @param state - Current state
 * @param plaintext - Message to encrypt
 * @returns Encrypted message and new state
 */
export async function encrypt(
  state: State,
  plaintext: Uint8Array
): Promise<[Message, State]> {
  await sodium.ready;
  
  // Clone state to avoid modifying the original
  const newState = cloneState(state);
  
  // Ensure we have a sending chain key
  if (newState.sendingKey === null) {
    if (newState.remotePublicKey === null) {
      throw new Error('Cannot encrypt: remote public key not set');
    }
    
    // For simplicity, just use the root key as the sending key
    newState.sendingKey = new Uint8Array(newState.rootKey);
  }
  
  // Use the current sending key as the message key
  const messageKey = newState.sendingKey;
  
  // Derive next sending key (simple hash of current key)
  newState.sendingKey = sodium.crypto_generichash(32, newState.sendingKey);
  
  // Create message header
  const header = {
    senderPublicKey: newState.keyPair.publicKey,
    messageNumber: newState.sendCount,
    previousChainLength: newState.previousSendCount
  };
  
  // Increment message counter
  newState.sendCount++;
  
  // Encrypt message with simple XOR
  const ciphertext = simpleEncrypt(plaintext, messageKey);
  
  return [{ header, ciphertext }, newState];
}

/**
 * Decrypt a message
 * 
 * @param state - Current state
 * @param message - Encrypted message
 * @returns Decrypted message and new state
 */
export async function decrypt(
  state: State,
  message: Message
): Promise<[Uint8Array, State]> {
  await sodium.ready;
  
  // Clone state to avoid modifying the original
  const newState = cloneState(state);
  
  // Check if this is the first message we're receiving
  if (newState.receivingKey === null) {
    // For simplicity, just use the root key as the initial receiving key
    newState.receivingKey = new Uint8Array(newState.rootKey);
    newState.remotePublicKey = new Uint8Array(message.header.senderPublicKey);
  }
  
  // Skip to the correct message key
  let messageKey = new Uint8Array(newState.receivingKey);
  
  // Skip ahead to the right message number
  for (let i = newState.receiveCount; i < message.header.messageNumber; i++) {
    messageKey = sodium.crypto_generichash(32, messageKey);
  }
  
  // Derive the next receiving key
  newState.receivingKey = sodium.crypto_generichash(32, messageKey);
  newState.receiveCount = message.header.messageNumber + 1;
  
  // Decrypt message
  try {
    const plaintext = simpleDecrypt(message.ciphertext, messageKey);
    return [plaintext, newState];
  } catch (error) {
    logger.error('Decryption error:', error);
    throw new Error(`Decryption failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Very simple encryption (XOR with key)
 * 
 * @param plaintext - Data to encrypt
 * @param key - Encryption key
 * @returns Encrypted data
 */
function simpleEncrypt(plaintext: Uint8Array, key: Uint8Array): Uint8Array {
  const ciphertext = new Uint8Array(plaintext.length);
  
  for (let i = 0; i < plaintext.length; i++) {
    ciphertext[i] = plaintext[i] ^ key[i % key.length];
  }
  
  return ciphertext;
}

/**
 * Simple decryption (XOR with key)
 * 
 * @param ciphertext - Encrypted data
 * @param key - Decryption key
 * @returns Decrypted data
 */
function simpleDecrypt(ciphertext: Uint8Array, key: Uint8Array): Uint8Array {
  // XOR is symmetric, so encryption and decryption are the same
  return simpleEncrypt(ciphertext, key);
}

/**
 * Clone a state object
 * 
 * @param state - State to clone
 * @returns Cloned state
 */
function cloneState(state: State): State {
  return {
    keyPair: {
      publicKey: new Uint8Array(state.keyPair.publicKey),
      privateKey: new Uint8Array(state.keyPair.privateKey)
    },
    remotePublicKey: state.remotePublicKey ? new Uint8Array(state.remotePublicKey) : null,
    rootKey: new Uint8Array(state.rootKey),
    sendingKey: state.sendingKey ? new Uint8Array(state.sendingKey) : null,
    receivingKey: state.receivingKey ? new Uint8Array(state.receivingKey) : null,
    sendCount: state.sendCount,
    receiveCount: state.receiveCount,
    previousSendCount: state.previousSendCount,
    remoteId: state.remoteId
  };
} 