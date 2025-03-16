/**
 * Simple Double Ratchet Implementation
 * 
 * This is a minimal implementation of the Double Ratchet algorithm
 * designed to demonstrate the core concepts with minimal complexity.
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
    // Derive initial chain key
    const [newRootKey, chainKey] = deriveKeys(
      state.rootKey,
      deriveSharedSecret(state.keyPair.privateKey, remotePublicKey)
    );
    
    state.rootKey = newRootKey;
    state.sendingKey = chainKey;
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
    
    // Derive chain keys
    const [newRootKey, chainKey] = deriveKeys(
      newState.rootKey,
      deriveSharedSecret(newState.keyPair.privateKey, newState.remotePublicKey)
    );
    
    newState.rootKey = newRootKey;
    newState.sendingKey = chainKey;
  }
  
  // Derive message key and next chain key
  const [messageKey, nextChainKey] = deriveChainKey(newState.sendingKey);
  newState.sendingKey = nextChainKey;
  
  // Create message header
  const header = {
    senderPublicKey: newState.keyPair.publicKey,
    messageNumber: newState.sendCount,
    previousChainLength: newState.previousSendCount
  };
  
  // Increment message counter
  newState.sendCount++;
  
  // Encrypt message
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
  
  // Check if we need to perform a DH ratchet step
  const samePublicKey = newState.remotePublicKey && 
                        arraysEqual(message.header.senderPublicKey, newState.remotePublicKey);
  
  if (!samePublicKey) {
    // Store the new remote public key
    newState.remotePublicKey = new Uint8Array(message.header.senderPublicKey);
    
    // Update counters
    newState.previousSendCount = newState.sendCount;
    newState.sendCount = 0;
    newState.receiveCount = 0;
    
    // Derive new receiving chain key
    const [newRootKey, chainKey] = deriveKeys(
      newState.rootKey,
      deriveSharedSecret(newState.keyPair.privateKey, newState.remotePublicKey)
    );
    
    newState.rootKey = newRootKey;
    newState.receivingKey = chainKey;
    
    // Generate new key pair
    const newKeyPair = sodium.crypto_box_keypair();
    
    // Derive new sending chain key
    const [newerRootKey, sendingChainKey] = deriveKeys(
      newState.rootKey,
      deriveSharedSecret(newKeyPair.privateKey, newState.remotePublicKey)
    );
    
    newState.rootKey = newerRootKey;
    newState.sendingKey = sendingChainKey;
    newState.keyPair = newKeyPair;
  }
  
  // Skip to the correct message key
  let messageKey: Uint8Array;
  
  if (newState.receivingKey === null) {
    throw new Error('No receiving chain key available');
  }
  
  let currentKey = newState.receivingKey;
  
  // Skip ahead to the right message number
  for (let i = newState.receiveCount; i < message.header.messageNumber; i++) {
    const [_, nextKey] = deriveChainKey(currentKey);
    currentKey = nextKey;
  }
  
  // Derive the message key and next chain key
  const [derivedMessageKey, nextChainKey] = deriveChainKey(currentKey);
  messageKey = derivedMessageKey;
  
  // Update state
  newState.receivingKey = nextChainKey;
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
 * Derive a shared secret using DH
 * 
 * @param privateKey - My private key
 * @param publicKey - Their public key
 * @returns Shared secret
 */
function deriveSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  // In a real implementation, this would use crypto_scalarmult
  // For simplicity, we'll use a key derivation function
  
  const combined = new Uint8Array(privateKey.length + publicKey.length);
  combined.set(privateKey);
  combined.set(publicKey, privateKey.length);
  
  return sodium.crypto_generichash(32, combined);
}

/**
 * Derive new keys from a root key and shared secret
 * 
 * @param rootKey - Current root key
 * @param sharedSecret - DH output
 * @returns New root key and chain key
 */
function deriveKeys(rootKey: Uint8Array, sharedSecret: Uint8Array): [Uint8Array, Uint8Array] {
  const combined = new Uint8Array(rootKey.length + sharedSecret.length);
  combined.set(rootKey);
  combined.set(sharedSecret, rootKey.length);
  
  const output = sodium.crypto_generichash(64, combined);
  
  return [
    output.slice(0, 32),  // New root key
    output.slice(32, 64)  // Chain key
  ];
}

/**
 * Derive message key and next chain key
 * 
 * @param chainKey - Current chain key
 * @returns Message key and next chain key
 */
function deriveChainKey(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  // Derive message key
  const messageKeyInput = new Uint8Array(chainKey.length + 1);
  messageKeyInput.set(chainKey);
  messageKeyInput[chainKey.length] = 1; // Constant for message key
  const messageKey = sodium.crypto_generichash(32, messageKeyInput);
  
  // Derive next chain key
  const chainKeyInput = new Uint8Array(chainKey.length + 1);
  chainKeyInput.set(chainKey);
  chainKeyInput[chainKey.length] = 2; // Constant for chain key
  const nextChainKey = sodium.crypto_generichash(32, chainKeyInput);
  
  return [messageKey, nextChainKey];
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
 * Compare two arrays for equality
 * 
 * @param a - First array
 * @param b - Second array
 * @returns Whether arrays are equal
 */
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  
  return true;
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