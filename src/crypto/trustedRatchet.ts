/**
 * Trusted Ratchet Implementation
 * 
 * This implementation provides a secure messaging protocol based on:
 * 1. Initial trusted key exchange (in-person or other secure channel)
 * 2. Deterministic chain key derivation for continued communication
 * 3. Authenticated encryption for all messages
 * 
 * Designed for HyperSecure Messenger's high-security requirements.
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { bytesToHex } from '../utils/encoding';

// Maximum chain depth before re-keying is required
const MAX_CHAIN_DEPTH = 1000;

/**
 * Message structure for the trusted ratchet implementation
 */
export interface Message {
  // Ciphertext containing the encrypted message
  ciphertext: Uint8Array;
  // Message counter (used to handle out-of-order messages)
  counter: number;
  // Sender ID
  sender: string;
  // Receiver ID
  receiver: string;
  // Nonce used for encryption
  nonce: Uint8Array;
}

/**
 * Session state for the trusted ratchet implementation
 */
export interface SessionState {
  // Identity of the local user
  selfId: string;
  // Identity of the remote user
  peerId: string;
  // Root key for the session
  rootKey: Uint8Array;
  // Current sending chain key
  sendingKey: Uint8Array;
  // Current receiving chain key
  receivingKey: Uint8Array;
  // Next message number to be sent
  sendingCounter: number;
  // Message numbers that have been received
  receivedCounters: Map<number, boolean>;
  // Highest received counter
  maxReceivedCounter: number;
  // Skipped message keys (counter -> message key)
  skippedMessageKeys: Map<number, Uint8Array>;
  // Maximum number of skipped message keys to store
  maxSkip: number;
}

/**
 * Initialize a secure session using a trusted shared secret
 * 
 * @param sharedSecret High-entropy shared secret established through a trusted channel
 * @param selfId Identity of the local user
 * @param peerId Identity of the remote user
 * @returns Initialized session state
 */
export async function initSession(
  sharedSecret: Uint8Array,
  selfId: string,
  peerId: string
): Promise<SessionState> {
  await sodium.ready;
  
  // Derive the root key from the shared secret
  const rootKey = await deriveRootKey(sharedSecret);
  
  // Derive initial chain keys
  const [sendingKey, receivingKey] = await deriveInitialChainKeys(rootKey, selfId, peerId);
  
  return {
    selfId,
    peerId,
    rootKey,
    sendingKey,
    receivingKey,
    sendingCounter: 0,
    receivedCounters: new Map<number, boolean>(),
    maxReceivedCounter: -1,
    skippedMessageKeys: new Map<number, Uint8Array>(),
    maxSkip: 1000, // Maximum number of skipped messages to store
  };
}

/**
 * Encrypt a message using the current sending key
 * 
 * @param state Current session state
 * @param plaintext Message to encrypt
 * @returns Encrypted message and updated session state
 */
export async function encrypt(
  state: SessionState,
  plaintext: Uint8Array
): Promise<[Message, SessionState]> {
  await sodium.ready;
  
  // Create a new nonce for this message
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  
  // Derive the message key from the current sending key
  const messageKey = await deriveMessageKey(state.sendingKey, state.sendingCounter);
  
  // Encrypt the message
  const ciphertext = sodium.crypto_secretbox_easy(plaintext, nonce, messageKey);
  
  // Create the message object
  const message: Message = {
    ciphertext,
    counter: state.sendingCounter,
    sender: state.selfId,
    receiver: state.peerId,
    nonce
  };
  
  // Update the sending key
  const nextSendingKey = await advanceChainKey(state.sendingKey);
  
  // Create the new state
  const newState: SessionState = {
    ...state,
    sendingKey: nextSendingKey,
    sendingCounter: state.sendingCounter + 1
  };
  
  return [message, newState];
}

/**
 * Decrypt a message using the appropriate receiving key
 * 
 * @param state Current session state
 * @param message Encrypted message to decrypt
 * @returns Decrypted plaintext and updated session state
 */
export async function decrypt(
  state: SessionState,
  message: Message
): Promise<[Uint8Array, SessionState]> {
  await sodium.ready;
  
  // Check if message is from the expected peer
  if (message.sender !== state.peerId || message.receiver !== state.selfId) {
    throw new Error('Message has invalid sender or receiver');
  }
  
  // Check if we've already processed this message
  if (state.receivedCounters.has(message.counter)) {
    throw new Error('Duplicate message detected');
  }
  
  // Make a mutable copy of the state
  let newState = { ...state };
  let plaintext: Uint8Array;
  
  // Check if the message is from a skipped chain key
  if (newState.skippedMessageKeys.has(message.counter)) {
    // Use the stored message key to decrypt
    const messageKey = newState.skippedMessageKeys.get(message.counter)!;
    plaintext = sodium.crypto_secretbox_open_easy(message.ciphertext, message.nonce, messageKey);
    
    // Remove the used message key
    newState.skippedMessageKeys.delete(message.counter);
  } else if (message.counter <= newState.maxReceivedCounter) {
    // Message is too old and we don't have the key
    throw new Error('Message is too old');
  } else if (message.counter > newState.maxReceivedCounter + 1) {
    // This message is ahead of what we expected, so we need to skip some keys
    const numSkipped = message.counter - (newState.maxReceivedCounter + 1);
    
    if (numSkipped > newState.maxSkip) {
      throw new Error('Too many skipped messages');
    }
    
    // Store the skipped message keys
    let currentKey = newState.receivingKey;
    for (let i = newState.maxReceivedCounter + 1; i < message.counter; i++) {
      const skippedMessageKey = await deriveMessageKey(currentKey, i);
      newState.skippedMessageKeys.set(i, skippedMessageKey);
      currentKey = await advanceChainKey(currentKey);
    }
    
    // Derive the message key for this message
    const messageKey = await deriveMessageKey(currentKey, message.counter);
    
    // Decrypt the message
    try {
      plaintext = sodium.crypto_secretbox_open_easy(message.ciphertext, message.nonce, messageKey);
    } catch (error: any) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
    
    // Update the receiving key
    newState.receivingKey = await advanceChainKey(currentKey);
  } else {
    // This is the next expected message
    const messageKey = await deriveMessageKey(newState.receivingKey, message.counter);
    
    // Decrypt the message
    try {
      plaintext = sodium.crypto_secretbox_open_easy(message.ciphertext, message.nonce, messageKey);
    } catch (error: any) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
    
    // Update the receiving key
    newState.receivingKey = await advanceChainKey(newState.receivingKey);
  }
  
  // Update the state
  newState.receivedCounters.set(message.counter, true);
  newState.maxReceivedCounter = Math.max(newState.maxReceivedCounter, message.counter);
  
  return [plaintext, newState];
}

/**
 * Rekey the session with a new shared secret
 * This would typically happen during a new in-person meeting
 * 
 * @param state Current session state
 * @param newSecret Optional new shared secret (if not provided, will derive from existing root key)
 * @returns Updated session state with new keys
 */
export async function rekeySession(
  state: SessionState,
  newSecret?: Uint8Array
): Promise<SessionState> {
  await sodium.ready;
  
  // Derive a new root key
  const newRootKey = newSecret ? 
    await deriveRootKey(newSecret) : 
    sodium.crypto_generichash(32, state.rootKey, stringToUint8Array("REKEY_ROOT_KEY"));
  
  // Derive new chain keys
  const [sendingKey, receivingKey] = await deriveInitialChainKeys(newRootKey, state.selfId, state.peerId);
  
  return {
    ...state,
    rootKey: newRootKey,
    sendingKey,
    receivingKey,
    sendingCounter: 0,
    receivedCounters: new Map<number, boolean>(),
    maxReceivedCounter: -1,
    skippedMessageKeys: new Map<number, Uint8Array>(),
  };
}

/**
 * Derive the root key from a shared secret
 * 
 * @param sharedSecret High-entropy shared secret
 * @returns Root key
 */
async function deriveRootKey(sharedSecret: Uint8Array): Promise<Uint8Array> {
  await sodium.ready;
  
  // Use HKDF-like construction to derive the root key
  const info = stringToUint8Array("HYPERSECURE_ROOT_KEY");
  return sodium.crypto_generichash(32, sharedSecret, info);
}

/**
 * Derive initial chain keys from the root key
 * 
 * @param rootKey Root key for the session
 * @param selfId Identity of the local user
 * @param peerId Identity of the remote user
 * @returns [sending key, receiving key]
 */
async function deriveInitialChainKeys(
  rootKey: Uint8Array,
  selfId: string,
  peerId: string
): Promise<[Uint8Array, Uint8Array]> {
  await sodium.ready;
  
  // Ensure deterministic ordering of IDs to avoid mirroring issues
  const [firstId, secondId] = [selfId, peerId].sort();
  
  // Create two different contexts for the chain keys
  const salt1 = stringToUint8Array(`${firstId}->${secondId}`);
  const salt2 = stringToUint8Array(`${secondId}->${firstId}`);
  
  // Derive two different keys
  const key1 = sodium.crypto_generichash(32, rootKey, salt1);
  const key2 = sodium.crypto_generichash(32, rootKey, salt2);
  
  // Assign sending and receiving keys based on ID ordering
  if (selfId === firstId) {
    return [key1, key2];
  } else {
    return [key2, key1];
  }
}

/**
 * Derive a message key from a chain key and counter
 * 
 * @param chainKey Current chain key
 * @param counter Message counter
 * @returns Message key
 */
async function deriveMessageKey(chainKey: Uint8Array, counter: number): Promise<Uint8Array> {
  await sodium.ready;
  
  // Convert counter to bytes for the message key context
  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, counter, true);
  
  // Derive message key using the chain key and counter
  const context = new Uint8Array(chainKey.length + counterBytes.length);
  context.set(chainKey);
  context.set(counterBytes, chainKey.length);
  
  return sodium.crypto_generichash(32, stringToUint8Array("MSG_KEY"), context);
}

/**
 * Advance the chain key to derive the next chain key
 * 
 * @param currentChainKey Current chain key
 * @returns Next chain key
 */
async function advanceChainKey(currentChainKey: Uint8Array): Promise<Uint8Array> {
  await sodium.ready;
  
  // Derive the next chain key by hashing the current one with a constant
  return sodium.crypto_generichash(32, currentChainKey, stringToUint8Array("NEXT_CHAIN_KEY"));
}

/**
 * Convert a string to Uint8Array using UTF-8 encoding
 * 
 * @param str String to convert
 * @returns Uint8Array containing the UTF-8 encoded string
 */
function stringToUint8Array(str: string): Uint8Array {
  return new TextEncoder().encode(str);
} 