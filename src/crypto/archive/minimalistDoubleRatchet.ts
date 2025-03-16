/**
 * Minimalist Double Ratchet Implementation
 * 
 * This implementation provides a basic Double Ratchet algorithm
 * with simplified encryption for demonstration purposes.
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { bytesToHex } from '../utils/encoding';

// Message header
export interface MessageHeader {
  publicKey: Uint8Array;  // Sender's current ratchet public key
  messageNumber: number;  // Message number
  previousChainLength: number; // Previous chain length
}

// Encrypted message format
export interface EncryptedMessage {
  header: MessageHeader;
  ciphertext: Uint8Array;
}

// State for the Double Ratchet
export interface State {
  // DH ratchet
  DHKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array } | null;
  DHRemoteKey: Uint8Array | null;
  
  // Symmetric ratchet
  rootKey: Uint8Array;
  sendingKey: Uint8Array | null;
  receivingKey: Uint8Array | null;
  
  // Counters
  sendingMessageNumber: number;
  receivedMessageNumber: number;
  previousSendingChainLength: number;
  
  // Cache for out-of-order messages
  skippedMessageKeys: Map<string, Uint8Array>;
  
  // For debugging
  remoteId: string;
}

/**
 * Initialize the sender state (Alice)
 * 
 * @param sharedSecret - Shared secret from X3DH
 * @param remoteId - ID of the remote peer
 * @param remotePublicKey - Optional remote public key
 * @returns Initialized sender state
 */
export async function initSender(
  sharedSecret: Uint8Array, 
  remoteId: string,
  remotePublicKey?: Uint8Array
): Promise<State> {
  await sodium.ready;
  
  // Generate DH key pair
  const keyPair = sodium.crypto_box_keypair();
  
  // Create initial state
  const state: State = {
    DHKeyPair: keyPair,
    DHRemoteKey: remotePublicKey ? new Uint8Array(remotePublicKey) : null,
    rootKey: new Uint8Array(sharedSecret),
    sendingKey: null,
    receivingKey: null,
    sendingMessageNumber: 0,
    receivedMessageNumber: 0,
    previousSendingChainLength: 0,
    skippedMessageKeys: new Map(),
    remoteId
  };
  
  // If we have the remote key, we can perform an initial ratchet step
  if (remotePublicKey) {
    ratchetStep(state);
  }
  
  return state;
}

/**
 * Initialize the receiver state (Bob)
 * 
 * @param sharedSecret - Shared secret from X3DH
 * @param senderPublicKey - Sender's public key
 * @param remoteId - ID of the remote peer
 * @returns Initialized receiver state
 */
export async function initReceiver(
  sharedSecret: Uint8Array,
  senderPublicKey: Uint8Array,
  remoteId: string
): Promise<State> {
  await sodium.ready;
  
  // Generate DH key pair
  const keyPair = sodium.crypto_box_keypair();
  
  const state: State = {
    DHKeyPair: keyPair,
    DHRemoteKey: senderPublicKey,
    rootKey: sharedSecret,
    sendingKey: null,
    receivingKey: null,
    sendingMessageNumber: 0,
    receivedMessageNumber: 0,
    previousSendingChainLength: 0,
    skippedMessageKeys: new Map(),
    remoteId
  };
  
  // Perform initial DH ratchet step
  ratchetStep(state);
  
  return state;
}

/**
 * Encrypt a message
 * 
 * @param state - Current state
 * @param plaintext - Message to encrypt
 * @returns Encrypted message and updated state
 */
export async function encrypt(
  state: State,
  plaintext: Uint8Array
): Promise<[EncryptedMessage, State]> {
  await sodium.ready;
  
  // Create a copy of the state
  const newState = cloneState(state);
  
  // Initialize keys if needed
  if (newState.sendingKey === null) {
    // We need the remote key for DH
    if (newState.DHRemoteKey === null) {
      throw new Error('Cannot encrypt: remote public key not set');
    }
    
    // Perform ratchet step to derive keys
    ratchetStep(newState);
  }
  
  // Get message key and advance chain
  const [messageKey, nextSendingKey] = deriveKeys(newState.sendingKey!);
  newState.sendingKey = nextSendingKey;
  
  // Prepare header
  const header: MessageHeader = {
    publicKey: newState.DHKeyPair!.publicKey,
    messageNumber: newState.sendingMessageNumber,
    previousChainLength: newState.previousSendingChainLength
  };
  
  // Increment counter
  newState.sendingMessageNumber++;
  
  // Encrypt message (simple XOR for demonstration)
  const ciphertext = simpleEncrypt(plaintext, messageKey);
  
  return [{ header, ciphertext }, newState];
}

/**
 * Decrypt a message
 * 
 * @param state - Current state
 * @param message - Encrypted message
 * @returns Decrypted message and updated state
 */
export async function decrypt(
  state: State,
  message: EncryptedMessage
): Promise<[Uint8Array, State]> {
  await sodium.ready;
  
  // Create a copy of the state
  const newState = cloneState(state);
  
  try {
    // Check if we need to perform a ratchet step (DH keys don't match)
    const dhKeysMatch = newState.DHRemoteKey !== null && 
                        arraysEqual(message.header.publicKey, newState.DHRemoteKey);
    
    if (!dhKeysMatch) {
      // Skip messages from previous sending chain
      if (newState.receivingKey !== null) {
        skipMessages(newState, message.header.previousChainLength);
      }
      
      // Update remote key
      newState.DHRemoteKey = message.header.publicKey;
      newState.previousSendingChainLength = newState.sendingMessageNumber;
      newState.sendingMessageNumber = 0;
      newState.receivedMessageNumber = 0;
      
      // Derive new keys
      ratchetStep(newState);
    }
    
    // Skip any missing messages
    skipMessages(newState, message.header.messageNumber);
    
    // Get message key and advance chain
    const [messageKey, nextReceivingKey] = deriveKeys(newState.receivingKey!);
    newState.receivingKey = nextReceivingKey;
    
    // Increment counter
    newState.receivedMessageNumber++;
    
    // Decrypt message
    const plaintext = simpleDecrypt(message.ciphertext, messageKey);
    
    return [plaintext, newState];
  } catch (error) {
    logger.error('Decryption error:', error);
    throw new Error(`Decryption failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Perform a DH ratchet step
 * 
 * @param state - Current state
 */
function ratchetStep(state: State): void {
  // Need remote key to do DH
  if (state.DHRemoteKey === null) {
    throw new Error('Remote public key not set');
  }
  
  // Calculate DH output - for simplicity we're using a key derivation substitute
  // since some libsodium TypeScript definitions may be missing
  const dhOutput = deriveSharedSecret(state.DHKeyPair!.privateKey, state.DHRemoteKey);
  
  // Derive root key and chain keys (KDF_RK)
  const keyMaterial = kdfRK(state.rootKey, dhOutput);
  
  // Update keys
  state.rootKey = keyMaterial.slice(0, 32);
  
  if (state.receivingKey === null) {
    // First ratchet, initialize receiving chain
    state.receivingKey = keyMaterial.slice(32, 64);
  } else {
    // We had a receiving chain, initialize sending chain
    state.sendingKey = keyMaterial.slice(32, 64);
  }
  
  // Generate new DH key pair
  const newKeyPair = sodium.crypto_box_keypair();
  
  // Another DH calculation with the new key pair
  const newDhOutput = deriveSharedSecret(newKeyPair.privateKey, state.DHRemoteKey);
  
  // Derive more keys
  const newKeyMaterial = kdfRK(state.rootKey, newDhOutput);
  
  // Update root key
  state.rootKey = newKeyMaterial.slice(0, 32);
  
  // Update the chain key that wasn't updated before
  if (state.sendingKey === null) {
    state.sendingKey = newKeyMaterial.slice(32, 64);
  } else {
    state.receivingKey = newKeyMaterial.slice(32, 64);
  }
  
  // Update DH key pair
  state.DHKeyPair = newKeyPair;
}

/**
 * Skip messages and store message keys
 * 
 * @param state - Current state
 * @param targetNumber - Message number to skip to
 */
function skipMessages(state: State, targetNumber: number): void {
  if (state.receivingKey === null) return;
  if (state.receivedMessageNumber >= targetNumber) return;
  
  // Cache message keys for skipped messages
  let receivingKey = state.receivingKey;
  
  for (let i = state.receivedMessageNumber; i < targetNumber; i++) {
    const [messageKey, nextKey] = deriveKeys(receivingKey);
    
    // Cache the message key
    const keyId = `${bytesToHex(state.DHRemoteKey!)}:${i}`;
    state.skippedMessageKeys.set(keyId, messageKey);
    
    receivingKey = nextKey;
  }
  
  // Update chain key
  state.receivingKey = receivingKey;
}

/**
 * Derive shared secret (simplified DH calculation)
 * 
 * @param privateKey - Private key
 * @param publicKey - Public key
 * @returns Derived shared secret
 */
function deriveSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  // In a real implementation, this would use proper DH calculation
  // For simplicity, we'll use a key derivation function with both keys as input
  const combined = new Uint8Array(privateKey.length + publicKey.length);
  combined.set(privateKey);
  combined.set(publicKey, privateKey.length);
  
  return sodium.crypto_generichash(32, combined);
}

/**
 * KDF for root key updates
 * 
 * @param rootKey - Current root key
 * @param dhOutput - DH output
 * @returns New key material
 */
function kdfRK(rootKey: Uint8Array, dhOutput: Uint8Array): Uint8Array {
  // Combine inputs
  const combined = new Uint8Array(rootKey.length + dhOutput.length);
  combined.set(rootKey);
  combined.set(dhOutput, rootKey.length);
  
  // Derive 64 bytes of key material
  return sodium.crypto_generichash(64, combined);
}

/**
 * Derive message key and next chain key
 * 
 * @param chainKey - Current chain key
 * @returns Tuple of message key and next chain key
 */
function deriveKeys(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  // Derive message key
  const messageKeyInput = new Uint8Array(chainKey.length + 1);
  messageKeyInput.set(chainKey);
  messageKeyInput[chainKey.length] = 0x01; // Constant for message key
  const messageKey = sodium.crypto_generichash(32, messageKeyInput);
  
  // Derive next chain key
  const nextChainKeyInput = new Uint8Array(chainKey.length + 1);
  nextChainKeyInput.set(chainKey);
  nextChainKeyInput[chainKey.length] = 0x02; // Constant for chain key
  const nextChainKey = sodium.crypto_generichash(32, nextChainKeyInput);
  
  return [messageKey, nextChainKey];
}

/**
 * Very simple encryption function (XOR)
 * Note: This is NOT secure for production use
 * 
 * @param plaintext - Data to encrypt
 * @param key - Encryption key
 * @returns Encrypted data
 */
function simpleEncrypt(plaintext: Uint8Array, key: Uint8Array): Uint8Array {
  // Generate keystream (simplified, just use the key directly)
  const keyStream = generateKeyStream(key, plaintext.length);
  
  // Encrypt with XOR
  const ciphertext = new Uint8Array(plaintext.length);
  for (let i = 0; i < plaintext.length; i++) {
    ciphertext[i] = plaintext[i] ^ keyStream[i % keyStream.length];
  }
  
  return ciphertext;
}

/**
 * Simple decryption function
 * 
 * @param ciphertext - Encrypted data
 * @param key - Decryption key
 * @returns Decrypted data
 */
function simpleDecrypt(ciphertext: Uint8Array, key: Uint8Array): Uint8Array {
  // Simply XOR again with the same keystream (symmetric encryption)
  return simpleEncrypt(ciphertext, key);
}

/**
 * Generate keystream for encryption/decryption
 * 
 * @param key - Key to use
 * @param length - Length of keystream to generate
 * @returns Keystream
 */
function generateKeyStream(key: Uint8Array, length: number): Uint8Array {
  // For simplicity, just use the key directly and extend if needed
  if (key.length >= length) {
    return key.slice(0, length);
  }
  
  // Need to extend the key
  const repeats = Math.ceil(length / key.length);
  const result = new Uint8Array(repeats * key.length);
  
  for (let i = 0; i < repeats; i++) {
    result.set(key, i * key.length);
  }
  
  return result.slice(0, length);
}

/**
 * Deep clone the state
 * 
 * @param state - State to clone
 * @returns Cloned state
 */
function cloneState(state: State): State {
  return {
    DHKeyPair: state.DHKeyPair ? {
      publicKey: new Uint8Array(state.DHKeyPair.publicKey),
      privateKey: new Uint8Array(state.DHKeyPair.privateKey)
    } : null,
    DHRemoteKey: state.DHRemoteKey ? new Uint8Array(state.DHRemoteKey) : null,
    rootKey: new Uint8Array(state.rootKey),
    sendingKey: state.sendingKey ? new Uint8Array(state.sendingKey) : null,
    receivingKey: state.receivingKey ? new Uint8Array(state.receivingKey) : null,
    sendingMessageNumber: state.sendingMessageNumber,
    receivedMessageNumber: state.receivedMessageNumber,
    previousSendingChainLength: state.previousSendingChainLength,
    skippedMessageKeys: new Map(
      Array.from(state.skippedMessageKeys.entries()).map(
        ([k, v]) => [k, new Uint8Array(v)]
      )
    ),
    remoteId: state.remoteId
  };
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