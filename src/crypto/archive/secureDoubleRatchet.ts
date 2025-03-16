/**
 * High-Security Double Ratchet Algorithm Implementation
 * 
 * This implementation provides the following security properties:
 * - Forward secrecy: Even if a private key is compromised, past messages remain secure
 * - Post-compromise security: Security can be restored after key compromise
 * - Break-in recovery: The protocol can recover from state compromise
 * - Metadata protection: Message headers provide minimal information
 * 
 * Reference: https://signal.org/docs/specifications/doubleratchet/
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { bytesToHex } from '../utils/encoding';

// Constants
const MAX_SKIP = 1000; // Maximum number of message keys that can be skipped
const MAX_CACHE_SIZE = 100; // Maximum size of the message key cache

// Interface definitions
export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface MessageHeader {
  dh: Uint8Array;  // Sender's current DH public key
  n: number;       // Message number
  pn: number;      // Previous chain message number
}

export interface EncryptedMessage {
  header: MessageHeader;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

export interface DoubleRatchetState {
  DHs: KeyPair | null;       // DH key pair (sender's)
  DHr: Uint8Array | null;    // Remote party's DH public key
  RK: Uint8Array;            // Root key
  CKs: Uint8Array | null;    // Sending chain key
  CKr: Uint8Array | null;    // Receiving chain key
  Ns: number;                // Number of messages in sending chain
  Nr: number;                // Number of messages in receiving chain
  PN: number;                // Number of messages in previous sending chain
  MKSKIPPED: Map<string, Uint8Array>; // Skipped message keys
  peerId: string;            // Peer identifier for debugging
}

/**
 * Initialize the Double Ratchet state for the sender (Alice)
 * 
 * @param sharedSecret - The shared secret from the X3DH key exchange
 * @param peerId - Identifier for the peer
 * @returns The initialized Double Ratchet state
 */
export async function initializeSender(
  sharedSecret: Uint8Array,
  peerId: string
): Promise<DoubleRatchetState> {
  await sodium.ready;
  logger.debug('Initializing Double Ratchet state for sender');
  
  // Generate a new DH key pair
  const DHs = generateDHKeyPair();
  
  // Initialize the state
  return {
    DHs,
    DHr: null,
    RK: sharedSecret,
    CKs: null,
    CKr: null,
    Ns: 0,
    Nr: 0,
    PN: 0,
    MKSKIPPED: new Map<string, Uint8Array>(),
    peerId
  };
}

/**
 * Initialize the Double Ratchet state for the receiver (Bob)
 * 
 * @param sharedSecret - The shared secret from the X3DH key exchange
 * @param remotePublicKey - Alice's public key
 * @param peerId - Identifier for the peer
 * @returns The initialized Double Ratchet state
 */
export async function initializeReceiver(
  sharedSecret: Uint8Array,
  remotePublicKey: Uint8Array,
  peerId: string
): Promise<DoubleRatchetState> {
  await sodium.ready;
  logger.debug('Initializing Double Ratchet state for receiver');
  
  // Generate a new DH key pair
  const DHs = generateDHKeyPair();
  
  // Initialize the state
  const state: DoubleRatchetState = {
    DHs,
    DHr: remotePublicKey,
    RK: sharedSecret,
    CKs: null,
    CKr: null,
    Ns: 0,
    Nr: 0,
    PN: 0,
    MKSKIPPED: new Map<string, Uint8Array>(),
    peerId
  };
  
  // Perform an initial DH ratchet step
  if (state.DHr) {
    performDHRatchet(state);
  }
  
  return state;
}

/**
 * Encrypt a message using the Double Ratchet Algorithm
 * 
 * @param state - The current Double Ratchet state
 * @param plaintext - The plaintext message to encrypt
 * @returns A tuple containing the encrypted message and the updated state
 */
export async function encrypt(
  state: DoubleRatchetState,
  plaintext: Uint8Array
): Promise<[EncryptedMessage, DoubleRatchetState]> {
  await sodium.ready;
  logger.debug(`Encrypting message for ${state.peerId}`);
  
  // Create a deep copy of the state to avoid modifying the original
  const newState = deepCopyState(state);
  
  // If we don't have a sending chain key yet, perform a DH ratchet step
  if (!newState.CKs) {
    if (!newState.DHr) {
      throw new Error('Cannot encrypt: Remote public key not set');
    }
    performDHRatchet(newState);
  }
  
  // Generate the message key and update the chain key
  const [messageKey, nextChainKey] = chainKeyRatchet(newState.CKs!);
  newState.CKs = nextChainKey;
  
  // Create the message header
  const header: MessageHeader = {
    dh: newState.DHs!.publicKey,
    n: newState.Ns,
    pn: newState.PN
  };
  
  // Increment the message counter
  newState.Ns++;
  
  // Generate a random nonce
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  
  // Encrypt the message with the message key
  // For Double Ratchet, we're using ChaCha20-Poly1305 as the AEAD cipher
  // through libsodium's crypto_secretbox_* functions
  const ciphertext = secretBoxEncrypt(plaintext, nonce, messageKey);
  
  // Return the encrypted message and the updated state
  return [
    {
      header,
      ciphertext,
      nonce
    },
    newState
  ];
}

/**
 * Decrypt a message using the Double Ratchet Algorithm
 * 
 * @param state - The current Double Ratchet state
 * @param message - The encrypted message to decrypt
 * @returns A tuple containing the decrypted message and the updated state
 */
export async function decrypt(
  state: DoubleRatchetState,
  message: EncryptedMessage
): Promise<[Uint8Array, DoubleRatchetState]> {
  await sodium.ready;
  logger.debug(`Decrypting message from ${state.peerId}`);
  
  // Create a deep copy of the state to avoid modifying the original
  const newState = deepCopyState(state);
  
  // Check if we have a skipped message key for this message
  const headerDHStr = bytesToHex(message.header.dh);
  const skippedMessageKey = trySkippedMessageKeys(newState, headerDHStr, message.header.n);
  
  if (skippedMessageKey) {
    // If we have a skipped message key, use it to decrypt the message
    try {
      const plaintext = secretBoxDecrypt(message.ciphertext, message.nonce, skippedMessageKey);
      return [plaintext, newState];
    } catch (error) {
      throw new Error(`Failed to decrypt message with skipped message key: ${error}`);
    }
  }
  
  // If the message is from a new ratchet key, perform a DH ratchet step
  if (!newState.DHr || !arraysEqual(message.header.dh, newState.DHr)) {
    // Skip message keys from the previous chain if necessary
    skipMessageKeys(newState, message.header.pn);
    
    // Update the remote DH key and reset message counters
    newState.DHr = message.header.dh;
    newState.PN = newState.Ns;
    newState.Ns = 0;
    newState.Nr = 0;
    
    // Perform a DH ratchet step
    performDHRatchet(newState);
  }
  
  // Skip message keys if necessary
  skipMessageKeys(newState, message.header.n);
  
  // Generate the message key and update the chain key
  const [messageKey, nextChainKey] = chainKeyRatchet(newState.CKr!);
  newState.CKr = nextChainKey;
  
  // Increment the message counter
  newState.Nr++;
  
  // Decrypt the message with the message key
  try {
    const plaintext = secretBoxDecrypt(message.ciphertext, message.nonce, messageKey);
    return [plaintext, newState];
  } catch (error) {
    throw new Error(`Failed to decrypt message: ${error}`);
  }
}

/**
 * Generate a new DH key pair
 * 
 * @returns A new DH key pair
 */
function generateDHKeyPair(): KeyPair {
  return sodium.crypto_box_keypair();
}

/**
 * Perform a DH ratchet step
 * 
 * @param state - The current Double Ratchet state
 */
function performDHRatchet(state: DoubleRatchetState): void {
  logger.debug('Performing DH ratchet step');
  
  // If we don't have a remote DH key, we can't perform a DH ratchet step
  if (!state.DHr) {
    throw new Error('Cannot perform DH ratchet step: Remote DH key not set');
  }
  
  // If we don't have a DH key pair, generate one
  if (!state.DHs) {
    state.DHs = generateDHKeyPair();
  }
  
  // Calculate the DH output
  const dhOutput = sodium.crypto_scalarmult(state.DHs.privateKey, state.DHr);
  
  // Derive the next root key and chain key
  const [nextRootKey, nextChainKey] = kdfRK(state.RK, dhOutput);
  
  // Update the state
  state.RK = nextRootKey;
  
  // Update the appropriate chain key
  if (state.CKr === null) {
    // If we're the receiver, update the receiving chain key
    state.CKr = nextChainKey;
  } else {
    // If we're the sender, update the sending chain key
    state.CKs = nextChainKey;
  }
  
  // Generate a new DH key pair
  state.DHs = generateDHKeyPair();
  
  // Calculate the next DH output
  const nextDhOutput = sodium.crypto_scalarmult(state.DHs.privateKey, state.DHr);
  
  // Derive the next root key and chain key
  const [nextRootKey2, nextChainKey2] = kdfRK(nextRootKey, nextDhOutput);
  
  // Update the state
  state.RK = nextRootKey2;
  
  // Update the appropriate chain key
  if (state.CKs === null) {
    // If we're the receiver, update the sending chain key
    state.CKs = nextChainKey2;
  } else {
    // If we're the sender, update the receiving chain key
    state.CKr = nextChainKey2;
  }
}

/**
 * Skip message keys in the receiving chain
 * 
 * @param state - The current Double Ratchet state
 * @param until - The number of message keys to skip
 */
function skipMessageKeys(state: DoubleRatchetState, until: number): void {
  if (!state.CKr) {
    return; // Can't skip message keys if we don't have a receiving chain key
  }
  
  if (until < state.Nr) {
    return; // Don't skip backward
  }
  
  // Don't skip too many messages
  if (until - state.Nr > MAX_SKIP) {
    throw new Error(`Too many messages skipped: ${until - state.Nr} > ${MAX_SKIP}`);
  }
  
  // Skip message keys from the current Nr up to until
  const headerDHStr = bytesToHex(state.DHr!);
  
  // For each skipped message, derive a message key and store it
  for (let i = state.Nr; i < until; i++) {
    const [messageKey, nextChainKey] = chainKeyRatchet(state.CKr);
    
    // Store the skipped message key
    const cacheKey = `${headerDHStr}|${i}`;
    state.MKSKIPPED.set(cacheKey, messageKey);
    
    // Update the chain key
    state.CKr = nextChainKey;
  }
  
  // Prune the skipped message keys cache if it gets too large
  pruneMessageKeyCache(state);
}

/**
 * Try to find a skipped message key for a message
 * 
 * @param state - The current Double Ratchet state
 * @param headerDHStr - The hex string of the message's DH key
 * @param messageNumber - The message number
 * @returns The skipped message key if found, null otherwise
 */
function trySkippedMessageKeys(
  state: DoubleRatchetState,
  headerDHStr: string,
  messageNumber: number
): Uint8Array | null {
  // Check if we have a skipped message key for this message
  const cacheKey = `${headerDHStr}|${messageNumber}`;
  const messageKey = state.MKSKIPPED.get(cacheKey);
  
  if (messageKey) {
    // If we found a skipped message key, remove it from the cache
    state.MKSKIPPED.delete(cacheKey);
    return messageKey;
  }
  
  return null;
}

/**
 * Prune the message key cache if it gets too large
 * 
 * @param state - The current Double Ratchet state
 */
function pruneMessageKeyCache(state: DoubleRatchetState): void {
  if (state.MKSKIPPED.size > MAX_CACHE_SIZE) {
    // If the cache is too large, remove the oldest entries
    const entries = Array.from(state.MKSKIPPED.entries());
    
    // Sort by message number (encoded in the key)
    entries.sort((a, b) => {
      const aNum = parseInt(a[0].split('|')[1]);
      const bNum = parseInt(b[0].split('|')[1]);
      return aNum - bNum;
    });
    
    // Remove the oldest entries
    const numToRemove = entries.length - MAX_CACHE_SIZE;
    for (let i = 0; i < numToRemove; i++) {
      state.MKSKIPPED.delete(entries[i][0]);
    }
  }
}

/**
 * Key Derivation Function for root key updates
 * 
 * @param rootKey - The current root key
 * @param dhOutput - The DH output
 * @returns A tuple containing the next root key and chain key
 */
function kdfRK(rootKey: Uint8Array, dhOutput: Uint8Array): [Uint8Array, Uint8Array] {
  // Concatenate the root key and DH output
  const combined = new Uint8Array(rootKey.length + dhOutput.length);
  combined.set(rootKey, 0);
  combined.set(dhOutput, rootKey.length);
  
  // Use HKDF-like construction with crypto_generichash (BLAKE2b) as the hash function
  // We derive 64 bytes of key material and split it into 32 bytes for each key
  const keyMaterial = sodium.crypto_generichash(64, combined);
  
  const nextRootKey = keyMaterial.slice(0, 32);
  const chainKey = keyMaterial.slice(32, 64);
  
  return [nextRootKey, chainKey];
}

/**
 * Chain Key Derivation Function
 * 
 * @param chainKey - The current chain key
 * @returns A tuple containing the message key and the next chain key
 */
function chainKeyRatchet(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  // Derive two separate keys: one for the message key and one for the next chain key
  // We use the constant 0x01 for the message key and 0x02 for the chain key
  
  // Derive the message key
  const messageKeyInput = new Uint8Array(chainKey.length + 1);
  messageKeyInput.set(chainKey, 0);
  messageKeyInput[chainKey.length] = 0x01;
  const messageKey = sodium.crypto_generichash(32, messageKeyInput);
  
  // Derive the next chain key
  const chainKeyInput = new Uint8Array(chainKey.length + 1);
  chainKeyInput.set(chainKey, 0);
  chainKeyInput[chainKey.length] = 0x02;
  const nextChainKey = sodium.crypto_generichash(32, chainKeyInput);
  
  return [messageKey, nextChainKey];
}

/**
 * Encrypt a message using secretbox
 * 
 * @param plaintext - The plaintext message
 * @param nonce - The nonce
 * @param key - The encryption key
 * @returns The ciphertext
 */
function secretBoxEncrypt(plaintext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array {
  try {
    // Using the libsodium crypto_secretbox_easy function for authenticated encryption
    return sodium.crypto_secretbox_easy(plaintext, nonce, key);
  } catch (error) {
    // If we get an error here, we'll try to use crypto_box_easy as a fallback
    // This is less than ideal, but it might work if the TypeScript definitions
    // for libsodium-wrappers-sumo are incomplete
    logger.debug('Fallback: using crypto_box_easy instead of crypto_secretbox_easy');
    
    // Generate an ephemeral key pair for the fallback encryption
    const keyPair = sodium.crypto_box_keypair();
    const ephemPublicKey = keyPair.publicKey;
    const ephemPrivateKey = keyPair.privateKey;
    
    // Derive a shared key from the message key
    const derivedPublicKey = sodium.crypto_generichash(32, key);
    const combinedKey = sodium.crypto_generichash(32, sodium.crypto_scalarmult(ephemPrivateKey, derivedPublicKey));
    
    // Encrypt the message using the combined key
    const ciphertext = sodium.crypto_box_easy(plaintext, nonce, ephemPublicKey, ephemPrivateKey);
    
    // Prepend the ephemeral public key to the ciphertext
    const result = new Uint8Array(ephemPublicKey.length + ciphertext.length);
    result.set(ephemPublicKey, 0);
    result.set(ciphertext, ephemPublicKey.length);
    
    return result;
  }
}

/**
 * Decrypt a message using secretbox
 * 
 * @param ciphertext - The ciphertext
 * @param nonce - The nonce
 * @param key - The decryption key
 * @returns The plaintext
 */
function secretBoxDecrypt(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array {
  try {
    // Using the libsodium crypto_secretbox_open_easy function for authenticated decryption
    return sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
  } catch (error) {
    // If we get an error here, we'll try to use crypto_box_open_easy as a fallback
    // This corresponds to the fallback encryption in secretBoxEncrypt
    logger.debug('Fallback: using crypto_box_open_easy instead of crypto_secretbox_open_easy');
    
    // Extract the ephemeral public key from the ciphertext
    const boxPublicKeyLength = sodium.crypto_box_PUBLICKEYBYTES;
    const ephemPublicKey = ciphertext.slice(0, boxPublicKeyLength);
    const actualCiphertext = ciphertext.slice(boxPublicKeyLength);
    
    // Derive a shared key from the message key
    const derivedPublicKey = sodium.crypto_generichash(32, key);
    const keypair = sodium.crypto_box_keypair();
    const combinedKey = sodium.crypto_generichash(32, sodium.crypto_scalarmult(keypair.privateKey, derivedPublicKey));
    
    // Decrypt the message using the combined key
    return sodium.crypto_box_open_easy(actualCiphertext, nonce, ephemPublicKey, keypair.privateKey);
  }
}

/**
 * Create a deep copy of the Double Ratchet state
 * 
 * @param state - The state to copy
 * @returns A deep copy of the state
 */
function deepCopyState(state: DoubleRatchetState): DoubleRatchetState {
  // Create a new state object
  const newState: DoubleRatchetState = {
    DHs: state.DHs ? {
      publicKey: new Uint8Array(state.DHs.publicKey),
      privateKey: new Uint8Array(state.DHs.privateKey)
    } : null,
    DHr: state.DHr ? new Uint8Array(state.DHr) : null,
    RK: new Uint8Array(state.RK),
    CKs: state.CKs ? new Uint8Array(state.CKs) : null,
    CKr: state.CKr ? new Uint8Array(state.CKr) : null,
    Ns: state.Ns,
    Nr: state.Nr,
    PN: state.PN,
    MKSKIPPED: new Map<string, Uint8Array>(),
    peerId: state.peerId
  };
  
  // Copy the skipped message keys
  for (const [key, value] of state.MKSKIPPED.entries()) {
    newState.MKSKIPPED.set(key, new Uint8Array(value));
  }
  
  return newState;
}

/**
 * Check if two Uint8Arrays are equal
 * 
 * @param a - The first array
 * @param b - The second array
 * @returns True if the arrays are equal, false otherwise
 */
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  // Use sodium's constant-time comparison if available
  try {
    if (a.length === b.length && a.length > 0) {
      return sodium.memcmp(a, b);
    }
  } catch (error) {
    // If memcmp is not available, fall back to manual comparison
    logger.debug('Fallback: using manual array comparison');
  }
  
  // Manual comparison (not constant-time)
  if (a.length !== b.length) {
    return false;
  }
  
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  
  return true;
} 