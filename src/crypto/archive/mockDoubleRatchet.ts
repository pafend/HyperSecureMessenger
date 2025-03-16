/**
 * Mock Double Ratchet Algorithm Implementation for Testing
 * 
 * This is a simplified mock implementation for testing purposes only.
 * It does not provide any actual security and should never be used in production.
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';

/**
 * Mock encrypted message format
 */
export interface EncryptedMessage {
  header: {
    publicKey: Uint8Array;
    N: number;
    PN: number;
  };
  ciphertext: Uint8Array;
}

/**
 * Mock Double Ratchet state
 */
export interface DoubleRatchetState {
  DHs: { publicKey: Uint8Array; privateKey: Uint8Array } | null;
  DHr: Uint8Array | null;
  rootKey: Uint8Array;
  sendingChainKey: Uint8Array | null;
  receivingChainKey: Uint8Array | null;
  NS: number;
  NR: number;
  PN: number;
  messageKeyCache: Map<string, Map<number, Uint8Array>>;
  pqSharedSecret: Uint8Array | null;
  peerId: string;
}

/**
 * Initialize a sender state
 */
export async function initializeSender(
  sharedSecret: Uint8Array,
  peerId: string
): Promise<DoubleRatchetState> {
  await sodium.ready;
  
  return {
    DHs: sodium.crypto_box_keypair(),
    DHr: null,
    rootKey: sharedSecret.slice(0, 32),
    sendingChainKey: sharedSecret.slice(0, 32),
    receivingChainKey: sharedSecret.slice(0, 32),
    NS: 0,
    NR: 0,
    PN: 0,
    messageKeyCache: new Map(),
    pqSharedSecret: null,
    peerId
  };
}

/**
 * Initialize a receiver state
 */
export async function initializeReceiver(
  sharedSecret: Uint8Array,
  remotePublicKey: Uint8Array,
  peerId: string
): Promise<DoubleRatchetState> {
  await sodium.ready;
  
  return {
    DHs: sodium.crypto_box_keypair(),
    DHr: remotePublicKey,
    rootKey: sharedSecret.slice(0, 32),
    sendingChainKey: sharedSecret.slice(0, 32),
    receivingChainKey: sharedSecret.slice(0, 32),
    NS: 0,
    NR: 0,
    PN: 0,
    messageKeyCache: new Map(),
    pqSharedSecret: null,
    peerId
  };
}

/**
 * Mock encrypt function that simply returns the plaintext
 */
export async function encrypt(
  state: DoubleRatchetState,
  plaintext: Uint8Array
): Promise<[EncryptedMessage, DoubleRatchetState]> {
  await sodium.ready;
  
  // Create a copy of the state to return
  const newState = { ...state, NS: state.NS + 1 };
  
  // Create a header
  const header = {
    publicKey: state.DHs?.publicKey || new Uint8Array(32),
    N: state.NS,
    PN: state.PN
  };
  
  // For testing, we'll just return the plaintext as the ciphertext
  return [{ header, ciphertext: plaintext }, newState];
}

/**
 * Mock decrypt function that simply returns the ciphertext
 */
export async function decrypt(
  state: DoubleRatchetState,
  message: EncryptedMessage
): Promise<[Uint8Array, DoubleRatchetState]> {
  await sodium.ready;
  
  // Create a copy of the state to return
  const newState = { ...state, NR: state.NR + 1 };
  
  // For testing, we'll just return the ciphertext as the plaintext
  return [message.ciphertext, newState];
} 