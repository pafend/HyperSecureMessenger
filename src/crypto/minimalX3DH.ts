/**
 * Minimal X3DH Key Exchange Implementation
 * 
 * This is a simplified version of the X3DH key exchange protocol
 * designed to work with our basic Double Ratchet implementation.
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { bytesToHex } from '../utils/encoding';

// Basic interfaces
export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

// Simplified pre-key bundle
export interface PreKeyBundle {
  identityPublicKey: Uint8Array;
  signedPreKeyPublicKey: Uint8Array;
}

// Initiation message
export interface InitiationMessage {
  identityPublicKey: Uint8Array;
  ephemeralPublicKey: Uint8Array;
}

/**
 * Generate a key pair for X25519
 * 
 * @returns A new key pair
 */
export function generateKeyPair(): KeyPair {
  const privateKey = sodium.randombytes_buf(sodium.crypto_box_SECRETKEYBYTES);
  const publicKey = sodium.crypto_scalarmult_base(privateKey);
  
  return {
    publicKey,
    privateKey
  };
}

/**
 * Initiate a key exchange with a recipient
 * 
 * @param identityKeyPair - Initiator's identity key pair
 * @param preKeyBundle - Recipient's pre-key bundle
 * @returns Shared secret and initiation message
 */
export async function initiateKeyExchange(
  identityKeyPair: KeyPair,
  preKeyBundle: PreKeyBundle
): Promise<[Uint8Array, InitiationMessage]> {
  await sodium.ready;
  
  // Generate ephemeral key pair
  const ephemeralKeyPair = generateKeyPair();
  
  // Create initiation message
  const message: InitiationMessage = {
    identityPublicKey: identityKeyPair.publicKey,
    ephemeralPublicKey: ephemeralKeyPair.publicKey
  };
  
  // Calculate DH1 = DH(IKa, SPKb)
  let dh1;
  try {
    dh1 = sodium.crypto_scalarmult(
      identityKeyPair.privateKey,
      preKeyBundle.signedPreKeyPublicKey
    );
    logger.debug(`DH1 (IKa, SPKb): ${bytesToHex(dh1).slice(0, 16)}...`);
  } catch (error) {
    logger.error('Failed to calculate DH1:', error);
    throw new Error(`Failed to calculate DH1: ${error instanceof Error ? error.message : String(error)}`);
  }
  
  // Calculate DH2 = DH(EKa, IKb)
  let dh2;
  try {
    dh2 = sodium.crypto_scalarmult(
      ephemeralKeyPair.privateKey,
      preKeyBundle.identityPublicKey
    );
    logger.debug(`DH2 (EKa, IKb): ${bytesToHex(dh2).slice(0, 16)}...`);
  } catch (error) {
    logger.error('Failed to calculate DH2:', error);
    throw new Error(`Failed to calculate DH2: ${error instanceof Error ? error.message : String(error)}`);
  }
  
  // Calculate DH3 = DH(EKa, SPKb)
  let dh3;
  try {
    dh3 = sodium.crypto_scalarmult(
      ephemeralKeyPair.privateKey,
      preKeyBundle.signedPreKeyPublicKey
    );
    logger.debug(`DH3 (EKa, SPKb): ${bytesToHex(dh3).slice(0, 16)}...`);
  } catch (error) {
    logger.error('Failed to calculate DH3:', error);
    throw new Error(`Failed to calculate DH3: ${error instanceof Error ? error.message : String(error)}`);
  }
  
  // Combine shared secrets: SK = KDF(DH1 || DH2 || DH3)
  const combinedSecrets = new Uint8Array(dh1.length + dh2.length + dh3.length);
  combinedSecrets.set(dh1, 0);
  combinedSecrets.set(dh2, dh1.length);
  combinedSecrets.set(dh3, dh1.length + dh2.length);
  
  // Derive final shared secret using BLAKE2b
  const sharedSecret = sodium.crypto_generichash(32, combinedSecrets);
  
  logger.debug(`Initiator derived shared secret: ${bytesToHex(sharedSecret).slice(0, 16)}...`);
  
  return [sharedSecret, message];
}

/**
 * Process a key exchange initiation
 * 
 * @param identityKeyPair - Recipient's identity key pair
 * @param signedPreKeyPair - Recipient's signed pre-key pair
 * @param message - Initiation message
 * @returns Shared secret
 */
export async function processKeyExchange(
  identityKeyPair: KeyPair,
  signedPreKeyPair: KeyPair,
  message: InitiationMessage
): Promise<Uint8Array> {
  await sodium.ready;
  
  // Calculate DH1 = DH(SPKb, IKa)
  let dh1;
  try {
    dh1 = sodium.crypto_scalarmult(
      signedPreKeyPair.privateKey,
      message.identityPublicKey
    );
    logger.debug(`DH1 (SPKb, IKa): ${bytesToHex(dh1).slice(0, 16)}...`);
  } catch (error) {
    logger.error('Failed to calculate DH1:', error);
    throw new Error(`Failed to calculate DH1: ${error instanceof Error ? error.message : String(error)}`);
  }
  
  // Calculate DH2 = DH(IKb, EKa)
  let dh2;
  try {
    dh2 = sodium.crypto_scalarmult(
      identityKeyPair.privateKey,
      message.ephemeralPublicKey
    );
    logger.debug(`DH2 (IKb, EKa): ${bytesToHex(dh2).slice(0, 16)}...`);
  } catch (error) {
    logger.error('Failed to calculate DH2:', error);
    throw new Error(`Failed to calculate DH2: ${error instanceof Error ? error.message : String(error)}`);
  }
  
  // Calculate DH3 = DH(SPKb, EKa)
  let dh3;
  try {
    dh3 = sodium.crypto_scalarmult(
      signedPreKeyPair.privateKey,
      message.ephemeralPublicKey
    );
    logger.debug(`DH3 (SPKb, EKa): ${bytesToHex(dh3).slice(0, 16)}...`);
  } catch (error) {
    logger.error('Failed to calculate DH3:', error);
    throw new Error(`Failed to calculate DH3: ${error instanceof Error ? error.message : String(error)}`);
  }
  
  // Combine shared secrets: SK = KDF(DH1 || DH2 || DH3)
  const combinedSecrets = new Uint8Array(dh1.length + dh2.length + dh3.length);
  combinedSecrets.set(dh1, 0);
  combinedSecrets.set(dh2, dh1.length);
  combinedSecrets.set(dh3, dh1.length + dh2.length);
  
  // Derive final shared secret using BLAKE2b
  const sharedSecret = sodium.crypto_generichash(32, combinedSecrets);
  
  logger.debug(`Recipient derived shared secret: ${bytesToHex(sharedSecret).slice(0, 16)}...`);
  
  return sharedSecret;
} 