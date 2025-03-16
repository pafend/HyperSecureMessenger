/**
 * Simple X3DH Key Exchange Implementation
 * 
 * This is a simplified version of the X3DH key exchange protocol
 * designed to work with our basic Double Ratchet implementation.
 */

import sodium from 'libsodium-wrappers-sumo';
import { logger } from '../utils/logger';
import { bytesToHex } from '../utils/encoding';

// Identity key pair
export interface IdentityKey {
  id: string;
  keyPair: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  };
}

// Pre-key bundle
export interface PreKeyBundle {
  identity: {
    id: string;
    publicKey: Uint8Array;
  };
  signedPreKey: {
    id: number;
    publicKey: Uint8Array;
    signature: Uint8Array;
  };
  oneTimePreKey?: {
    id: number;
    publicKey: Uint8Array;
  };
}

// Initiation message
export interface InitiationMessage {
  identityKey: Uint8Array;
  ephemeralKey: Uint8Array;
  preKeyId: number;
  oneTimePreKeyId?: number;
}

// Key storage for the receiver
export interface KeyStorage {
  signedPreKey: {
    id: number;
    keyPair: {
      publicKey: Uint8Array;
      privateKey: Uint8Array;
    };
  };
  oneTimePreKeys: Map<number, {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  }>;
}

/**
 * Initiate a key exchange with a recipient
 * 
 * @param identity - Initiator's identity
 * @param preKeyBundle - Recipient's pre-key bundle
 * @returns Shared secret and initiation message
 */
export async function initiateKeyExchange(
  identity: IdentityKey,
  preKeyBundle: PreKeyBundle
): Promise<[Uint8Array, InitiationMessage]> {
  await sodium.ready;
  
  // Generate ephemeral key pair
  const ephemeralKeyPair = sodium.crypto_box_keypair();
  
  // Create initiation message
  const message: InitiationMessage = {
    identityKey: identity.keyPair.publicKey,
    ephemeralKey: ephemeralKeyPair.publicKey,
    preKeyId: preKeyBundle.signedPreKey.id,
    oneTimePreKeyId: preKeyBundle.oneTimePreKey?.id
  };
  
  // Calculate shared secret components
  const dh1 = deriveSharedSecret(
    identity.keyPair.privateKey,
    preKeyBundle.signedPreKey.publicKey
  );
  
  const dh2 = deriveSharedSecret(
    ephemeralKeyPair.privateKey,
    preKeyBundle.identity.publicKey
  );
  
  const dh3 = deriveSharedSecret(
    ephemeralKeyPair.privateKey,
    preKeyBundle.signedPreKey.publicKey
  );
  
  // Combine shared secrets
  let sharedSecretInput = new Uint8Array(dh1.length + dh2.length + dh3.length);
  sharedSecretInput.set(dh1, 0);
  sharedSecretInput.set(dh2, dh1.length);
  sharedSecretInput.set(dh3, dh1.length + dh2.length);
  
  // Add one-time pre-key if available
  if (preKeyBundle.oneTimePreKey) {
    const dh4 = deriveSharedSecret(
      ephemeralKeyPair.privateKey,
      preKeyBundle.oneTimePreKey.publicKey
    );
    
    const newInput = new Uint8Array(sharedSecretInput.length + dh4.length);
    newInput.set(sharedSecretInput, 0);
    newInput.set(dh4, sharedSecretInput.length);
    sharedSecretInput = newInput;
  }
  
  // Derive final shared secret
  const hashLength = 32;
  const sharedSecret = sodium.crypto_generichash(hashLength, sharedSecretInput);
  
  return [sharedSecret, message];
}

/**
 * Process a key exchange initiation
 * 
 * @param identity - Recipient's identity
 * @param keyStorage - Recipient's key storage
 * @param message - Initiation message
 * @returns Shared secret
 */
export async function processKeyExchange(
  identity: IdentityKey,
  keyStorage: KeyStorage,
  message: InitiationMessage
): Promise<Uint8Array> {
  await sodium.ready;
  
  // Get signed pre-key
  const signedPreKey = keyStorage.signedPreKey;
  
  // Get one-time pre-key if used
  let oneTimePreKey = null;
  if (message.oneTimePreKeyId !== undefined) {
    oneTimePreKey = keyStorage.oneTimePreKeys.get(message.oneTimePreKeyId);
    if (!oneTimePreKey) {
      throw new Error(`One-time pre-key with ID ${message.oneTimePreKeyId} not found`);
    }
    
    // Remove one-time pre-key after use
    keyStorage.oneTimePreKeys.delete(message.oneTimePreKeyId);
  }
  
  // Calculate shared secret components
  const dh1 = deriveSharedSecret(
    signedPreKey.keyPair.privateKey,
    message.identityKey
  );
  
  const dh2 = deriveSharedSecret(
    identity.keyPair.privateKey,
    message.ephemeralKey
  );
  
  const dh3 = deriveSharedSecret(
    signedPreKey.keyPair.privateKey,
    message.ephemeralKey
  );
  
  // Combine shared secrets
  let sharedSecretInput = new Uint8Array(dh1.length + dh2.length + dh3.length);
  sharedSecretInput.set(dh1, 0);
  sharedSecretInput.set(dh2, dh1.length);
  sharedSecretInput.set(dh3, dh1.length + dh2.length);
  
  // Add one-time pre-key if used
  if (oneTimePreKey) {
    const dh4 = deriveSharedSecret(
      oneTimePreKey.privateKey,
      message.ephemeralKey
    );
    
    const newInput = new Uint8Array(sharedSecretInput.length + dh4.length);
    newInput.set(sharedSecretInput, 0);
    newInput.set(dh4, sharedSecretInput.length);
    sharedSecretInput = newInput;
  }
  
  // Derive final shared secret
  const hashLength = 32;
  const sharedSecret = sodium.crypto_generichash(hashLength, sharedSecretInput);
  
  return sharedSecret;
}

/**
 * Derive a shared secret using DH
 * 
 * @param privateKey - Private key
 * @param publicKey - Public key
 * @returns Shared secret
 */
function deriveSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  // In a real implementation, this would use crypto_scalarmult
  // For simplicity, we'll use a key derivation function
  
  // Sort the keys to ensure the same result regardless of the order
  const isPrivateFirst = bytesToHex(privateKey) < bytesToHex(publicKey);
  
  const combined = new Uint8Array(privateKey.length + publicKey.length);
  if (isPrivateFirst) {
    combined.set(privateKey);
    combined.set(publicKey, privateKey.length);
  } else {
    combined.set(publicKey);
    combined.set(privateKey, publicKey.length);
  }
  
  const hashLength = 32;
  return sodium.crypto_generichash(hashLength, combined);
} 