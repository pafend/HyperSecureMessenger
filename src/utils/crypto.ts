/**
 * Cryptographic utility functions for the HyperSecure Messenger
 * 
 * This file contains helper functions for cryptographic operations
 * used throughout the application.
 */

import sodium from 'libsodium-wrappers-sumo';

/**
 * Generate random bytes using libsodium
 * 
 * @param length - The number of random bytes to generate
 * @returns A Uint8Array containing the random bytes
 */
export function generateRandomBytes(length: number): Uint8Array {
  return sodium.randombytes_buf(length);
}

/**
 * Concatenate two or more Uint8Arrays
 * 
 * @param arrays - The arrays to concatenate
 * @returns A new Uint8Array containing all the input arrays concatenated
 */
export function concatUint8Arrays(...arrays: Uint8Array[]): Uint8Array {
  // Calculate the total length
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  
  // Create a new array with the total length
  const result = new Uint8Array(totalLength);
  
  // Copy each array into the result
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  
  return result;
}

/**
 * Compare two Uint8Arrays for equality in constant time
 * 
 * @param a - The first array
 * @param b - The second array
 * @returns True if the arrays are equal, false otherwise
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  return sodium.crypto_verify_16(
    a.slice(0, Math.min(a.length, 16)),
    b.slice(0, Math.min(b.length, 16))
  );
}

/**
 * Securely zero out a Uint8Array
 * 
 * @param array - The array to zero out
 */
export function secureZeroMemory(array: Uint8Array): void {
  sodium.memzero(array);
}

/**
 * Generate a secure random key
 * 
 * @param length - The length of the key to generate
 * @returns A Uint8Array containing the random key
 */
export function generateRandomKey(length: number = 32): Uint8Array {
  return generateRandomBytes(length);
}

/**
 * Derive a key from a password using Argon2id
 * 
 * @param password - The password to derive the key from
 * @param salt - The salt to use for key derivation
 * @param keyLength - The length of the key to derive
 * @returns A Uint8Array containing the derived key
 */
export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
  keyLength: number = 32
): Promise<Uint8Array> {
  await sodium.ready;
  
  return sodium.crypto_pwhash(
    keyLength,
    new TextEncoder().encode(password),
    salt,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_ALG_DEFAULT
  );
}

/**
 * Encrypt data with a key using XChaCha20-Poly1305
 * 
 * @param data - The data to encrypt
 * @param key - The key to use for encryption
 * @returns An object containing the ciphertext and nonce
 */
export function encrypt(
  data: Uint8Array,
  key: Uint8Array
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const nonce = generateRandomBytes(sodium.crypto_secretbox_NONCEBYTES);
  const ciphertext = sodium.crypto_secretbox_easy(data, nonce, key);
  
  return { ciphertext, nonce };
}

/**
 * Decrypt data with a key using XChaCha20-Poly1305
 * 
 * @param ciphertext - The ciphertext to decrypt
 * @param nonce - The nonce used for encryption
 * @param key - The key to use for decryption
 * @returns The decrypted data
 */
export function decrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  return sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
}

/**
 * Create an HMAC for data using a key
 * 
 * @param data - The data to authenticate
 * @param key - The key to use for authentication
 * @returns The HMAC
 */
export function createHMAC(data: Uint8Array, key: Uint8Array): Uint8Array {
  return sodium.crypto_auth(data, key);
}

/**
 * Verify an HMAC for data using a key
 * 
 * @param mac - The HMAC to verify
 * @param data - The data to authenticate
 * @param key - The key to use for authentication
 * @returns True if the HMAC is valid, false otherwise
 */
export function verifyHMAC(
  mac: Uint8Array,
  data: Uint8Array,
  key: Uint8Array
): boolean {
  return sodium.crypto_auth_verify(mac, data, key);
}

/**
 * Compute a DH shared secret
 * 
 * @param privateKey - The private key
 * @param publicKey - The public key
 * @returns The shared secret
 */
export function computeDHSharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array {
  return sodium.crypto_scalarmult(privateKey, publicKey);
} 