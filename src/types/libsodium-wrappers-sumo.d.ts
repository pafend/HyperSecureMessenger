/**
 * Type definitions for libsodium-wrappers-sumo
 * 
 * This file provides TypeScript type definitions for the libsodium-wrappers-sumo package.
 */

declare module 'libsodium-wrappers-sumo' {
  interface KeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
    keyType: string;
  }

  interface LibsodiumWrappersSumo {
    ready: Promise<void>;
    
    // Random bytes generation
    randombytes_buf(length: number): Uint8Array;
    
    // Constants
    crypto_box_PUBLICKEYBYTES: number;
    crypto_box_SECRETKEYBYTES: number;
    crypto_box_NONCEBYTES: number;
    crypto_box_MACBYTES: number;
    crypto_secretbox_NONCEBYTES: number;
    crypto_secretbox_KEYBYTES: number;
    crypto_secretbox_MACBYTES: number;
    
    // Key generation
    crypto_box_keypair(): KeyPair;
    crypto_scalarmult_base(privateKey: Uint8Array): Uint8Array;
    
    // Diffie-Hellman
    crypto_scalarmult(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
    
    // Hashing
    crypto_generichash(outputLength: number, message: Uint8Array, key?: Uint8Array): Uint8Array;
    
    // Authenticated encryption
    crypto_secretbox_easy(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
    crypto_secretbox_open_easy(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
    
    // Public key encryption
    crypto_box_easy(message: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array): Uint8Array;
    crypto_box_open_easy(ciphertext: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array): Uint8Array;
  }

  const sodium: LibsodiumWrappersSumo;
  export default sodium;
} 