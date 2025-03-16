declare module 'libsodium-wrappers-sumo' {
  interface LibsodiumWrappersSumo {
    ready: Promise<void>;
    
    // Key generation
    crypto_box_keypair: () => { publicKey: Uint8Array; privateKey: Uint8Array; };
    
    // Random bytes
    randombytes_buf: (length: number) => Uint8Array;
    
    // Constants
    crypto_box_NONCEBYTES: number;
    crypto_box_PUBLICKEYBYTES: number;
    crypto_box_SECRETKEYBYTES: number;
    crypto_box_MACBYTES: number;
    crypto_secretbox_KEYBYTES: number;
    crypto_secretbox_NONCEBYTES: number;
    crypto_generichash_BYTES: number;
    crypto_generichash_BYTES_MIN: number;
    crypto_generichash_BYTES_MAX: number;
    crypto_generichash_KEYBYTES: number;
    crypto_scalarmult_BYTES: number;
    
    // Encryption
    crypto_box_easy: (message: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array) => Uint8Array;
    crypto_box_open_easy: (ciphertext: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array) => Uint8Array;
    
    // Secret-key encryption
    crypto_secretbox_easy: (message: Uint8Array, nonce: Uint8Array, key: Uint8Array) => Uint8Array;
    crypto_secretbox_open_easy: (ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array) => Uint8Array;
    
    // Hashing
    crypto_hash: (message: Uint8Array) => Uint8Array;
    
    // Generic hashing
    crypto_generichash: (hash_length: number, message: Uint8Array) => Uint8Array;
    crypto_generichash_batch: (hash_length: number, message_chunks: Uint8Array[], key?: Uint8Array) => Uint8Array;
    
    // Scalar multiplication (DH)
    crypto_scalarmult: (privateKey: Uint8Array, publicKey: Uint8Array) => Uint8Array;
    
    // Memory management
    memzero: (array: Uint8Array) => void;
    memcmp: (a: Uint8Array, b: Uint8Array) => boolean;
    sodium_malloc?: (length: number) => Uint8Array;
    sodium_free?: (array: Uint8Array) => void;
    
    // Encoding/decoding
    to_base64: (input: Uint8Array) => string;
    from_base64: (input: string) => Uint8Array;
  }
  
  const sodium: LibsodiumWrappersSumo;
  export default sodium;
} 