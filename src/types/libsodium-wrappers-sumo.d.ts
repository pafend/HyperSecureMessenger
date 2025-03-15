declare module 'libsodium-wrappers-sumo' {
  interface LibsodiumWrappersSumo {
    ready: Promise<void>;
    crypto_box_keypair: () => { publicKey: Uint8Array; privateKey: Uint8Array; };
    randombytes_buf: (length: number) => Uint8Array;
    crypto_box_NONCEBYTES: number;
    crypto_hash_BYTES: number;
    crypto_box_easy: (message: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array) => Uint8Array;
    crypto_box_open_easy: (ciphertext: Uint8Array, nonce: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array) => Uint8Array;
    memcmp: (a: Uint8Array, b: Uint8Array) => boolean;
    crypto_hash: (message: Uint8Array) => Uint8Array;
    sodium_malloc: (length: number) => Uint8Array;
    sodium_free: (array: Uint8Array) => void;
    crypto_generichash: (input: Uint8Array | string) => Uint8Array;
    to_base64: (input: Uint8Array) => string;
    from_base64: (input: string) => Uint8Array;
  }
  
  const sodium: LibsodiumWrappersSumo;
  export default sodium;
} 