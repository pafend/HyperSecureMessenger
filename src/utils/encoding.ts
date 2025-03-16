/**
 * Encoding utility functions for HyperSecure Messenger
 * These functions handle conversions between different data formats
 * with zero dependencies on external libraries for maximum security.
 */

/**
 * Convert a UTF-8 string to a Uint8Array
 * @param str The string to encode
 * @returns Uint8Array containing the UTF-8 encoded bytes
 */
export function utf8Encode(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

/**
 * Convert a Uint8Array to a UTF-8 string
 * @param bytes The bytes to decode
 * @returns Decoded UTF-8 string
 */
export function utf8Decode(bytes: Uint8Array): string {
  const decoder = new TextDecoder('utf-8');
  return decoder.decode(bytes);
}

/**
 * Convert a Uint8Array to a hex string
 * @param bytes The bytes to convert
 * @returns Hex string representation
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert a hex string to a Uint8Array
 * @param hex The hex string to convert
 * @returns Uint8Array containing the bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Hex string must have an even number of characters');
  }
  
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    result[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  
  return result;
}

/**
 * Convert a Uint8Array to a base64 string
 * @param bytes The bytes to convert
 * @returns Base64 string representation
 */
export function bytesToBase64(bytes: Uint8Array): string {
  // Platform-independent implementation
  if (typeof Buffer !== 'undefined') {
    // Node.js environment
    return Buffer.from(bytes).toString('base64');
  } else if (typeof btoa === 'function') {
    // Browser environment
    const binaryString = Array.from(bytes)
      .map(byte => String.fromCharCode(byte))
      .join('');
    return btoa(binaryString);
  } else {
    // Fallback implementation for other environments
    const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let result = '';
    const len = bytes.length;
    for (let i = 0; i < len; i += 3) {
      const b1 = bytes[i];
      const b2 = i + 1 < len ? bytes[i + 1] : 0;
      const b3 = i + 2 < len ? bytes[i + 2] : 0;
      const triplet = (b1 << 16) | (b2 << 8) | b3;
      result += CHARS[(triplet >> 18) & 0x3F];
      result += CHARS[(triplet >> 12) & 0x3F];
      result += i + 1 < len ? CHARS[(triplet >> 6) & 0x3F] : '=';
      result += i + 2 < len ? CHARS[triplet & 0x3F] : '=';
    }
    return result;
  }
}

/**
 * Convert a base64 string to a Uint8Array
 * @param base64 The base64 string to convert
 * @returns Uint8Array containing the bytes
 */
export function base64ToBytes(base64: string): Uint8Array {
  // Platform-independent implementation
  if (typeof Buffer !== 'undefined') {
    // Node.js environment
    return new Uint8Array(Buffer.from(base64, 'base64'));
  } else if (typeof atob === 'function') {
    // Browser environment
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  } else {
    // Fallback implementation for other environments
    // Remove padding characters
    const base64Clean = base64.replace(/=+$/, '');
    const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const lookup = new Uint8Array(256);
    for (let i = 0; i < CHARS.length; i++) {
      lookup[CHARS.charCodeAt(i)] = i;
    }
    
    const outputLength = Math.floor((base64Clean.length * 3) / 4);
    const result = new Uint8Array(outputLength);
    
    let outputPosition = 0;
    for (let i = 0; i < base64Clean.length; i += 4) {
      const a = lookup[base64Clean.charCodeAt(i)];
      const b = lookup[base64Clean.charCodeAt(i + 1)];
      const c = i + 2 < base64Clean.length ? lookup[base64Clean.charCodeAt(i + 2)] : 0;
      const d = i + 3 < base64Clean.length ? lookup[base64Clean.charCodeAt(i + 3)] : 0;
      
      const triplet = (a << 18) | (b << 12) | (c << 6) | d;
      
      if (outputPosition < outputLength) result[outputPosition++] = (triplet >> 16) & 0xFF;
      if (outputPosition < outputLength) result[outputPosition++] = (triplet >> 8) & 0xFF;
      if (outputPosition < outputLength) result[outputPosition++] = triplet & 0xFF;
    }
    
    return result;
  }
}

/**
 * Securely concatenate two Uint8Arrays
 * @param a First array
 * @param b Second array
 * @returns New Uint8Array containing a followed by b
 */
export function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

/**
 * Compare two Uint8Arrays for equality in constant time
 * @param a First array
 * @param b Second array
 * @returns True if arrays have identical content
 */
export function constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    // XOR each byte and OR the results
    // This ensures we check all bytes even if we find a mismatch
    result |= a[i] ^ b[i];
  }
  
  return result === 0;
} 