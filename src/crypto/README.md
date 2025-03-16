# HyperSecure Messenger Cryptography

This directory contains the cryptographic implementations for HyperSecure Messenger, focusing on secure end-to-end encrypted communication with perfect forward secrecy.

## Core Components

### X3DH Key Exchange

The Extended Triple Diffie-Hellman (X3DH) protocol is implemented in `minimalX3DH.ts`. This protocol establishes a shared secret between two parties who may be offline at different times. Key features:

- Identity key management
- Pre-key bundles for asynchronous communication
- Perfect forward secrecy
- Multiple Diffie-Hellman exchanges for enhanced security

### Double Ratchet Algorithm

We have two implementations of the Double Ratchet algorithm:

1. **Basic Implementation** (`basicRatchet.ts`): 
   - Simple implementation focused on core functionality
   - Provides basic encryption/decryption with key rotation
   - Does not support out-of-order messages
   - Uses XOR-based encryption (for demonstration purposes)

2. **Enhanced Implementation** (`doubleRatchet.ts`):
   - Full-featured implementation with authenticated encryption
   - Supports out-of-order messages
   - Implements proper key derivation functions
   - Uses libsodium's crypto_secretbox for authenticated encryption

## Integration

The integration of X3DH and Double Ratchet is demonstrated in `integration.ts`. This shows a complete secure messaging setup:

1. Identity key generation
2. Pre-key bundle creation
3. X3DH key exchange
4. Double Ratchet initialization
5. Secure message exchange with forward secrecy

## Testing

Various test files are provided to verify the correctness of the implementations:

- `basicRatchetTest.ts`: Tests for the basic Double Ratchet
- `doubleRatchetTest.ts`: Tests for the enhanced Double Ratchet
- `x3dh.test.ts`: Tests for the X3DH key exchange
- `integration.ts`: End-to-end test of the complete secure messaging protocol

## Usage

To run the integration test:

```bash
npm run crypto:integration
```

To run the basic Double Ratchet test:

```bash
npm run crypto:basic-ratchet-test
```

## Security Considerations

This implementation focuses on the core cryptographic protocols. In a production environment, additional security measures would be needed:

- Secure storage of keys and session states
- Anti-forensic measures for sensitive data
- Protection against side-channel attacks
- Metadata protection
- Post-quantum cryptography considerations

## Dependencies

- libsodium-wrappers-sumo: For cryptographic primitives
- TypeScript: For type safety and code organization 