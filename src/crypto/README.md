# HyperSecure Messenger Cryptographic Implementation

This directory contains the cryptographic implementations for the HyperSecure Messenger, focusing on secure end-to-end encrypted communication with perfect forward secrecy.

## Core Components

### 1. In-Person Key Exchange & Trusted Ratchet

The trusted ratchet implementation provides a simplified but highly secure approach to encrypted messaging that relies on an initial in-person key exchange:

- **Implementation**: [`trustedRatchet.ts`](./trustedRatchet.ts)
- **Test**: [`trustedRatchetTest.ts`](./trustedRatchetTest.ts)

Key features:
- Initial high-entropy shared secret exchanged in-person (maximum security)
- Deterministic key derivation to ensure both parties can generate the same keys
- Perfect forward secrecy through continuous key rotation
- Support for out-of-order message delivery
- Protection against message replay attacks
- Manual re-keying capability for long-term security
- No reliance on third-party key distribution

### 2. X3DH Key Exchange (Extended Triple Diffie-Hellman)

For scenarios where in-person verification isn't possible, the X3DH protocol enables secure key exchange over untrusted channels:

- **Simple Implementation**: [`simpleX3DH.ts`](./simpleX3DH.ts)
- **Extended Implementation**: [`x3dh.ts`](./x3dh.ts)

Key features:
- Asynchronous initial key exchange (does not require both parties to be online)
- Identity key verification mechanism
- Pre-key and signed pre-key bundles for initial message delivery
- Generates a shared secret for initializing the Double Ratchet

### 3. Double Ratchet Algorithm

Two implementations of the Double Ratchet Algorithm for ongoing message encryption:

- **Basic Implementation**: [`basicRatchet.ts`](./basicRatchet.ts)
- **Enhanced Implementation**: [`doubleRatchet.ts`](./doubleRatchet.ts)

Key features:
- Self-healing encryption (if a key is compromised, future messages remain secure)
- Perfect forward secrecy through continuous key rotation
- Diffie-Hellman ratchet for shared key derivation
- Symmetric-key ratchet for chain key derivation
- Support for out-of-order message delivery

## Integration

The implementations can be used in two primary configurations:

1. **High-Security Mode**: In-person key verification with the Trusted Ratchet
   - Maximum security through trusted initial key exchange
   - Simpler implementation with fewer failure points
   - Requires physical proximity for initial setup

2. **Remote Exchange Mode**: X3DH + Double Ratchet
   - Allows secure communication without in-person meeting
   - More complex with additional crypto operations
   - Needs identity validation through alternative channels

## Testing

Each component has dedicated test files to verify its implementation:

- [`trustedRatchetTest.ts`](./trustedRatchetTest.ts): Tests the trusted ratchet implementation
- [`basicRatchetTest.ts`](./basicRatchetTest.ts): Tests the basic Double Ratchet implementation
- [`simpleRatchetTest.ts`](./simpleRatchetTest.ts): Tests a simplified version of the ratchet
- [`basicIntegration.ts`](./basicIntegration.ts): Tests integration of X3DH and the basic Double Ratchet

## Usage

Run the tests using npm:

```
npm run crypto:trusted-ratchet-test   # Test the trusted ratchet implementation
npm run crypto:basic-ratchet-test     # Test the basic Double Ratchet
npm run crypto:basic-integration      # Test the integration of X3DH and Double Ratchet
```

## Security Considerations

This implementation is intended for the HyperSecure Messenger, which requires maximum security. In a production environment, additional measures should be implemented:

- Side-channel attack protection
- Secure keystore with hardware security modules when available
- Anti-forensic measures for encrypted data
- Memory protection to prevent key extraction
- Deniable authentication mechanisms
- Regular security audits

## Dependencies

- `libsodium-wrappers-sumo`: Provides the cryptographic primitives
- TypeScript with strict type checking for implementation safety 