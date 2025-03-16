# HyperSecure Messenger: Identity Management

The identity management module of HyperSecure Messenger provides a fully decentralized, cryptographically secure system for managing user identities without any central servers.

## Core Features

1. **Decentralized Identity Management**: No reliance on central servers or authorities
2. **Cryptographic Identities**: Each identity is backed by strong cryptographic keys
3. **Identity Verification**: Manual identity verification with trust marking
4. **Secure Storage**: All identity data is securely stored
5. **Identity Portability**: Export/import support for identity sharing
6. **Zero Trust Model**: Trust is explicitly granted only after verification

## Key Components

### Identity Interface

The `Identity` interface represents a basic user identity with the following properties:

- `userId`: A unique identifier derived from the user's public key
- `displayName`: User-friendly name for display
- `publicKey`: The user's public key for verification
- `fingerprint`: A fingerprint derived from the public key for easy verification
- `createdAt`: Timestamp of identity creation
- `deviceId`: Unique device identifier
- `trusted`: Flag indicating if the identity has been verified and trusted

### User Identity

The `UserIdentity` extends the basic `Identity` with information specific to the local user:

- `privateKey`: The user's private key for signing messages
- `recoveryPhrase`: Optional backup phrase for recovery

### Identity Manager

The `IdentityManager` class provides the following key functionalities:

1. **Identity Creation**: Generate new cryptographic identities
2. **Identity Storage**: Securely store identities in encrypted storage
3. **Identity Export/Import**: Share public identity information
4. **Trust Management**: Mark identities as trusted/untrusted after verification
5. **Message Signing**: Sign messages with the local identity
6. **Signature Verification**: Verify signatures from other identities

## Usage Examples

### Creating a Local Identity

```typescript
// Initialize identity manager
const identityManager = new IdentityManager({
  storageKey: 'user-identities',
  storagePassword: 'secure-password', // Should be derived from user password
  secureStorage: secureStorage
});

await identityManager.initialize();

// Create a new identity
const identity = await identityManager.createIdentity('Alice');
console.log(`Identity created with ID: ${identity.userId}`);
```

### Exporting and Importing Identities

```typescript
// Export identity for sharing (only public information)
const exportedData = identityManager.exportIdentity(identity.userId);

// Share the exported data with another user (QR code, NFC, etc.)
// ...

// On the recipient side:
const importedIdentity = await identityManager.importIdentity(exportedData);
```

### Trust Verification

```typescript
// After verifying identity through secure channel (in-person, video call, etc.)
await identityManager.trustIdentity(importedIdentity.userId, true);

// Get all trusted identities
const trustedContacts = identityManager.getTrustedIdentities();
```

### Message Signing & Verification

```typescript
// Sign a message
const message = new TextEncoder().encode('Hello, this is a secure message');
const signature = identityManager.signMessage(message);

// Verify a signature
const isValid = identityManager.verifySignature(senderId, message, signature);
if (isValid) {
  console.log('Message signature verified successfully');
} else {
  console.log('Invalid signature - possible tampering detected');
}
```

## Security Features

1. **No Central Identity Provider**: Identities are created and managed locally
2. **Cryptographic Verification**: Ed25519 signatures for all identity operations
3. **Fingerprint Verification**: Human-verifiable fingerprints for key comparison
4. **Explicit Trust Model**: Trust must be explicitly granted after verification
5. **Secure Storage**: All identity data is stored in encrypted form
6. **Private Key Protection**: Private keys never leave the device

## Testing

To run the identity manager tests:

```bash
npm run identity:test
```

This will execute a comprehensive test suite that validates:
- Identity creation
- Identity export/import
- Trust management
- Signature generation and verification
- Storage and retrieval

## Implementation Notes

The current implementation uses Ed25519 signatures via libsodium for all cryptographic operations. The system is designed to be easily extensible to support multiple device identities and identity recovery in future versions.

For more details on the implementation, see the source code in `identityManager.ts` and the tests in `identityManagerTest.ts`. 