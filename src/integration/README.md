# HyperSecure Messenger Integration Tests

This directory contains integration tests that verify the proper functioning of multiple components working together within the HyperSecure Messenger system.

## Core Integration Components

### Full System Test

The `fullSystemTest.ts` file verifies the seamless integration between:

1. **Secure Storage**: Testing basic encrypted storage operations
2. **Message Storage**: Verifying conversation and message management
3. **Trusted Ratchet**: Validating end-to-end encrypted messaging
4. **Message Expiration**: Confirming automatic self-destruction of messages

This integration test ensures that the core cryptographic and storage components of HyperSecure Messenger work together correctly, satisfying the high-security requirements of the platform.

## Running Integration Tests

```bash
# Run the full system integration test
npm run integration:full-system
```

## Component Interaction

The integration tests demonstrate how different components work together:

### 1. Cryptography + Storage Integration

The cryptographic components (Trusted Ratchet) generate encrypted messages that are then stored and retrieved using the secure storage layer. This verifies that:

- Encrypted messages can be properly stored and retrieved
- Message metadata is correctly preserved
- Cryptographic sessions maintain state across multiple messages
- Different users (Alice and Bob) can securely communicate

### 2. Storage + Expiration Integration

The secure storage layer implements the automatic expiration of messages, which is a critical privacy feature. The tests verify that:

- Messages with expiration times are automatically deleted
- Permanent messages remain available
- Deleted messages become unrecoverable
- The expiration process doesn't affect other messages

## Security Properties Verified

These integration tests confirm several key security properties required by HyperSecure Messenger:

1. **End-to-End Encryption**: Messages are only readable by the intended recipient
2. **Perfect Forward Secrecy**: Each message uses derived keys that evolve over time
3. **Anti-Forensic Storage**: Secure deletion with cryptographic guarantees
4. **Self-Destructing Messages**: Automatic expiration of messages after a set time
5. **Zero Trust Architecture**: No central services required for message exchange

## Adding New Integration Tests

When adding new components to HyperSecure Messenger, corresponding integration tests should be created that verify:

1. The component functions correctly in isolation (unit tests)
2. The component integrates properly with existing systems
3. The integration preserves all security properties
4. Performance remains acceptable when components interact

New tests should be added to the package.json scripts section with the prefix `integration:`. 