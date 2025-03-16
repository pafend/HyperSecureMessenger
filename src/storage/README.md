# HyperSecure Messenger Storage

This directory contains the secure storage implementation for HyperSecure Messenger, providing anti-forensic capabilities for storing sensitive data.

## Core Components

### 1. Secure Storage Module (`secureStorage.ts`)

The base secure storage module provides:

- **Authenticated Encryption**: All data is encrypted at rest using libsodium's authenticated encryption.
- **Anti-Forensic Deletion**: Secure deletion with multiple overwrite passes to prevent forensic recovery.
- **Memory-Only Mode**: Option to keep all data in memory without touching disk.
- **Automatic Expiration**: Automatic secure deletion of expired items.
- **Plausible Deniability**: Structural design that minimizes metadata leakage.

### 2. Message Storage Module (`messageStorage.ts`)

Built on top of the secure storage module, the message storage provides:

- **Message Management**: Store, retrieve, and delete encrypted messages.
- **Conversation Management**: Group messages into conversations.
- **Type-Safe Interface**: Strongly typed APIs for messages and conversations.
- **Automatic Serialization**: Handles binary data and complex objects.
- **Query Capabilities**: Retrieve messages by conversation.

## Usage

The storage modules are designed to be used with the messaging components of HyperSecure Messenger:

```typescript
// Initialize message storage
const storage = new MessageStorage();
await storage.initialize(masterKey);

// Create a conversation
const conversation = storage.createConversation(
  ['alice@hypersecure.chat', 'bob@hypersecure.chat'], 
  'Secret Project'
);
await storage.storeConversation(conversation);

// Create and store a message
const message = storage.createMessage(
  conversation.id,
  'alice@hypersecure.chat',
  encryptedContent,
  24 * 60 * 60 * 1000 // Expire after 24 hours
);
await storage.storeMessage(message);

// Retrieve messages
const messageIds = await storage.getMessagesForConversation(conversation.id);
for (const id of messageIds) {
  const message = await storage.retrieveMessage(id);
  // Process message...
}
```

## Security Features

The storage implementation includes several security features:

1. **Zero Storage of Plaintext**: All sensitive data is encrypted before storage.
2. **Perfect Forward Secrecy**: Each item has its own encryption parameters.
3. **Secure Deletion**: Multi-pass overwriting to prevent forensic recovery.
4. **Automatic Expiration**: Time-based secure deletion for ephemeral messages.
5. **Memory-Only Mode**: Option to avoid storing any data on disk.
6. **Metadata Protection**: Minimizing stored metadata to prevent leakage.
7. **Plausible Deniability**: Storage structure that doesn't reveal the nature of contents.

## Testing

Each component has dedicated test files to verify its implementation:

- [`secureStorageTest.ts`](./secureStorageTest.ts): Tests for the secure storage module.
- [`messageStorageTest.ts`](./messageStorageTest.ts): Tests for the message storage module.

Run the tests using npm:

```
npm run storage:test            # Test the secure storage module
npm run storage:message-test    # Test the message storage module
```

## Integration with Crypto

The storage modules are designed to work with the cryptographic components from the `crypto` directory:

- Messages are typically encrypted with the trusted ratchet or double ratchet before storage.
- Conversations maintain cryptographic state for the messaging protocols.
- The storage layer provides an additional layer of protection beyond the E2E encryption. 