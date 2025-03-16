# HyperSecure Messenger

A fully decentralized, end-to-end encrypted messenger with no central servers or services. 

> **IMPORTANT**: HyperSecure Messenger is never distributed as a pre-built application. All users must build the software themselves from source code. There are no official builds or binaries. [Learn more about our self-build policy](disclaimer.md#self-build-only-policy).

[Read our Manifesto](manifesto.md) | [Important Disclaimers](disclaimer.md)

## Architecture

HyperSecure Messenger is built with a modular architecture consisting of several key components:

### Cryptography Layer

- **Trusted Ratchet**: Secure messaging protocol based on the Double Ratchet algorithm
- **Identity Management**: Cryptographic identity creation, verification, and management
- **Anti-Forensic Storage**: Secure storage with plausible deniability and secure deletion

### Networking Layer

- **P2P Network**: Fully decentralized peer-to-peer networking using libp2p
- **Distributed Discovery**: Find peers without central servers
- **Onion Routing**: Protect metadata through multi-hop routing

### Storage Layer

- **Secure Storage**: Encrypted local storage with anti-forensic capabilities
- **Message Storage**: Secure storage and retrieval of messages with automatic expiration
- **Backup & Recovery**: Secure, encrypted backups with recovery options

### User Interface

- **Minimal UI**: Simple, secure interface focused on privacy
- **Verification UI**: Tools for verifying identities and securing communications
- **Accessibility**: Designed to be usable by everyone

## Getting Started

### Prerequisites

- Node.js 16+
- npm or yarn
- Git for source code verification
- Basic knowledge of command line tools

### Installation (Self-Build Only)

HyperSecure Messenger adheres to a strict self-build policy. Each user must:

1. Verify the source code
2. Build the application themselves
3. Maintain their own installation

```bash
# Clone the repository and verify the source
git clone https://github.com/yourusername/hypersecure-messenger.git
cd hypersecure-messenger

# Examine the code for any security concerns
# This step is critical - never skip code review

# Install dependencies after reviewing package.json
npm install

# Build the application
npm run build

# Start your self-built application
npm start
```

No pre-built binaries are ever provided. This ensures you have complete control and visibility over the code running on your device.

### Development

```bash
# Run in development mode
npm run dev

# Build for production
npm run build

# Run tests
npm test
```

## Security Features

- **End-to-End Encryption**: All messages are encrypted using strong cryptography
- **Perfect Forward Secrecy**: Key rotation ensures past communications remain secure
- **Identity Verification**: Manual verification of contacts through secure channels
- **Anti-Forensic Storage**: Secure deletion with multiple overwrite passes
- **Metadata Protection**: Minimize metadata leakage through network design
- **No Central Points of Trust**: Fully decentralized architecture

## Testing

The project includes comprehensive tests for all components:

```bash
# Run all tests
npm test

# Run specific test suites
npm run storage:test
npm run identity:test
npm run network:p2p-test

# Run integration tests
npm run integration:p2p
npm run integration:identity-network
npm run integration:full-system
```

## Project Structure

```
src/
├── crypto/           # Cryptographic components
│   ├── trustedRatchet.ts
│   └── README.md
├── identity/         # Identity management
│   ├── identityManager.ts
│   └── README.md
├── network/          # P2P networking
│   ├── p2pNetwork.ts
│   └── README.md
├── storage/          # Secure storage
│   ├── secureStorage.ts
│   ├── messageStorage.ts
│   └── README.md
├── integration/      # Integration tests
│   ├── p2pIntegrationTest.ts
│   ├── identityNetworkTest.ts
│   └── fullSystemTest.ts
├── utils/            # Utility functions
│   └── logger.ts
└── index.ts          # Application entry point
```

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting a pull request.

## Security

If you discover a security vulnerability, please do NOT open an issue. Email security@example.com instead.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The Signal Protocol for inspiration on secure messaging
- The libp2p project for decentralized networking capabilities
- The crypto community for their ongoing work in secure communications 