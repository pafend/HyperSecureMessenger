# HyperSecure Messenger: Network Layer

The networking layer of HyperSecure Messenger provides fully decentralized peer-to-peer (P2P) communication capabilities with no reliance on central servers or services.

## Core Components

### P2P Network Implementation

The P2P networking layer is built on libp2p and provides the following key features:

1. **Fully Decentralized Communication**: Direct peer-to-peer connections without central servers
2. **Multiple Discovery Methods**: 
   - Local network discovery via mDNS
   - DHT-based discovery for internet-scale networks
   - Manual peer connection for trusted setups
3. **Secure Connections**: All connections are encrypted using the Noise protocol
4. **Metadata Protection**: Optional onion routing to protect network metadata
5. **Mesh Networking**: Ability to route messages between peers in partially-connected networks

### Message Transport

The P2P network handles secure transport of encrypted messages between peers:

1. **End-to-End Encrypted Messages**: All messages are encrypted before transport
2. **Message Delivery Guarantees**: Store-and-forward capability for offline recipients
3. **TTL-Based Expiration**: Messages can have time-to-live values for expiration
4. **Efficient PubSub**: Using GossipSub for efficient message distribution

## Network Architecture

The network implements a hybrid architecture with multiple connection methods:

1. **Direct P2P**: When peers can directly connect
2. **DHT-Routed**: For peers behind NATs or firewalls
3. **Mesh Network Routing**: For partially connected networks

## Integration with Other Components

The P2P network integrates with other HyperSecure Messenger components:

1. **Crypto Layer**: Uses cryptographic keys for secure connections and message encryption
2. **Storage Layer**: Delivers messages to be stored in the secure storage system
3. **Identity Management**: Securely handles peer identity verification

## Usage

### Basic P2P Node Creation

```typescript
import { createP2PNetwork } from './network/p2pNetwork';

// Create and initialize a P2P network node
const node = await createP2PNetwork({
  discoveryMethod: 'hybrid',  // Use both local and DHT discovery
  useOnionRouting: true       // Enable metadata protection
});

// Start the node
await node.start();

// Connect to a peer
await node.connectToPeer('/ip4/192.168.1.42/tcp/8000/p2p/QmS...'); 

// Send an encrypted message
await node.sendMessage(recipientId, encryptedContent);

// Handle incoming messages
node.on('message', (message) => {
  // Process received message
});
```

## Testing

You can test the P2P networking functionality with:

```bash
# Run the basic P2P network test
npm run network:p2p-test

# Run the P2P integration test (with crypto and storage)
npm run integration:p2p
```

## Security Features

1. **Connection Encryption**: All P2P connections are encrypted using the Noise protocol
2. **Perfect Forward Secrecy**: Connection keys are rotated regularly
3. **Onion Routing**: Optional multi-hop routing to protect metadata
4. **Public Key Verification**: All peers verify each other's public keys
5. **No Central Points of Trust**: No reliance on any central infrastructure

## Implementation Notes

The current implementation includes:

1. Full libp2p-based P2P networking
2. Local network and DHT discovery
3. Secure message transport
4. Integration with crypto and storage components

Future enhancements will include:

1. Full onion routing implementation
2. NAT traversal improvements
3. Bandwidth and latency optimizations
4. Enhanced peer discovery through well-known peer lists
5. Circuit relay for firewall traversal

For more details on using the P2P network capabilities, see the integration tests in `src/integration/p2pIntegrationTest.ts`. 