/**
 * P2P Network Implementation for HyperSecure Messenger
 * 
 * This module provides a fully decentralized P2P networking layer using libp2p.
 * It implements secure peer discovery, connection management, and encrypted message transport
 * with no reliance on central servers.
 */

import { logger } from '../utils/logger';
import sodium from 'libsodium-wrappers-sumo';
import { createLibp2p, Libp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { noise } from '@chainsafe/libp2p-noise';
import { mplex } from '@libp2p/mplex';
import { kadDHT } from '@libp2p/kad-dht';
import { mdns } from '@libp2p/mdns';
import { pubsubPeerDiscovery } from '@libp2p/pubsub-peer-discovery';
import { gossipsub } from '@chainsafe/libp2p-gossipsub';
import { bootstrap } from '@libp2p/bootstrap';
import { webSockets } from '@libp2p/websockets';
import { toString as uint8ArrayToString } from 'uint8arrays/to-string';
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string';
import { PeerId } from '@libp2p/interface-peer-id';
import { multiaddr } from '@multiformats/multiaddr';
import EventEmitter from 'events';

// Network configuration options
export interface P2PNetworkOptions {
  // Local node configuration
  listenPort: number;
  listenAddress: string;
  
  // Security and routing
  useOnionRouting: boolean;
  routingHops: number;
  
  // Discovery method
  discoveryMethod: 'manual' | 'local-network' | 'dht' | 'hybrid';
  
  // Bootstrap nodes (used if discovery method includes 'dht')
  bootstrapNodes: string[];
  
  // Mesh network options
  enableMesh: boolean;
  maxConnections: number;
  
  // Encryption key (optional, will generate if not provided)
  encryptionKey?: Uint8Array;
}

// Default network configuration
const DEFAULT_P2P_OPTIONS: P2PNetworkOptions = {
  listenPort: 0, // Zero means pick an available port
  listenAddress: '0.0.0.0',
  useOnionRouting: true,
  routingHops: 3,
  discoveryMethod: 'hybrid', // Use multiple discovery methods for better connectivity
  bootstrapNodes: [
    // These would be community-maintained nodes in a real implementation
    // or user could provide their own trusted bootstrap nodes
    '/dns4/bootstrap.libp2p.io/tcp/443/wss/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN',
    '/dns4/bootstrap.libp2p.io/tcp/443/wss/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa'
  ],
  enableMesh: true,
  maxConnections: 50
};

// P2P message structure
export interface P2PMessage {
  id: string;
  sender: string;
  recipient: string;
  encryptedContent: Uint8Array;
  timestamp: number;
  ttl: number;
  routingInfo?: {
    path: string[];
    hops: number;
  };
}

/**
 * P2P Network class that provides secure peer-to-peer networking
 * for HyperSecure Messenger
 */
export class P2PNetwork extends EventEmitter {
  private options: P2PNetworkOptions;
  private libp2p: Libp2p | null = null;
  private nodeId: string = '';
  private keyPair: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null;
  private isRunning: boolean = false;
  private connectedPeers: Map<string, { peerId: string, publicKey?: Uint8Array, lastSeen: number }> = new Map();
  
  // Topics for messaging
  private readonly DIRECT_MSG_TOPIC = 'hypersecure/dm/v1';
  private readonly DISCOVERY_TOPIC = 'hypersecure/discovery/v1';
  
  constructor(options: Partial<P2PNetworkOptions> = {}) {
    super();
    this.options = { ...DEFAULT_P2P_OPTIONS, ...options };
  }
  
  /**
   * Initialize the P2P network
   */
  public async initialize(): Promise<void> {
    try {
      await sodium.ready;
      logger.info('Initializing P2P Network layer...');
      
      // Generate or use provided encryption key
      if (this.options.encryptionKey) {
        // Use provided key to derive key pair
        const seed = sodium.crypto_generichash(sodium.crypto_box_SECRETKEYBYTES, this.options.encryptionKey);
        this.keyPair = sodium.crypto_box_seed_keypair(seed);
      } else {
        // Generate new random key pair
        this.keyPair = sodium.crypto_box_keypair();
      }
      
      // Create a simple hash of the public key for the node ID
      const publicKeyHash = sodium.crypto_generichash(16, this.keyPair.publicKey);
      this.nodeId = uint8ArrayToString(publicKeyHash, 'base64');
      
      logger.info(`P2P node initialized with ID: ${this.nodeId}`);
    } catch (error) {
      logger.error('Failed to initialize P2P network', error);
      throw error;
    }
  }
  
  /**
   * Start the P2P network node
   */
  public async start(): Promise<void> {
    if (!this.keyPair) {
      throw new Error('P2P network not initialized. Call initialize() first.');
    }
    
    if (this.isRunning) {
      logger.warn('P2P network already running');
      return;
    }
    
    try {
      logger.info('Starting P2P network node...');
      
      // Configure libp2p based on options
      const libp2pConfig = await this.buildLibp2pConfiguration();
      
      // Create and start the libp2p node
      this.libp2p = await createLibp2p(libp2pConfig);
      await this.libp2p.start();
      
      // Set up message handling
      this.setupMessageHandling();
      
      // Save node state
      this.isRunning = true;
      
      // Log listening addresses
      const addresses = this.libp2p.getMultiaddrs();
      logger.info(`P2P node listening on: ${addresses.map(a => a.toString()).join(', ')}`);
      
      // Emit started event
      this.emit('started', { nodeId: this.nodeId });
      
      logger.info(`P2P network node started successfully with ID: ${this.nodeId}`);
    } catch (error) {
      logger.error('Failed to start P2P network node', error);
      throw error;
    }
  }
  
  /**
   * Stop the P2P network node
   */
  public async stop(): Promise<void> {
    if (!this.isRunning || !this.libp2p) {
      logger.warn('P2P network not running');
      return;
    }
    
    try {
      logger.info('Stopping P2P network node...');
      
      // Unsubscribe from topics
      await this.libp2p.pubsub.unsubscribe(this.DIRECT_MSG_TOPIC);
      await this.libp2p.pubsub.unsubscribe(this.DISCOVERY_TOPIC);
      
      // Stop the libp2p node
      await this.libp2p.stop();
      
      // Clear state
      this.libp2p = null;
      this.isRunning = false;
      this.connectedPeers.clear();
      
      logger.info('P2P network node stopped successfully');
      
      // Emit stopped event
      this.emit('stopped', { nodeId: this.nodeId });
    } catch (error) {
      logger.error('Failed to stop P2P network node', error);
      throw error;
    }
  }
  
  /**
   * Build the libp2p configuration based on the options
   */
  private async buildLibp2pConfiguration(): Promise<any> {
    const config: any = {
      addresses: {
        listen: [`/ip4/${this.options.listenAddress}/tcp/${this.options.listenPort}`]
      },
      transports: [
        tcp(),
        webSockets()
      ],
      connectionEncryption: [
        noise()
      ],
      streamMuxers: [
        mplex()
      ],
      services: {
        pubsub: gossipsub({
          allowPublishToZeroPeers: true,
          emitSelf: false
        })
      }
    };
    
    // Add peer discovery based on options
    const peerDiscovery = [];
    
    if (['local-network', 'hybrid'].includes(this.options.discoveryMethod)) {
      peerDiscovery.push(mdns());
      logger.info('Enabled local network discovery (mDNS)');
    }
    
    if (['dht', 'hybrid'].includes(this.options.discoveryMethod)) {
      // Add Kademlia DHT for peer discovery and content routing
      config.services.dht = kadDHT({
        clientMode: false, // Full DHT node
        kBucketSize: 20
      });
      
      // Add bootstrap nodes for initial connection
      if (this.options.bootstrapNodes.length > 0) {
        peerDiscovery.push(bootstrap({
          list: this.options.bootstrapNodes
        }));
        logger.info(`Added ${this.options.bootstrapNodes.length} bootstrap nodes for DHT`);
      }
      
      // Add PubSub peer discovery
      peerDiscovery.push(pubsubPeerDiscovery({
        interval: 10000, // Discover peers every 10 seconds
        topics: [this.DISCOVERY_TOPIC]
      }));
      
      logger.info('Enabled DHT and PubSub peer discovery');
    }
    
    if (peerDiscovery.length > 0) {
      config.peerDiscovery = peerDiscovery;
    }
    
    if (this.options.maxConnections > 0) {
      // Configure connection manager
      config.connectionManager = {
        maxConnections: this.options.maxConnections,
        minConnections: Math.min(5, this.options.maxConnections)
      };
    }
    
    return config;
  }
  
  /**
   * Set up message handling for the P2P network
   */
  private setupMessageHandling(): void {
    if (!this.libp2p) return;
    
    // Subscribe to direct message topic
    this.libp2p.pubsub.subscribe(this.DIRECT_MSG_TOPIC);
    
    // Subscribe to discovery topic
    this.libp2p.pubsub.subscribe(this.DISCOVERY_TOPIC);
    
    // Handle incoming messages
    this.libp2p.pubsub.addEventListener('message', async (event: any) => {
      try {
        const { topic, data } = event.detail;
        
        if (topic === this.DIRECT_MSG_TOPIC) {
          await this.handleDirectMessage(data);
        } else if (topic === this.DISCOVERY_TOPIC) {
          await this.handleDiscoveryMessage(data);
        }
      } catch (error) {
        logger.error('Error handling pubsub message', error);
      }
    });
    
    // Handle peer connection events
    this.libp2p.addEventListener('peer:connect', (event: any) => {
      const remotePeerId = event.detail.remotePeer.toString();
      logger.info(`Connected to peer: ${remotePeerId}`);
      
      this.connectedPeers.set(remotePeerId, {
        peerId: remotePeerId,
        lastSeen: Date.now()
      });
      
      this.emit('peer:connect', { peerId: remotePeerId });
    });
    
    // Handle peer disconnection events
    this.libp2p.addEventListener('peer:disconnect', (event: any) => {
      const remotePeerId = event.detail.remotePeer.toString();
      logger.info(`Disconnected from peer: ${remotePeerId}`);
      
      this.connectedPeers.delete(remotePeerId);
      
      this.emit('peer:disconnect', { peerId: remotePeerId });
    });
  }
  
  /**
   * Handle incoming direct messages
   */
  private async handleDirectMessage(data: Uint8Array): Promise<void> {
    try {
      // Parse the message
      const messageStr = uint8ArrayToString(data);
      const message = JSON.parse(messageStr) as P2PMessage;
      
      // Check if this message is for us
      if (message.recipient !== this.nodeId) {
        if (this.options.useOnionRouting) {
          // If this is part of onion routing, try to forward it
          await this.forwardMessage(message);
        }
        return;
      }
      
      // Check if the message has expired
      if (message.ttl > 0 && Date.now() > message.timestamp + message.ttl) {
        logger.debug(`Received expired message from ${message.sender}, discarding`);
        return;
      }
      
      // Process message (in a real implementation, we would decrypt it here)
      logger.info(`Received message from ${message.sender} with ID: ${message.id}`);
      
      // Emit message event
      this.emit('message', message);
    } catch (error) {
      logger.error('Failed to process direct message', error);
    }
  }
  
  /**
   * Handle discovery messages
   */
  private async handleDiscoveryMessage(data: Uint8Array): Promise<void> {
    try {
      const messageStr = uint8ArrayToString(data);
      const message = JSON.parse(messageStr);
      
      // Update peer information if this is a discovery advertisement
      if (message.type === 'discovery' && message.nodeId && message.publicKey) {
        const peerId = message.nodeId;
        
        // Update connected peers with public key info
        if (this.connectedPeers.has(peerId)) {
          const peer = this.connectedPeers.get(peerId)!;
          peer.publicKey = uint8ArrayFromString(message.publicKey, 'base64');
          peer.lastSeen = Date.now();
          this.connectedPeers.set(peerId, peer);
          
          logger.debug(`Updated peer information for ${peerId}`);
        }
      }
    } catch (error) {
      logger.error('Failed to process discovery message', error);
    }
  }
  
  /**
   * Forward a message as part of onion routing
   */
  private async forwardMessage(message: P2PMessage): Promise<void> {
    // Only forward if we're using onion routing and the message has routing info
    if (!this.options.useOnionRouting || !message.routingInfo) {
      return;
    }
    
    try {
      // Check if we have more hops to go
      if (message.routingInfo.path.length > message.routingInfo.hops) {
        // Get the next hop
        const nextHopId = message.routingInfo.path[message.routingInfo.hops];
        
        // Increment the hop count
        message.routingInfo.hops++;
        
        // Forward the message
        await this.sendMessageToPeer(nextHopId, message);
        
        logger.debug(`Forwarded message ${message.id} to next hop: ${nextHopId}`);
      } else {
        logger.debug(`Cannot forward message ${message.id}: routing path exhausted`);
      }
    } catch (error) {
      logger.error(`Failed to forward message ${message.id}`, error);
    }
  }
  
  /**
   * Connect to a peer using their multiaddress
   */
  public async connectToPeer(multiAddr: string): Promise<boolean> {
    if (!this.isRunning || !this.libp2p) {
      throw new Error('P2P network not running');
    }
    
    try {
      const ma = multiaddr(multiAddr);
      await this.libp2p.dial(ma);
      return true;
    } catch (error) {
      logger.error(`Failed to connect to peer at ${multiAddr}`, error);
      return false;
    }
  }
  
  /**
   * Disconnect from a peer
   */
  public async disconnectFromPeer(peerId: string): Promise<void> {
    if (!this.isRunning || !this.libp2p) {
      throw new Error('P2P network not running');
    }
    
    try {
      await this.libp2p.hangUp(PeerId.parse(peerId));
    } catch (error) {
      logger.error(`Failed to disconnect from peer ${peerId}`, error);
      throw error;
    }
  }
  
  /**
   * Send an encrypted message to a peer
   */
  public async sendMessage(
    recipientId: string, 
    content: Uint8Array, 
    options: { ttl?: number; useOnionRouting?: boolean } = {}
  ): Promise<string> {
    if (!this.isRunning || !this.libp2p || !this.keyPair) {
      throw new Error('P2P network not running or not initialized');
    }
    
    // Find recipient's public key
    const recipientInfo = this.connectedPeers.get(recipientId);
    if (!recipientInfo || !recipientInfo.publicKey) {
      throw new Error(`Cannot send message: recipient ${recipientId} not found or public key unknown`);
    }
    
    try {
      // Encrypt the message with the recipient's public key
      const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
      const encryptedContent = sodium.crypto_box_easy(
        content,
        nonce,
        recipientInfo.publicKey,
        this.keyPair.privateKey
      );
      
      // Create a message ID
      const messageIdBase = new Uint8Array(32);
      sodium.randombytes_buf(messageIdBase);
      const messageId = uint8ArrayToString(messageIdBase.slice(0, 16), 'base64');
      
      // Create the message
      const message: P2PMessage = {
        id: messageId,
        sender: this.nodeId,
        recipient: recipientId,
        encryptedContent: encryptedContent,
        timestamp: Date.now(),
        ttl: options.ttl || 0
      };
      
      // Add onion routing if enabled
      const useOnionRouting = options.useOnionRouting !== undefined 
        ? options.useOnionRouting 
        : this.options.useOnionRouting;
        
      if (useOnionRouting) {
        // In a real implementation, we would:
        // 1. Find a path of nodes to route through
        // 2. Encrypt the message in layers (like an onion)
        // 3. Send it through the path
        
        // For now, we just set up a simple routing structure
        message.routingInfo = {
          path: [recipientId], // The direct path for now
          hops: 0
        };
      }
      
      // Send the message
      await this.sendMessageToPeer(recipientId, message);
      
      logger.info(`Sent message to ${recipientId} with ID: ${messageId}`);
      return messageId;
    } catch (error) {
      logger.error(`Failed to send message to ${recipientId}`, error);
      throw error;
    }
  }
  
  /**
   * Send a message to a specific peer
   */
  private async sendMessageToPeer(peerId: string, message: P2PMessage): Promise<void> {
    if (!this.libp2p) {
      throw new Error('P2P network not running');
    }
    
    // Convert message to string
    const messageStr = JSON.stringify(message);
    const messageData = uint8ArrayFromString(messageStr);
    
    // Publish to the direct message topic
    await this.libp2p.pubsub.publish(this.DIRECT_MSG_TOPIC, messageData);
  }
  
  /**
   * Advertise our presence and public key to the network
   */
  public async advertiseToNetwork(): Promise<void> {
    if (!this.isRunning || !this.libp2p || !this.keyPair) {
      throw new Error('P2P network not running or not initialized');
    }
    
    try {
      // Create a discovery message
      const discoveryMessage = {
        type: 'discovery',
        nodeId: this.nodeId,
        publicKey: uint8ArrayToString(this.keyPair.publicKey, 'base64'),
        timestamp: Date.now()
      };
      
      // Convert to bytes
      const messageStr = JSON.stringify(discoveryMessage);
      const messageData = uint8ArrayFromString(messageStr);
      
      // Publish to discovery topic
      await this.libp2p.pubsub.publish(this.DISCOVERY_TOPIC, messageData);
      
      logger.info('Advertised node to the network');
    } catch (error) {
      logger.error('Failed to advertise to network', error);
      throw error;
    }
  }
  
  /**
   * Get all connected peers
   */
  public getConnectedPeers(): Array<{ peerId: string, publicKey?: Uint8Array, lastSeen: number }> {
    return Array.from(this.connectedPeers.values());
  }
  
  /**
   * Get node information
   */
  public getNodeInfo(): { nodeId: string; isRunning: boolean; publicKey: string } {
    return {
      nodeId: this.nodeId,
      isRunning: this.isRunning,
      publicKey: this.keyPair 
        ? uint8ArrayToString(this.keyPair.publicKey, 'base64')
        : ''
    };
  }
  
  /**
   * Check if connected to a specific peer
   */
  public isConnectedToPeer(peerId: string): boolean {
    return this.connectedPeers.has(peerId);
  }
}

/**
 * Create a new P2P Network instance
 */
export async function createP2PNetwork(options: Partial<P2PNetworkOptions> = {}): Promise<P2PNetwork> {
  const network = new P2PNetwork(options);
  await network.initialize();
  return network;
} 