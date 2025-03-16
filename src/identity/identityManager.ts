import sodium from 'libsodium-wrappers-sumo';
import { SecureStorage } from '../storage/secureStorage';
import { logger } from '../utils/logger';
import * as crypto from 'crypto';

export interface Identity {
  userId: string;
  displayName: string;
  publicKey: Uint8Array;
  privateKey?: Uint8Array; // Only present for the local user
  fingerprint: string;
  createdAt: number;
  deviceId: string;
  trusted: boolean;
}

export interface UserIdentity extends Identity {
  privateKey: Uint8Array;
  recoveryPhrase?: string;
}

export interface IdentityManagerOptions {
  storageKey: string;
  storagePassword: string;
  secureStorage: SecureStorage;
}

/**
 * IdentityManager handles creating, storing, and verifying user identities
 * in a completely decentralized manner with no central servers.
 */
export class IdentityManager {
  private readonly secureStorage: SecureStorage;
  private readonly storageKey: string;
  private readonly storagePassword: string;
  private localIdentity: UserIdentity | null = null;
  private knownIdentities: Map<string, Identity> = new Map();
  private initialized = false;

  constructor(options: IdentityManagerOptions) {
    this.secureStorage = options.secureStorage;
    this.storageKey = options.storageKey;
    this.storagePassword = options.storagePassword;
  }

  /**
   * Initialize the identity manager, loading existing identities from storage
   */
  public async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      // Wait for sodium to be ready
      await sodium.ready;
      
      // Load identities from secure storage
      const storedData = await this.secureStorage.get(this.storageKey, this.storagePassword);
      
      if (storedData) {
        const data = JSON.parse(storedData);
        
        // Load local identity if it exists
        if (data.localIdentity) {
          this.localIdentity = {
            ...data.localIdentity,
            publicKey: new Uint8Array(Object.values(data.localIdentity.publicKey)),
            privateKey: new Uint8Array(Object.values(data.localIdentity.privateKey))
          };
        }
        
        // Load known identities
        if (data.knownIdentities && Array.isArray(data.knownIdentities)) {
          for (const identity of data.knownIdentities) {
            this.knownIdentities.set(identity.userId, {
              ...identity,
              publicKey: new Uint8Array(Object.values(identity.publicKey))
            });
          }
        }
      }
      
      this.initialized = true;
      logger.info('Identity manager initialized');
    } catch (error) {
      logger.error('Failed to initialize identity manager', error);
      throw new Error('Failed to initialize identity manager');
    }
  }

  /**
   * Create a new local identity with the given display name
   */
  public async createIdentity(displayName: string): Promise<UserIdentity> {
    if (!this.initialized) {
      await this.initialize();
    }

    try {
      // Generate key pair using Node.js crypto
      const keyPair = crypto.generateKeyPairSync('ed25519');
      const publicKey = keyPair.publicKey.export({ type: 'spki', format: 'der' });
      const privateKey = keyPair.privateKey.export({ type: 'pkcs8', format: 'der' });
      
      // Convert to Uint8Array
      const publicKeyBytes = new Uint8Array(publicKey);
      const privateKeyBytes = new Uint8Array(privateKey);
      
      // Generate a unique user ID (using the public key fingerprint)
      const fingerprint = this.generateFingerprint(publicKeyBytes);
      const userId = fingerprint.substring(0, 16);
      
      // Generate a device ID
      const deviceId = crypto.randomBytes(8);
      const deviceIdHex = deviceId.toString('hex');
      
      // Create the identity
      const identity: UserIdentity = {
        userId,
        displayName,
        publicKey: publicKeyBytes,
        privateKey: privateKeyBytes,
        fingerprint,
        createdAt: Date.now(),
        deviceId: deviceIdHex,
        trusted: true,
        recoveryPhrase: this.generateRecoveryPhrase()
      };
      
      // Store as local identity
      this.localIdentity = identity;
      await this.saveIdentities();
      
      logger.info('Created new identity', { userId, displayName });
      return identity;
    } catch (error) {
      logger.error('Failed to create identity', error);
      throw new Error('Failed to create identity');
    }
  }

  /**
   * Get the local user identity
   */
  public getLocalIdentity(): UserIdentity | null {
    return this.localIdentity;
  }

  /**
   * Add or update a known identity
   */
  public async addKnownIdentity(identity: Identity): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }

    // Validate the identity by checking that the fingerprint matches the public key
    const calculatedFingerprint = this.generateFingerprint(identity.publicKey);
    if (calculatedFingerprint !== identity.fingerprint) {
      throw new Error('Identity validation failed: fingerprint mismatch');
    }

    // Add to known identities
    this.knownIdentities.set(identity.userId, identity);
    await this.saveIdentities();
    
    logger.info('Added known identity', { userId: identity.userId, displayName: identity.displayName });
  }

  /**
   * Mark an identity as trusted after verification
   */
  public async trustIdentity(userId: string, trusted: boolean = true): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }

    const identity = this.knownIdentities.get(userId);
    if (!identity) {
      throw new Error(`Unknown identity: ${userId}`);
    }

    identity.trusted = trusted;
    this.knownIdentities.set(userId, identity);
    await this.saveIdentities();
    
    logger.info(`Identity ${trusted ? 'trusted' : 'untrusted'}`, { userId });
  }

  /**
   * Get a known identity by userId
   */
  public getIdentity(userId: string): Identity | null {
    return this.knownIdentities.get(userId) || null;
  }

  /**
   * Get all known identities
   */
  public getAllIdentities(): Identity[] {
    return Array.from(this.knownIdentities.values());
  }

  /**
   * Get trusted identities
   */
  public getTrustedIdentities(): Identity[] {
    return Array.from(this.knownIdentities.values()).filter(id => id.trusted);
  }

  /**
   * Verify that a signature was made by the specified identity
   */
  public verifySignature(userId: string, message: Uint8Array, signature: Uint8Array): boolean {
    const identity = this.knownIdentities.get(userId);
    if (!identity) {
      logger.warn('Cannot verify signature: unknown identity', { userId });
      return false;
    }

    try {
      // Create a public key object from the stored bytes
      const publicKey = crypto.createPublicKey({
        key: Buffer.from(identity.publicKey),
        format: 'der',
        type: 'spki'
      });
      
      // Verify the signature
      return crypto.verify(
        null, // algorithm auto-detected from key
        Buffer.from(message),
        publicKey,
        Buffer.from(signature)
      );
    } catch (error) {
      logger.error('Signature verification failed', error);
      return false;
    }
  }

  /**
   * Sign a message using the local identity
   */
  public signMessage(message: Uint8Array): Uint8Array {
    if (!this.localIdentity) {
      throw new Error('No local identity available');
    }

    try {
      // Create a private key object from the stored bytes
      const privateKey = crypto.createPrivateKey({
        key: Buffer.from(this.localIdentity.privateKey),
        format: 'der',
        type: 'pkcs8'
      });
      
      // Sign the message
      const signature = crypto.sign(
        null, // algorithm auto-detected from key
        Buffer.from(message),
        privateKey
      );
      
      return new Uint8Array(signature);
    } catch (error) {
      logger.error('Failed to sign message', error);
      throw new Error('Failed to sign message');
    }
  }

  /**
   * Export identity for sharing (public data only)
   */
  public exportIdentity(userId: string): string {
    const identity = userId === this.localIdentity?.userId
      ? this.localIdentity
      : this.knownIdentities.get(userId);

    if (!identity) {
      throw new Error(`Unknown identity: ${userId}`);
    }

    // Create export object with only public information
    const exportData = {
      userId: identity.userId,
      displayName: identity.displayName,
      publicKey: Array.from(identity.publicKey),
      fingerprint: identity.fingerprint,
      createdAt: identity.createdAt,
      deviceId: identity.deviceId
    };

    return JSON.stringify(exportData);
  }

  /**
   * Import an identity shared by another user
   */
  public async importIdentity(identityData: string): Promise<Identity> {
    try {
      const data = JSON.parse(identityData);
      
      // Validate required fields
      if (!data.userId || !data.publicKey || !data.fingerprint) {
        throw new Error('Invalid identity data');
      }
      
      // Convert publicKey back to Uint8Array
      const publicKey = new Uint8Array(data.publicKey);
      
      // Verify fingerprint
      const calculatedFingerprint = this.generateFingerprint(publicKey);
      if (calculatedFingerprint !== data.fingerprint) {
        throw new Error('Identity validation failed: fingerprint mismatch');
      }
      
      // Create identity object
      const identity: Identity = {
        userId: data.userId,
        displayName: data.displayName || 'Unknown',
        publicKey,
        fingerprint: data.fingerprint,
        createdAt: data.createdAt || Date.now(),
        deviceId: data.deviceId || 'unknown',
        trusted: false // Imported identities are untrusted by default
      };
      
      // Add to known identities
      await this.addKnownIdentity(identity);
      return identity;
      
    } catch (error) {
      logger.error('Failed to import identity', error);
      throw new Error('Failed to import identity');
    }
  }

  /**
   * Generate a secure and human-readable recovery phrase
   */
  private generateRecoveryPhrase(): string {
    // This is a simple implementation. In a production system,
    // you would use a BIP39 or similar library to generate a proper mnemonic
    const randomBytes = crypto.randomBytes(16);
    return randomBytes.toString('hex');
  }

  /**
   * Generate a fingerprint from a public key
   */
  private generateFingerprint(publicKey: Uint8Array): string {
    const hash = crypto.createHash('sha256').update(Buffer.from(publicKey)).digest();
    return hash.toString('hex');
  }

  /**
   * Save identities to secure storage
   */
  private async saveIdentities(): Promise<void> {
    try {
      const data = {
        localIdentity: this.localIdentity ? {
          ...this.localIdentity,
          publicKey: Array.from(this.localIdentity.publicKey),
          privateKey: Array.from(this.localIdentity.privateKey)
        } : null,
        knownIdentities: Array.from(this.knownIdentities.values()).map(identity => ({
          ...identity,
          publicKey: Array.from(identity.publicKey)
        }))
      };
      
      await this.secureStorage.set(this.storageKey, JSON.stringify(data), this.storagePassword);
      logger.debug('Saved identities to secure storage');
    } catch (error) {
      logger.error('Failed to save identities', error);
      throw new Error('Failed to save identities');
    }
  }
} 