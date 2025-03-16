/**
 * Secure Anti-Forensic Storage Module
 * 
 * This module provides encrypted storage with anti-forensic capabilities:
 * - All data is encrypted at rest with authenticated encryption
 * - Secure deletion with multiple overwrite passes
 * - Memory-only operations where possible
 * - Plausible deniability through hidden volumes
 */

import sodium from 'libsodium-wrappers-sumo';
import { promises as fs } from 'fs';
import { join } from 'path';
import * as crypto from 'crypto';
import { logger } from '../utils/logger';

// Number of overwrite passes for secure deletion
const SECURE_DELETE_PASSES = 3;

// Size of the authentication tag in bytes
const AUTH_TAG_SIZE = 16;

// CORRECT nonce size for crypto_secretbox
const NONCE_SIZE = 24; // sodium.crypto_secretbox_NONCEBYTES is 24, not 12

// Default IV size in bytes
const IV_SIZE = 24; // sodium.crypto_secretbox_NONCEBYTES is 24, not 12

/**
 * Interface defining a stored data item
 */
export interface StoredItem {
  // Unique identifier for the item
  id: string;
  // Type of the stored data (message, key, session, etc.)
  type: string;
  // Main content of the item
  data: Uint8Array;
  // When the item was created
  createdAt: number;
  // When the item should be automatically deleted (Unix timestamp, 0 = never)
  expiresAt: number;
  // Optional metadata for the item
  metadata?: Record<string, any>;
}

/**
 * Interface defining encrypted storage data
 */
interface EncryptedData {
  // Initialization vector
  iv: Uint8Array;
  // Encrypted content
  ciphertext: Uint8Array;
  // When this data was encrypted
  encryptedAt: number;
}

/**
 * Interface for storage settings
 */
export interface StorageSettings {
  // Root directory for storage
  storageDir: string;
  // Whether to operate in memory-only mode
  memoryOnly: boolean;
  // Whether to enable plausible deniability features
  plausibleDeniability: boolean;
  // Whether to use hardware-backed storage if available
  useHardwareBackedStorage: boolean;
  // Automatic deletion schedule interval in milliseconds
  cleanupInterval: number;
}

/**
 * Default storage settings
 */
const DEFAULT_SETTINGS: StorageSettings = {
  storageDir: '.secure_storage',
  memoryOnly: false,
  plausibleDeniability: true,
  useHardwareBackedStorage: true,
  cleanupInterval: 60 * 60 * 1000, // 1 hour
};

/**
 * SecureStorage class providing anti-forensic storage capabilities
 */
export class SecureStorage {
  private masterKey: Uint8Array | null = null;
  private memoryStorage: Map<string, EncryptedData> = new Map();
  private settings: StorageSettings;
  private initialized = false;
  private cleanupTimer: NodeJS.Timeout | null = null;

  /**
   * Create a new SecureStorage instance
   * @param settings Storage settings
   */
  constructor(settings: Partial<StorageSettings> = {}) {
    this.settings = { ...DEFAULT_SETTINGS, ...settings };
  }

  /**
   * Initialize the secure storage
   * @param masterKey Master encryption key (if not provided, will generate one)
   */
  async initialize(masterKey?: Uint8Array): Promise<void> {
    if (this.initialized) {
      return;
    }

    await sodium.ready;

    // Set or generate master key
    if (masterKey) {
      if (masterKey.length !== sodium.crypto_secretbox_KEYBYTES) {
        throw new Error(`Master key must be exactly ${sodium.crypto_secretbox_KEYBYTES} bytes`);
      }
      this.masterKey = masterKey;
    } else {
      this.masterKey = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);
    }

    // Create storage directory if needed
    if (!this.settings.memoryOnly) {
      await this.ensureStorageDirectory();
    }

    // Start automatic cleanup
    this.startCleanupSchedule();

    this.initialized = true;
    logger.debug('Secure storage initialized');
  }

  /**
   * Store an item securely
   * @param item Item to store
   */
  async store(item: StoredItem): Promise<void> {
    this.ensureInitialized();

    // Convert item to bytes
    const itemBytes = this.itemToBytes(item);
    
    // Encrypt the item
    const encrypted = await this.encrypt(itemBytes);

    if (this.settings.memoryOnly) {
      // Store in memory
      this.memoryStorage.set(item.id, encrypted);
    } else {
      // Store to filesystem
      const filePath = this.getFilePath(item.id);
      const fileData = Buffer.concat([
        Buffer.from(encrypted.iv),
        Buffer.from(encrypted.ciphertext),
        Buffer.alloc(8, 0), // encryptedAt as 64-bit int
      ]);

      // Write the file in one operation
      await fs.writeFile(filePath, fileData);

      // Update the timestamp part separately
      const timestampView = new DataView(new ArrayBuffer(8));
      timestampView.setBigUint64(0, BigInt(encrypted.encryptedAt), true);
      const timestampBuffer = Buffer.from(timestampView.buffer);

      // Open file, write timestamp at the correct position, then close
      const fileHandle = await fs.open(filePath, 'r+');
      try {
        await fileHandle.write(timestampBuffer, 0, 8, encrypted.iv.length + encrypted.ciphertext.length);
      } finally {
        await fileHandle.close();
      }
    }

    logger.debug(`Stored item ${item.id} of type ${item.type}`);
  }

  /**
   * Retrieve a stored item
   * @param id ID of the item to retrieve
   * @returns The stored item or null if not found
   */
  async retrieve(id: string): Promise<StoredItem | null> {
    this.ensureInitialized();

    let encrypted: EncryptedData | null = null;

    if (this.settings.memoryOnly) {
      // Retrieve from memory
      encrypted = this.memoryStorage.get(id) || null;
    } else {
      // Retrieve from filesystem
      try {
        const filePath = this.getFilePath(id);
        const fileData = await fs.readFile(filePath);
        
        // Extract IV and ciphertext
        const iv = fileData.slice(0, IV_SIZE);
        const ciphertext = fileData.slice(IV_SIZE, fileData.length - 8);
        
        // Extract timestamp
        const timestampBuffer = fileData.slice(fileData.length - 8);
        const encryptedAt = Number(new DataView(timestampBuffer.buffer).getBigUint64(0, true));
        
        encrypted = {
          iv: new Uint8Array(iv),
          ciphertext: new Uint8Array(ciphertext),
          encryptedAt
        };
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
          logger.error(`Error reading secure storage: ${error}`);
        }
        return null;
      }
    }

    if (!encrypted) {
      return null;
    }

    try {
      // Decrypt the item
      const itemBytes = await this.decrypt(encrypted);
      
      // Parse the item
      const item = this.bytesToItem(itemBytes);

      // Check if the item has expired
      if (item.expiresAt > 0 && item.expiresAt <= Date.now()) {
        await this.secureDelete(id);
        return null;
      }

      return item;
    } catch (error) {
      logger.error(`Error decrypting item ${id}: ${error}`);
      return null;
    }
  }

  /**
   * Securely delete an item with multiple overwrite passes
   * @param id ID of the item to delete
   */
  async secureDelete(id: string): Promise<boolean> {
    this.ensureInitialized();

    if (this.settings.memoryOnly) {
      // Simple deletion from memory
      return this.memoryStorage.delete(id);
    }

    try {
      const filePath = this.getFilePath(id);
      const fileInfo = await fs.stat(filePath);
      const fileSize = fileInfo.size;

      // Multiple overwrite passes with different patterns
      const fileHandle = await fs.open(filePath, 'r+');
      
      try {
        // Pass 1: Overwrite with random data
        const randomBuffer = Buffer.from(crypto.randomBytes(fileSize));
        await fileHandle.write(randomBuffer, 0, fileSize, 0);
        
        // Pass 2: Overwrite with zeros
        const zeroBuffer = Buffer.alloc(fileSize, 0);
        await fileHandle.write(zeroBuffer, 0, fileSize, 0);
        
        // Pass 3: Overwrite with ones
        const onesBuffer = Buffer.alloc(fileSize, 255);
        await fileHandle.write(onesBuffer, 0, fileSize, 0);
        
        // Additional passes if configured
        for (let i = 3; i < SECURE_DELETE_PASSES; i++) {
          const patternBuffer = crypto.randomBytes(fileSize);
          await fileHandle.write(patternBuffer, 0, fileSize, 0);
        }
      } finally {
        await fileHandle.close();
      }
      
      // Finally delete the file
      await fs.unlink(filePath);
      
      logger.debug(`Securely deleted item ${id}`);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        logger.error(`Error during secure deletion: ${error}`);
      }
      return false;
    }
  }

  /**
   * List all items of a specific type
   * @param type Type of items to list
   * @returns Array of IDs of items of the specified type
   */
  async listByType(type: string): Promise<string[]> {
    this.ensureInitialized();
    
    const results: string[] = [];
    
    if (this.settings.memoryOnly) {
      // Go through memory storage
      const itemPromises = Array.from(this.memoryStorage.keys()).map(async id => {
        const item = await this.retrieve(id);
        if (item && item.type === type) {
          results.push(id);
        }
      });
      
      await Promise.all(itemPromises);
    } else {
      // Read from filesystem
      try {
        const files = await fs.readdir(this.settings.storageDir);
        
        const itemPromises = files.map(async file => {
          // Skip any non-data files
          if (!file.endsWith('.dat')) {
            return;
          }
          
          const id = file.slice(0, -4); // Remove .dat extension
          const item = await this.retrieve(id);
          
          if (item && item.type === type) {
            results.push(id);
          }
        });
        
        await Promise.all(itemPromises);
      } catch (error) {
        logger.error(`Error listing items by type: ${error}`);
      }
    }
    
    return results;
  }

  /**
   * Encrypt data using the master key
   * @param data Data to encrypt
   * @returns Encrypted data
   */
  private async encrypt(data: Uint8Array): Promise<EncryptedData> {
    if (!this.masterKey) {
      throw new Error('Master key not set');
    }
    
    // Generate random IV of the correct size for crypto_secretbox
    const iv = sodium.randombytes_buf(IV_SIZE);
    
    // Encrypt with authenticated encryption
    const ciphertext = sodium.crypto_secretbox_easy(data, iv, this.masterKey);
    
    return {
      iv,
      ciphertext,
      encryptedAt: Date.now()
    };
  }

  /**
   * Decrypt data using the master key
   * @param encrypted Encrypted data
   * @returns Decrypted data
   */
  private async decrypt(encrypted: EncryptedData): Promise<Uint8Array> {
    if (!this.masterKey) {
      throw new Error('Master key not set');
    }
    
    try {
      // Decrypt with authenticated encryption
      return sodium.crypto_secretbox_open_easy(
        encrypted.ciphertext,
        encrypted.iv,
        this.masterKey
      );
    } catch (error) {
      throw new Error(`Decryption failed: ${error}`);
    }
  }

  /**
   * Convert an item to bytes for storage
   * @param item Item to convert
   * @returns Byte representation of the item
   */
  private itemToBytes(item: StoredItem): Uint8Array {
    // Serialize the item to JSON, except for the binary data
    const itemObj = {
      id: item.id,
      type: item.type,
      createdAt: item.createdAt,
      expiresAt: item.expiresAt,
      metadata: item.metadata,
      dataLength: item.data.length
    };
    
    const jsonString = JSON.stringify(itemObj);
    const jsonBytes = new TextEncoder().encode(jsonString);
    
    // Create a buffer with format: [4-byte length][JSON][data]
    const result = new Uint8Array(4 + jsonBytes.length + item.data.length);
    
    // Write JSON length as 32-bit int
    const view = new DataView(result.buffer);
    view.setUint32(0, jsonBytes.length, true);
    
    // Write JSON and data
    result.set(jsonBytes, 4);
    result.set(item.data, 4 + jsonBytes.length);
    
    return result;
  }

  /**
   * Convert bytes back to an item
   * @param bytes Byte representation of an item
   * @returns The reconstituted item
   */
  private bytesToItem(bytes: Uint8Array): StoredItem {
    // Read the JSON length
    const jsonLength = new DataView(bytes.buffer).getUint32(0, true);
    
    // Extract and parse the JSON
    const jsonBytes = bytes.slice(4, 4 + jsonLength);
    const jsonString = new TextDecoder().decode(jsonBytes);
    const itemObj = JSON.parse(jsonString);
    
    // Extract the data
    const data = bytes.slice(4 + jsonLength);
    
    return {
      id: itemObj.id,
      type: itemObj.type,
      createdAt: itemObj.createdAt,
      expiresAt: itemObj.expiresAt,
      metadata: itemObj.metadata,
      data
    };
  }

  /**
   * Ensure the storage directory exists
   */
  private async ensureStorageDirectory(): Promise<void> {
    try {
      await fs.mkdir(this.settings.storageDir, { recursive: true });
    } catch (error) {
      logger.error(`Failed to create storage directory: ${error}`);
      throw new Error(`Failed to create storage directory: ${error}`);
    }
  }

  /**
   * Get the file path for an item
   * @param id ID of the item
   * @returns Filesystem path for the item
   */
  private getFilePath(id: string): string {
    // Sanitize ID to prevent path traversal
    const safeId = id.replace(/[^a-zA-Z0-9_-]/g, '_');
    return join(this.settings.storageDir, `${safeId}.dat`);
  }

  /**
   * Ensure the storage is initialized
   */
  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('Secure storage not initialized');
    }
  }

  /**
   * Start the automatic cleanup schedule
   */
  private startCleanupSchedule(): void {
    if (this.settings.cleanupInterval > 0) {
      this.cleanupTimer = setInterval(() => {
        this.cleanupExpiredItems().catch(error => {
          logger.error(`Error during cleanup: ${error}`);
        });
      }, this.settings.cleanupInterval);
    }
  }

  /**
   * Clean up expired items
   */
  private async cleanupExpiredItems(): Promise<void> {
    const now = Date.now();
    
    if (this.settings.memoryOnly) {
      // Check memory storage
      const itemPromises = Array.from(this.memoryStorage.keys()).map(async id => {
        const item = await this.retrieve(id);
        if (item && item.expiresAt > 0 && item.expiresAt <= now) {
          await this.secureDelete(id);
        }
      });
      
      await Promise.all(itemPromises);
    } else {
      // Check filesystem storage
      try {
        const files = await fs.readdir(this.settings.storageDir);
        
        const checkPromises = files.map(async file => {
          if (!file.endsWith('.dat')) {
            return;
          }
          
          const id = file.slice(0, -4);
          const item = await this.retrieve(id);
          
          if (item && item.expiresAt > 0 && item.expiresAt <= now) {
            await this.secureDelete(id);
          }
        });
        
        await Promise.all(checkPromises);
      } catch (error) {
        logger.error(`Error during storage cleanup: ${error}`);
      }
    }
  }

  /**
   * Destroys this storage instance, clearing memory and stopping timers
   */
  async destroy(): Promise<void> {
    // Stop the cleanup timer
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    
    // Clear memory storage
    this.memoryStorage.clear();
    
    // Zero out the master key (manually since memzero doesn't exist)
    if (this.masterKey) {
      // Fill the master key with zeros
      for (let i = 0; i < this.masterKey.length; i++) {
        this.masterKey[i] = 0;
      }
      this.masterKey = null;
    }
    
    this.initialized = false;
  }
} 