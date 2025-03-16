/**
 * Message Storage Module
 * 
 * This module provides secure storage for messages, built on top of
 * the anti-forensic SecureStorage module.
 */

import { SecureStorage, StoredItem } from './secureStorage';
import { logger } from '../utils/logger';
import { randomBytes } from 'crypto';

// Message item type identifier
const MESSAGE_TYPE = 'message';

// Conversation item type identifier
const CONVERSATION_TYPE = 'conversation';

/**
 * Interface for message data
 */
export interface Message {
  // Unique message identifier
  id: string;
  // Conversation this message belongs to
  conversationId: string;
  // Sender identifier
  senderId: string;
  // Timestamp when the message was sent
  timestamp: number;
  // Message content
  content: Uint8Array;
  // Whether this message has been read
  read: boolean;
  // Optional expiration time (Unix timestamp, 0 = never)
  expiresAt: number;
  // Optional metadata
  metadata?: {
    // Whether this is a system message
    isSystem?: boolean;
    // Whether the message has been edited
    edited?: boolean;
    // Whether delivery has been confirmed
    delivered?: boolean;
    // Additional properties as needed
    [key: string]: any;
  };
}

/**
 * Interface for conversation data
 */
export interface Conversation {
  // Unique conversation identifier
  id: string;
  // Name of the conversation (for group chats)
  name?: string;
  // Participants in the conversation
  participants: string[];
  // Timestamp when the conversation was created
  createdAt: number;
  // Timestamp when the conversation was last active
  lastActiveAt: number;
  // Optional metadata
  metadata?: {
    // Whether this is a group conversation
    isGroup?: boolean;
    // Additional properties as needed
    [key: string]: any;
  };
}

/**
 * Class for securely storing and retrieving messages
 */
export class MessageStorage {
  private storage: SecureStorage;
  private initialized = false;

  /**
   * Create a new MessageStorage instance
   * @param storageDir Directory for storing messages on disk
   * @param memoryOnly Whether to store messages in memory only
   */
  constructor(
    private storageDir: string = '.secure_messages',
    private memoryOnly: boolean = false
  ) {
    this.storage = new SecureStorage({
      storageDir: this.storageDir,
      memoryOnly: this.memoryOnly,
      // Auto-delete expired messages every 5 minutes
      cleanupInterval: 5 * 60 * 1000,
      // Enable maximum security features
      plausibleDeniability: true
    });
  }

  /**
   * Initialize the message storage
   * @param masterKey Master encryption key
   */
  async initialize(masterKey?: Uint8Array): Promise<void> {
    if (this.initialized) {
      return;
    }

    await this.storage.initialize(masterKey);
    this.initialized = true;
    logger.debug('Message storage initialized');
  }

  /**
   * Store a message
   * @param message Message to store
   */
  async storeMessage(message: Message): Promise<void> {
    this.ensureInitialized();

    const item: StoredItem = {
      id: message.id,
      type: MESSAGE_TYPE,
      data: this.messageToBytes(message),
      createdAt: Date.now(),
      expiresAt: message.expiresAt || 0,
      metadata: {
        conversationId: message.conversationId,
        senderId: message.senderId,
        timestamp: message.timestamp
      }
    };

    await this.storage.store(item);
    logger.debug(`Stored message ${message.id} in conversation ${message.conversationId}`);
  }

  /**
   * Retrieve a message by ID
   * @param id Message ID
   * @returns The message or null if not found
   */
  async retrieveMessage(id: string): Promise<Message | null> {
    this.ensureInitialized();

    const item = await this.storage.retrieve(id);
    if (!item || item.type !== MESSAGE_TYPE) {
      return null;
    }

    return this.bytesToMessage(item.data);
  }

  /**
   * Delete a message
   * @param id Message ID
   * @returns Whether the message was successfully deleted
   */
  async deleteMessage(id: string): Promise<boolean> {
    this.ensureInitialized();
    return this.storage.secureDelete(id);
  }

  /**
   * Store a conversation
   * @param conversation Conversation to store
   */
  async storeConversation(conversation: Conversation): Promise<void> {
    this.ensureInitialized();

    const item: StoredItem = {
      id: conversation.id,
      type: CONVERSATION_TYPE,
      data: this.conversationToBytes(conversation),
      createdAt: conversation.createdAt,
      expiresAt: 0, // Conversations don't expire
      metadata: {
        participants: conversation.participants,
        lastActiveAt: conversation.lastActiveAt
      }
    };

    await this.storage.store(item);
    logger.debug(`Stored conversation ${conversation.id}`);
  }

  /**
   * Retrieve a conversation by ID
   * @param id Conversation ID
   * @returns The conversation or null if not found
   */
  async retrieveConversation(id: string): Promise<Conversation | null> {
    this.ensureInitialized();

    const item = await this.storage.retrieve(id);
    if (!item || item.type !== CONVERSATION_TYPE) {
      return null;
    }

    return this.bytesToConversation(item.data);
  }

  /**
   * Delete a conversation and all its messages
   * @param conversationId Conversation ID
   * @returns Whether the conversation was successfully deleted
   */
  async deleteConversation(conversationId: string): Promise<boolean> {
    this.ensureInitialized();

    // First delete the conversation
    const conversationDeleted = await this.storage.secureDelete(conversationId);

    // Get all messages in this conversation
    const messageIds = await this.getMessagesForConversation(conversationId);

    // Delete all messages
    const messageDeletePromises = messageIds.map(id => this.storage.secureDelete(id));
    await Promise.all(messageDeletePromises);

    return conversationDeleted;
  }

  /**
   * Get all messages for a conversation
   * @param conversationId Conversation ID
   * @returns Array of message IDs
   */
  async getMessagesForConversation(conversationId: string): Promise<string[]> {
    this.ensureInitialized();

    // Get all message IDs
    const messageIds = await this.storage.listByType(MESSAGE_TYPE);
    const result: string[] = [];

    // Check each message to see if it belongs to the conversation
    for (const id of messageIds) {
      const item = await this.storage.retrieve(id);
      if (item && item.metadata && item.metadata['conversationId'] === conversationId) {
        result.push(id);
      }
    }

    return result;
  }

  /**
   * Get all conversations
   * @returns Array of conversation IDs
   */
  async getAllConversations(): Promise<string[]> {
    this.ensureInitialized();
    return this.storage.listByType(CONVERSATION_TYPE);
  }

  /**
   * Create a new message
   * @param conversationId Conversation ID
   * @param senderId Sender ID
   * @param content Message content
   * @param expiresIn Optional time in milliseconds after which the message will expire
   * @returns The created message
   */
  createMessage(
    conversationId: string,
    senderId: string,
    content: Uint8Array,
    expiresIn?: number
  ): Message {
    const now = Date.now();
    return {
      id: this.generateId('msg'),
      conversationId,
      senderId,
      timestamp: now,
      content,
      read: false,
      expiresAt: expiresIn ? now + expiresIn : 0
    };
  }

  /**
   * Create a new conversation
   * @param participants Participant IDs
   * @param name Optional conversation name
   * @param isGroup Whether this is a group conversation
   * @returns The created conversation
   */
  createConversation(
    participants: string[],
    name?: string,
    isGroup: boolean = false
  ): Conversation {
    const now = Date.now();
    return {
      id: this.generateId('conv'),
      participants,
      name,
      createdAt: now,
      lastActiveAt: now,
      metadata: { isGroup }
    };
  }

  /**
   * Destroy the message storage
   */
  async destroy(): Promise<void> {
    if (this.initialized) {
      await this.storage.destroy();
      this.initialized = false;
    }
  }

  /**
   * Convert a message to bytes for storage
   * @param message Message to convert
   * @returns Byte representation of the message
   */
  private messageToBytes(message: Message): Uint8Array {
    const json = JSON.stringify(message, (key, value) => {
      // Handle Uint8Array conversion
      if (value instanceof Uint8Array) {
        return {
          __type: 'Uint8Array',
          data: Array.from(value)
        };
      }
      return value;
    });
    return new TextEncoder().encode(json);
  }

  /**
   * Convert bytes back to a message
   * @param bytes Byte representation of a message
   * @returns The reconstituted message
   */
  private bytesToMessage(bytes: Uint8Array): Message {
    const json = new TextDecoder().decode(bytes);
    return JSON.parse(json, (key, value) => {
      // Handle Uint8Array conversion
      if (value && typeof value === 'object' && value.__type === 'Uint8Array') {
        return new Uint8Array(value.data);
      }
      return value;
    });
  }

  /**
   * Convert a conversation to bytes for storage
   * @param conversation Conversation to convert
   * @returns Byte representation of the conversation
   */
  private conversationToBytes(conversation: Conversation): Uint8Array {
    const json = JSON.stringify(conversation);
    return new TextEncoder().encode(json);
  }

  /**
   * Convert bytes back to a conversation
   * @param bytes Byte representation of a conversation
   * @returns The reconstituted conversation
   */
  private bytesToConversation(bytes: Uint8Array): Conversation {
    const json = new TextDecoder().decode(bytes);
    return JSON.parse(json);
  }

  /**
   * Generate a unique ID with a prefix
   * @param prefix Prefix for the ID
   * @returns A unique ID
   */
  private generateId(prefix: string): string {
    const random = randomBytes(16).toString('hex');
    return `${prefix}_${Date.now()}_${random}`;
  }

  /**
   * Ensure the storage is initialized
   */
  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('Message storage not initialized');
    }
  }
} 