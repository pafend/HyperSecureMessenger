import * as sodium from 'libsodium-wrappers';
import { IdentityManager } from './identityManager';
import { SecureStorage, StorageSettings } from '../storage/secureStorage';
import { logger } from '../utils/logger';

// Mock SecureStorage for testing
class MockSecureStorage extends SecureStorage {
  private storage: Map<string, string> = new Map();

  constructor() {
    super({
      memoryOnly: true,
      storageDir: '.mock_storage',
      plausibleDeniability: false,
      useHardwareBackedStorage: false,
      cleanupInterval: 0 // Disable cleanup
    });
  }

  // Override the password-based methods to use the mock storage
  override async get(key: string, _password: string): Promise<string | null> {
    return this.storage.get(key) || null;
  }

  override async set(key: string, value: string, _password: string): Promise<void> {
    this.storage.set(key, value);
    return Promise.resolve();
  }

  override async delete(key: string, _password: string): Promise<void> {
    this.storage.delete(key);
    return Promise.resolve();
  }

  override async exists(key: string): Promise<boolean> {
    return Promise.resolve(this.storage.has(key));
  }
}

/**
 * Run tests for the identity manager
 */
async function runIdentityManagerTests(): Promise<void> {
  logger.info('Starting identity manager tests');

  // Initialize sodium
  await sodium.ready;
  logger.info('Sodium initialized');

  // Create mock secure storage
  const secureStorage = new MockSecureStorage();
  await secureStorage.initialize();

  // Create identity manager
  const identityManager = new IdentityManager({
    storageKey: 'test-identities',
    storagePassword: 'test-password',
    secureStorage
  });

  try {
    // Test 1: Initialize identity manager
    logger.info('Test 1: Initialize identity manager');
    await identityManager.initialize();
    logger.info('✅ Identity manager initialized successfully');

    // Test 2: Create local identity
    logger.info('Test 2: Create local identity');
    const aliceIdentity = await identityManager.createIdentity('Alice');
    logger.info('✅ Created local identity', { 
      userId: aliceIdentity.userId,
      displayName: aliceIdentity.displayName
    });

    // Test 3: Retrieve local identity
    logger.info('Test 3: Retrieve local identity');
    const retrievedIdentity = identityManager.getLocalIdentity();
    
    if (!retrievedIdentity) {
      throw new Error('Failed to retrieve local identity');
    }
    
    if (retrievedIdentity.userId !== aliceIdentity.userId) {
      throw new Error(`Identity mismatch: ${retrievedIdentity.userId} !== ${aliceIdentity.userId}`);
    }
    
    logger.info('✅ Retrieved local identity successfully');

    // Test 4: Export identity
    logger.info('Test 4: Export identity');
    const exportedIdentity = identityManager.exportIdentity(aliceIdentity.userId);
    logger.info('✅ Exported identity', { data: exportedIdentity.substring(0, 50) + '...' });

    // Test 5: Create a second identity manager instance (Bob)
    logger.info('Test 5: Create second identity manager');
    const bobSecureStorage = new MockSecureStorage();
    await bobSecureStorage.initialize();
    
    const bobIdentityManager = new IdentityManager({
      storageKey: 'bob-identities',
      storagePassword: 'bob-password',
      secureStorage: bobSecureStorage
    });
    
    await bobIdentityManager.initialize();
    const bobIdentity = await bobIdentityManager.createIdentity('Bob');
    logger.info('✅ Created Bob identity', { 
      userId: bobIdentity.userId,
      displayName: bobIdentity.displayName
    });

    // Test 6: Import identity
    logger.info('Test 6: Import identity');
    const bobExportedIdentity = bobIdentityManager.exportIdentity(bobIdentity.userId);
    const importedBobIdentity = await identityManager.importIdentity(bobExportedIdentity);
    
    if (importedBobIdentity.userId !== bobIdentity.userId) {
      throw new Error(`Imported identity mismatch: ${importedBobIdentity.userId} !== ${bobIdentity.userId}`);
    }
    
    logger.info('✅ Imported Bob identity successfully');

    // Test 7: Trust identity
    logger.info('Test 7: Trust identity');
    await identityManager.trustIdentity(importedBobIdentity.userId);
    const trustedIdentities = identityManager.getTrustedIdentities();
    
    if (!trustedIdentities.some(id => id.userId === importedBobIdentity.userId)) {
      throw new Error('Failed to trust identity');
    }
    
    logger.info('✅ Trusted Bob identity successfully');

    // Test 8: Sign and verify message
    logger.info('Test 8: Sign and verify message');
    const message = new TextEncoder().encode('Hello, this is a test message!');
    
    // Alice signs a message
    const signature = identityManager.signMessage(message);
    logger.info('✅ Signed message');
    
    // Import Alice's identity to Bob's identity manager
    const aliceExportedIdentity = identityManager.exportIdentity(aliceIdentity.userId);
    const importedAliceIdentity = await bobIdentityManager.importIdentity(aliceExportedIdentity);
    
    // Bob verifies Alice's signature
    const isValid = bobIdentityManager.verifySignature(importedAliceIdentity.userId, message, signature);
    
    if (!isValid) {
      throw new Error('Signature verification failed');
    }
    
    logger.info('✅ Verified signature successfully');

    // Test 9: Untrust identity
    logger.info('Test 9: Untrust identity');
    await identityManager.trustIdentity(importedBobIdentity.userId, false);
    const trustedIdentitiesAfterUntrust = identityManager.getTrustedIdentities();
    
    if (trustedIdentitiesAfterUntrust.some(id => id.userId === importedBobIdentity.userId)) {
      throw new Error('Failed to untrust identity');
    }
    
    logger.info('✅ Untrusted Bob identity successfully');

    // Test 10: Get all identities
    logger.info('Test 10: Get all identities');
    const allIdentities = identityManager.getAllIdentities();
    
    if (allIdentities.length !== 1) { // Should have 1 identity (Bob)
      throw new Error(`Unexpected number of identities: ${allIdentities.length}`);
    }
    
    logger.info('✅ Retrieved all identities successfully', {
      count: allIdentities.length
    });

    logger.info('✅ All identity manager tests passed successfully! ✅');
  } catch (error) {
    logger.error('❌ Identity manager test failed', error);
    throw error;
  }
}

// Run the tests
runIdentityManagerTests()
  .then(() => {
    logger.info('Identity manager tests completed successfully');
    process.exit(0);
  })
  .catch((error) => {
    logger.error('Identity manager tests failed', error);
    process.exit(1);
  }); 