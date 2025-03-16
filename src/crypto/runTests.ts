/**
 * Command-line test runner for HyperSecure cryptographic components
 */

import { testDoubleRatchet } from './doubleRatchet.test';
import { testX3DH } from './x3dh.test';
import { logger } from '../utils/logger';

/**
 * Run all crypto tests
 */
async function runAllTests() {
  try {
    logger.info('Starting crypto tests...');
    
    // Run Double Ratchet tests
    logger.info('Running Double Ratchet tests...');
    await testDoubleRatchet();
    logger.info('Double Ratchet tests completed successfully!');
    
    // Run X3DH tests
    logger.info('Running X3DH tests...');
    await testX3DH();
    logger.info('X3DH tests completed successfully!');
    
    logger.info('All crypto tests completed successfully!');
  } catch (error) {
    logger.error('Crypto tests failed:', error);
    process.exit(1);
  }
}

// Run all tests when this file is executed directly
if (require.main === module) {
  runAllTests();
}

export { runAllTests }; 