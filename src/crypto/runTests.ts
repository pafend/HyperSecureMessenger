/**
 * Command-line test runner for HyperSecure cryptographic components
 */

import { testDoubleRatchet } from './doubleRatchet.test';

/**
 * Run all cryptographic tests
 */
async function runAllTests(): Promise<void> {
  console.log('===================================');
  console.log('HyperSecure Cryptographic Test Suite');
  console.log('===================================');
  console.log();
  
  try {
    // Run Double Ratchet tests
    console.log('Running Double Ratchet tests...');
    await testDoubleRatchet();
    console.log('✅ Double Ratchet tests passed!\n');
    
    // Run other crypto tests when implemented
    // ...
    
    console.log('All cryptographic tests passed successfully!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Tests failed with error:', error);
    process.exit(1);
  }
}

// Run the tests when this file is executed directly
if (require.main === module) {
  runAllTests().catch(error => {
    console.error('Uncaught error:', error);
    process.exit(1);
  });
}

export { runAllTests }; 