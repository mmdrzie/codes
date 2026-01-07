/**
 * Example usage of the authentication system
 * This demonstrates how to implement both Firebase and Web3 authentication flows
 */

import { AuthService } from './src/services/auth-service';
import { SiweService } from './src/services/web3/siwe-service';
import { SecurityMonitor } from './src/lib/security-monitoring';

// Example: Firebase Authentication Flow
async function exampleFirebaseAuth() {
  try {
    console.log('=== Firebase Authentication Example ===');
    
    // Sign up a new user
    const signupResult = await AuthService.signUpWithEmailAndPassword(
      'user@example.com',
      'password123',
      'John Doe'
    );
    console.log('Signup successful:', signupResult.user.id);
    
    // Sign in with the user
    const signinResult = await AuthService.signInWithEmailAndPassword(
      'user@example.com',
      'password123'
    );
    console.log('Signin successful:', signinResult.user.id);
    
    // Get current user session
    const currentUser = await AuthService.getCurrentUser();
    console.log('Current user:', currentUser?.id);
    
  } catch (error) {
    console.error('Firebase auth error:', error);
  }
}

// Example: Web3 Authentication Flow
async function exampleWeb3Auth() {
  try {
    console.log('\n=== Web3 Authentication Example ===');
    
    // In a real scenario, you would get the address from the connected wallet
    const address = '0x742d35Cc6634C0532925a3b844Bc454e4438f44e'; // Example address
    const domain = 'example.com';
    const chainId = 1; // Mainnet
    
    // Generate SIWE message and nonce
    const { message, nonce } = SiweService.generateSiweMessage(address, domain, chainId);
    console.log('Generated SIWE message:', message);
    console.log('Nonce:', nonce);
    
    // Note: In a real implementation, the user would sign the message with their wallet
    // and return the signature. For this example, we'll skip the actual signing step.
    
    // Once the user provides the signature, you would verify it:
    // const result = await AuthService.signInWithWeb3(
    //   { message, signature: userProvidedSignature },
    //   domain
    // );
    
  } catch (error) {
    console.error('Web3 auth error:', error);
  }
}

// Example: Security Monitoring
async function exampleSecurityMonitoring() {
  try {
    console.log('\n=== Security Monitoring Example ===');
    
    // Log a successful authentication event
    SecurityMonitor.logAuthSuccess('user-123', {
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0...',
    });
    
    // Log an authentication failure
    SecurityMonitor.logAuthFailure('user-123', {
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0...',
    }, 'Invalid credentials');
    
    // Log a suspicious activity
    SecurityMonitor.logSuspiciousActivity({
      ipAddress: '192.168.1.100',
      userAgent: 'Unknown bot',
    }, 'Multiple failed login attempts');
    
  } catch (error) {
    console.error('Security monitoring error:', error);
  }
}

// Run examples
async function runExamples() {
  await exampleFirebaseAuth();
  await exampleWeb3Auth();
  await exampleSecurityMonitoring();
  
  console.log('\n=== Examples completed ===');
}

// Export for use in other modules
export {
  exampleFirebaseAuth,
  exampleWeb3Auth,
  exampleSecurityMonitoring,
  runExamples
};

// Run if this file is executed directly
if (require.main === module) {
  runExamples().catch(console.error);
}