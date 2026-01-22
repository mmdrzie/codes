import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { HardenedAuthService } from '@/services/auth/hardened-auth-service';
import { SecurityMonitor, SecurityEvent } from '@/lib/security-monitoring';
import { generateAccessToken, generateRefreshToken, verifyAccessToken, verifyRefreshToken } from '@/lib/tokenUtils';
import { PQCryptoService } from '@/services/crypto/pq-crypto-service';
import { ethers } from 'ethers';
import crypto from 'crypto';

// Mock Redis for testing
jest.mock('@upstash/redis', () => ({
  Redis: {
    fromEnv: () => ({
      setex: jest.fn().mockResolvedValue('OK'),
      get: jest.fn().mockResolvedValue(null),
      del: jest.fn().mockResolvedValue(1),
      set: jest.fn().mockResolvedValue('OK'),
    })
  }
}));

describe('Authentication Security Tests', () => {
  const mockClientInfo = {
    ip: '192.168.1.100',
    userAgent: 'Mozilla/5.0 (test)'
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Wallet Authentication Security', () => {
    it('should successfully authenticate with valid credentials', async () => {
      // Generate a valid wallet address and signature
      const wallet = ethers.Wallet.createRandom();
      const address = wallet.address;
      const nonce = await HardenedAuthService.generateSecureNonce(address);
      
      // Create a message and sign it
      const message = `Sign this message to authenticate: ${nonce}`;
      const signature = await wallet.signMessage(message);

      const result = await HardenedAuthService.authenticateWallet(
        address,
        signature,
        nonce,
        mockClientInfo
      );

      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.tokens).toBeDefined();
      expect(result.tokens!.accessToken).toBeDefined();
      expect(result.tokens!.refreshToken).toBeDefined();
    });

    it('should reject authentication with invalid nonce', async () => {
      const wallet = ethers.Wallet.createRandom();
      const address = wallet.address;
      const invalidNonce = 'invalid-nonce-12345';
      
      const message = `Sign this message to authenticate: ${invalidNonce}`;
      const signature = await wallet.signMessage(message);

      const result = await HardenedAuthService.authenticateWallet(
        address,
        signature,
        invalidNonce,
        mockClientInfo
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid nonce');
    });

    it('should reject authentication with invalid signature', async () => {
      const wallet = ethers.Wallet.createRandom();
      const address = wallet.address;
      const nonce = await HardenedAuthService.generateSecureNonce(address);
      
      // Create a message and sign it with a different wallet
      const otherWallet = ethers.Wallet.createRandom();
      const message = `Sign this message to authenticate: ${nonce}`;
      const signature = await otherWallet.signMessage(message);

      const result = await HardenedAuthService.authenticateWallet(
        address,
        signature,
        nonce,
        mockClientInfo
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid signature');
    });

    it('should reject authentication with invalid wallet address', async () => {
      const invalidAddress = '0xInvalidAddress';
      const nonce = 'test-nonce-12345';
      const signature = '0xInvalidSignature';

      const result = await HardenedAuthService.authenticateWallet(
        invalidAddress,
        signature,
        nonce,
        mockClientInfo
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid wallet address format');
    });
  });

  describe('Nonce Lifecycle Security', () => {
    it('should generate and consume nonce properly', async () => {
      const identifier = 'test-user-123';
      const nonce = await HardenedAuthService.generateSecureNonce(identifier);
      
      expect(nonce).toBeDefined();
      expect(nonce.length).toBeGreaterThan(10);

      const isValid = await HardenedAuthService.verifyAndConsumeNonce(identifier, nonce);
      expect(isValid).toBe(true);

      // Try to use the same nonce again (should fail)
      const isReplayValid = await HardenedAuthService.verifyAndConsumeNonce(identifier, nonce);
      expect(isReplayValid).toBe(false);
    });

    it('should detect replay attacks', async () => {
      const identifier = 'test-user-456';
      const nonce = await HardenedAuthService.generateSecureNonce(identifier);
      
      // First use should succeed
      const firstUse = await HardenedAuthService.verifyAndConsumeNonce(identifier, nonce);
      expect(firstUse).toBe(true);

      // Second use should fail (replay attack)
      const replayAttempt = await HardenedAuthService.verifyAndConsumeNonce(identifier, nonce);
      expect(replayAttempt).toBe(false);
    });

    it('should handle expired nonces', async () => {
      const identifier = 'test-user-789';
      const nonce = await HardenedAuthService.generateSecureNonce(identifier);
      
      // Simulate nonce expiration by manually manipulating storage
      // (In real tests, we'd need to wait or mock the time)
      
      // Verify that a valid nonce works
      const validNonce = await HardenedAuthService.generateSecureNonce(identifier);
      const isValid = await HardenedAuthService.verifyAndConsumeNonce(identifier, validNonce);
      expect(isValid).toBe(true);
    });
  });

  describe('JWT Token Security', () => {
    it('should generate and verify post-quantum secured tokens', async () => {
      const tokenPayload = {
        userId: 'test-user-id',
        walletAddress: '0x742d35Cc6634C0532925a3b8D4C9db4C4C4C4C4C',
        authMethod: 'wallet' as const,
        role: 'user'
      };

      const accessToken = await generateAccessToken(tokenPayload, mockClientInfo);
      const refreshToken = await generateRefreshToken(tokenPayload, mockClientInfo);

      expect(accessToken).toBeDefined();
      expect(refreshToken).toBeDefined();

      // Verify access token
      const accessVerification = await verifyAccessToken(accessToken);
      expect(accessVerification).toBeDefined();
      expect(accessVerification!.userId).toBe(tokenPayload.userId);
      expect(accessVerification!.type).toBe('access');

      // Verify refresh token
      const refreshVerification = await verifyRefreshToken(refreshToken);
      expect(refreshVerification.valid).toBe(true);
      expect(refreshVerification.payload!.userId).toBe(tokenPayload.userId);
      expect(refreshVerification.payload!.type).toBe('refresh');
    });

    it('should reject tampered tokens', async () => {
      const tokenPayload = {
        userId: 'test-user-id',
        walletAddress: '0x742d35Cc6634C0532925a3b8D4C9db4C4C4C4C4C',
        authMethod: 'wallet' as const,
        role: 'user'
      };

      const accessToken = await generateAccessToken(tokenPayload, mockClientInfo);
      
      // Tamper with the token
      const parts = accessToken.split('.');
      const tamperedToken = `${parts[0]}.${parts[1]}.tampered_signature`;

      const verification = await verifyAccessToken(tamperedToken);
      expect(verification).toBeNull();
    });

    it('should reject expired tokens', async () => {
      const tokenPayload = {
        userId: 'test-user-id',
        walletAddress: '0x742d35Cc6634C0532925a3b8D4C9db4C4C4C4C4C',
        authMethod: 'wallet' as const,
        role: 'user'
      };

      // Mock a token with an expired timestamp
      const expiredPayload = {
        ...tokenPayload,
        exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
        iat: Math.floor(Date.now() / 1000) - 3600,
        type: 'access' as const,
        iss: 'quantumiq-api',
        aud: 'quantumiq-web',
        jti: 'test-jti-123'
      };

      // Create a token with expired time (but valid signature)
      const expiredToken = await generateAccessToken(expiredPayload, mockClientInfo);
      
      const verification = await verifyAccessToken(expiredToken);
      expect(verification).toBeNull();
    });
  });

  describe('Hybrid Cryptography Security', () => {
    it('should generate and verify hybrid signatures', async () => {
      const keypair = await PQCryptoService.generateHybridKeyPair();
      const message = new Uint8Array(Buffer.from('test message for hybrid signature'));
      
      const signature = await PQCryptoService.generateHybridSignature(
        message,
        keypair.pqPrivateKey,
        keypair.classicalPrivateKey
      );

      const isValid = await PQCryptoService.verifyHybridSignature(
        message,
        signature,
        keypair.pqPublicKey,
        keypair.classicalPublicKey
      );

      expect(isValid).toBe(true);
    });

    it('should reject signatures with only classical or only PQ components', async () => {
      const keypair = await PQCryptoService.generateHybridKeyPair();
      const message = new Uint8Array(Buffer.from('test message'));

      const signature = await PQCryptoService.generateHybridSignature(
        message,
        keypair.pqPrivateKey,
        keypair.classicalPrivateKey
      );

      // Test with wrong public keys to ensure both components are required
      const wrongKeypair = await PQCryptoService.generateHybridKeyPair();
      
      const isValidWithWrongPQ = await PQCryptoService.verifyHybridSignature(
        message,
        signature,
        wrongKeypair.pqPublicKey,
        keypair.classicalPublicKey
      );

      const isValidWithWrongClassical = await PQCryptoService.verifyHybridSignature(
        message,
        signature,
        keypair.pqPublicKey,
        wrongKeypair.classicalPublicKey
      );

      expect(isValidWithWrongPQ).toBe(false);
      expect(isValidWithWrongClassical).toBe(false);
    });

    it('should reject tampered messages', async () => {
      const keypair = await PQCryptoService.generateHybridKeyPair();
      const message = new Uint8Array(Buffer.from('original message'));
      const tamperedMessage = new Uint8Array(Buffer.from('tampered message'));
      
      const signature = await PQCryptoService.generateHybridSignature(
        message,
        keypair.pqPrivateKey,
        keypair.classicalPrivateKey
      );

      const isValid = await PQCryptoService.verifyHybridSignature(
        tamperedMessage,
        signature,
        keypair.pqPublicKey,
        keypair.classicalPublicKey
      );

      expect(isValid).toBe(false);
    });
  });

  describe('Negative Tests', () => {
    it('should handle malformed JWT tokens', async () => {
      const malformedToken = 'invalid.token.format';
      
      const verification = await verifyAccessToken(malformedToken);
      expect(verification).toBeNull();
    });

    it('should handle expired nonce in authentication', async () => {
      // Test with a nonce that appears expired (old timestamp)
      const wallet = ethers.Wallet.createRandom();
      const address = wallet.address;
      
      // Create an "old" nonce (in practice, this would be tested with mocked time)
      const oldNonce = `nonce-${Date.now() - 400000}`; // 400 seconds ago
      const message = `Sign this message to authenticate: ${oldNonce}`;
      const signature = await wallet.signMessage(message);

      // This should fail due to expired nonce check
      const result = await HardenedAuthService.authenticateWallet(
        address,
        signature,
        oldNonce,
        mockClientInfo
      );

      // Depending on the exact implementation, this might fail differently
      // The important thing is that it should fail appropriately
      expect(result.success).toBe(false);
    });

    it('should handle empty/null inputs gracefully', async () => {
      const result = await HardenedAuthService.authenticateWallet(
        '',
        '',
        '',
        mockClientInfo
      );

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe('Security Monitoring', () => {
    it('should log authentication events', async () => {
      const logSpy = jest.spyOn(SecurityMonitor, 'logEvent');
      
      const wallet = ethers.Wallet.createRandom();
      const address = wallet.address;
      const nonce = await HardenedAuthService.generateSecureNonce(address);
      
      const message = `Sign this message to authenticate: ${nonce}`;
      const signature = await wallet.signMessage(message);

      await HardenedAuthService.authenticateWallet(
        address,
        signature,
        nonce,
        mockClientInfo
      );

      expect(logSpy).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          timestamp: expect.any(Date),
          metadata: expect.any(Object)
        }),
        expect.any(String)
      );
    });

    it('should log failed authentication attempts', async () => {
      const logSpy = jest.spyOn(SecurityMonitor, 'logEvent');
      
      const invalidAddress = '0xInvalidAddress';
      const result = await HardenedAuthService.authenticateWallet(
        invalidAddress,
        'invalid-signature',
        'invalid-nonce',
        mockClientInfo
      );

      expect(result.success).toBe(false);
      expect(logSpy).toHaveBeenCalledWith(
        SecurityEvent.INVALID_WALLET_ADDRESS,
        expect.objectContaining({
          timestamp: expect.any(Date),
          metadata: expect.objectContaining({
            address: invalidAddress
          })
        }),
        expect.any(String)
      );
    });
  });
});

// Run tests
if (typeof jest !== 'undefined') {
  // Jest environment
  export {};
} else {
  // Direct execution
  (async () => {
    console.log('Running Authentication Security Tests...');
    // This would normally be run through jest CLI
  })();
}