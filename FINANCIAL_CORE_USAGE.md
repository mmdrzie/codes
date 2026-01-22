# Financial Core Usage Guide

This document explains how to use the Financial Core system that has been implemented with Tier-1 security measures.

## Architecture Overview

The Financial Core system consists of 5 main components:

1. **Immutable Ledger** - Cryptographically chained transaction records
2. **DPoP Session Security** - Sender-constrained token system
3. **Network Trust Model** - Secure header validation
4. **Secure Wallet Management** - HSM/MPC-ready custody layer
5. **Kill-Switch Controller** - Immediate fund freeze capabilities

## Getting Started

### Basic Usage

```typescript
import { getFinancialCore } from './src/lib/financial-core';

// Initialize with security controls
const financialCore = getFinancialCore({
  enableKillSwitch: true,
  requireDPoPTokens: true,
  enforceNetworkTrust: true,
  auditAllActions: true,
  maxConcurrentTransactions: 10
});

// Create wallets for users
const wallet1 = await financialCore.createWallet('user-123', 'USD');
const wallet2 = await financialCore.createWallet('user-456', 'USD');

// Process secure transactions
const transactionResult = await financialCore.processTransaction({
  fromWalletId: wallet1.id,
  toWalletId: wallet2.id,
  amount: 100,
  currency: 'USD',
  userId: 'user-123'
});

console.log('Transaction result:', transactionResult);
```

### With HTTP Request Integration

```typescript
// Example with network trust validation
const httpRequest = {
  socket: { remoteAddress: '127.0.0.1' },
  headers: { 'x-forwarded-for': '203.0.113.1' },
  url: '/api/transfer',
  method: 'POST'
};

const transactionResult = await financialCore.processTransaction(
  transactionRequest,
  httpRequest  // Optional, for network trust validation
);
```

### DPoP Token Validation

```typescript
// Validate DPoP tokens for enhanced security
const validationResult = await financialCore.validateDPoPToken(
  accessToken,
  dpopProof,
  httpRequest
);

if (validationResult.valid) {
  // Proceed with authorized operation
} else {
  // Reject request due to invalid DPoP proof
}
```

### Kill-Switch Operations

```typescript
// Activate emergency freeze (stops all operations)
await financialCore.activateKillSwitch('admin-user', 'security-incident');

// Check system state
if (financialCore.isSystemFrozen()) {
  console.log('System is frozen - no transactions allowed');
}

// Deactivate kill switch when safe
await financialCore.deactivateKillSwitch('admin-user', 'incident-resolved');
```

## Security Features

### 1. Network Trust Validation
- Validates client IP addresses only from trusted proxies
- Rejects spoofed forwarded headers from untrusted sources
- Falls back to direct socket address for untrusted connections

### 2. DPoP Token Security
- Sender-constrained tokens prevent replay attacks
- Public key binding ensures token ownership
- Short-lived tokens with mandatory refresh

### 3. Immutable Ledger
- Cryptographically chained entries ensure tamper evidence
- Every financial action recorded permanently
- Integrity verification available at any time

### 4. Concurrent Operation Safety
- Atomic transaction processing prevents race conditions
- Transaction queuing under high load
- Balance validation before processing

## Configuration Options

```typescript
const config = {
  enableKillSwitch: true,              // Enable emergency shutdown
  requireDPoPTokens: true,             // Require DPoP for all requests
  enforceNetworkTrust: true,           // Validate network headers
  auditAllActions: true,               // Log all operations
  maxConcurrentTransactions: 10        // Limit concurrent ops
};
```

## Important Security Notes

⚠️ **CRITICAL**: This implementation requires production infrastructure:
- Hardware Security Modules (HSM) for key management
- MPC (Multi-Party Computation) for signing operations
- Distributed storage for nonce management
- Production-grade monitoring and alerting

⚠️ **DO NOT** deploy this system without proper security infrastructure.

## Testing

Run the comprehensive test suite:

```bash
npx ts-node src/lib/financial-core/test-financial-core.ts
```

## Error Handling

The system follows a fail-closed approach:
- Any security dependency failure results in service denial
- Generic client error messages to prevent information leakage
- Detailed server-side logging for investigation

## Audit Trail

All operations are logged with:
- Cryptographic signatures for non-repudiation
- Correlation IDs for cross-service tracing
- Immutable records in the ledger system
- Real-time security event notifications