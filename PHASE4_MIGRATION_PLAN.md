# PHASE 4 - LEGACY ERADICATION & ENTERPRISE MIGRATION

## CRITICAL FINDINGS

### Enterprise Components Status
| Component | Status | Integration | Usage Count |
|-----------|--------|-------------|-------------|
| enterprise-redis-client.ts | ✅ Exists | ❌ Partial | 3 (internal only) |
| enterprise-session-manager.ts | ✅ Exists | ❌ 0% | 0 |
| enterprise-rate-limiter.ts | ✅ Exists | ❌ 0% | 0 |
| enterprise-siwe-nonce-store.ts | ✅ Exists | ❌ 0% | 0 |

### Legacy Insecure Code Still Active
| File | Issue | Risk Level |
|------|-------|------------|
| src/lib/nonceStore.ts | Memory fallback when Redis fails | CRITICAL |
| src/lib/wallet.ts | Non-atomic nonce operations | CRITICAL |
| src/services/web3/siwe-service.ts | In-memory Map for nonces | CRITICAL |
| src/lib/rateLimit.ts | Fallback to memory, not fail-closed | HIGH |
| src/lib/db.ts | MockDatabase with in-memory storage | CRITICAL |

## MIGRATION STEPS

### Step 1: Replace Nonce Generation Route
File: src/app/api/auth/wallet/nonce/route.ts
- Replace: generateAndStoreNonce from @/lib/nonceStore
- With: EnterpriseSiweNonceStore
- Replace: checkRateLimit from @/lib/rateLimit  
- With: EnterpriseRateLimiter

### Step 2: Replace Wallet Auth Route
File: src/app/api/auth/wallet/route.ts
- Replace: verifyAndConsumeNonce from @/lib/wallet
- With: EnterpriseSiweNonceStore.verifyAndConsumeNonce

### Step 3: Replace Web3 Nonce Route
File: src/app/api/auth/web3/nonce/route.ts
- Replace: SiweService.generateSiweMessage (uses Map)
- With: EnterpriseSiweNonceStore

### Step 4: Remove Legacy Files
- src/lib/nonceStore.ts → DELETE or mark as deprecated
- src/lib/wallet.ts nonce functions → DEPRECATE
- src/services/web3/siwe-service.ts nonceStore → REMOVE

## EXECUTION STATUS
