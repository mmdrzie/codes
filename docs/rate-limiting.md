# Rate Limiting Documentation

## Overview

This document describes the comprehensive rate limiting system implemented for the QuantumIQ Financial platform. The system provides granular protection against various types of abuse including API abuse, DDoS attacks, and account enumeration.

## Rate Limit Categories

### Per-IP Limits
- Limits requests from individual IP addresses
- Prevents basic DDoS and brute force attacks
- Configured with different thresholds based on request type

### Per-Account Limits
- Limits requests per authenticated user account
- Protects against targeted attacks on specific accounts
- Helps prevent resource exhaustion

### Global System Limits
- Overall limits for the entire system
- Prevents complete system overload
- Acts as a safety net when other limits fail

## Rate Limit Configurations

### Authentication Endpoints
- `/api/auth/login`: 5 attempts per 15 minutes per IP, 10 per hour
- `/api/auth/register`: 3 registrations per hour per IP
- `/api/auth/forgot-password`: 3 requests per 15 minutes per IP
- `/api/auth/reset-password`: 5 attempts per 15 minutes per IP

### Account Management
- `/api/account/settings`: 10 requests per minute per IP, 100 per hour per account
- `/api/account/change-email`: 2 changes per hour per account
- `/api/account/change-password`: 5 changes per hour per account

### Transaction Endpoints
- `/api/transactions/create`: 50 transactions per hour per account, 200 per day
- `/api/transactions/list`: 30 requests per minute per account

### General API Endpoints
- `/api/user/profile`: 60 requests per minute per IP
- `/api/dashboard/data`: 100 requests per minute per IP

## Algorithms

### Token Bucket
- Allows burst traffic up to a maximum capacity
- Refills tokens at a fixed rate
- Good for handling legitimate traffic spikes

### Sliding Window
- Tracks requests within a rolling time window
- Provides accurate rate enforcement
- Better for preventing sustained attacks

## Velocity Detection

The system implements advanced velocity detection that identifies:

- **Rapid Fire**: More than 10 requests per second from the same IP
- **Burst Patterns**: Sudden spikes in requests (>50 req/min)
- **Sustained High Volume**: Consistently high request volume (>100 req/hr)
- **Credential Stuffing**: Many failed login attempts with different credentials
- **Account Enumeration**: Sequential requests to user-specific endpoints

## Response Actions

Based on velocity assessment, the system applies:

1. **Allow**: Normal processing continues
2. **Warn**: Request is processed but logged for review
3. **Throttle**: Delay responses to slow down requester
4. **Block**: Reject requests with 429 status

## Whitelist Bypass

Trusted sources can be added to bypass rate limits:

- Office IP addresses
- Monitoring services
- Partner services
- Temporary testing bypasses

## Configuration

Rate limits can be adjusted via environment variables:

```
SESSION_KEY_ROTATION_DAYS=90
JWT_KEY_ROTATION_DAYS=90
API_KEY_ROTATION_DAYS=90
DB_KEY_ROTATION_DAYS=90
PBKDF2_ITERATIONS=100000
HASH_KEYLEN=64
HASH_DIGEST=sha512
KEY_HISTORY_MAX_VERSIONS=10
KEY_RETENTION_DAYS=365
TRUST_PROXY=true
```

## Monitoring and Alerting

- Rate limit violations are logged and monitored
- Alerts are generated for high violation rates
- Dashboard shows real-time rate limiting statistics
- Reports include top violators and patterns

## Performance

- Rate limiting adds <5ms overhead per request
- Distributed across Redis cluster for scalability
- Atomic operations prevent race conditions
- Cached results for frequently accessed limits

## Testing

- Unit tests for all rate limit algorithms
- Load testing to verify performance
- Integration tests for bypass mechanisms
- Chaos engineering to test resilience