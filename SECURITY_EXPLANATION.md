# Security Implementation Explanation

This document explains how the implemented security measures protect against the identified attack vectors and vulnerabilities.

## 1. JWT Authentication Security

### Attack Vector: Token Forgery Prevention
**How it's blocked:**
- **Cryptographic Signature Verification**: All JWTs are verified using HMAC SHA-256 algorithm with a strong secret key
- **Issuer Verification**: Validates that tokens come from the expected issuer (`your-app-issuer`)
- **Audience Validation**: Ensures tokens are intended for the correct audience (`your-app-audience`)
- **Expiration Checks**: Validates both `exp` and `nbf` claims to prevent use of expired or not-yet-valid tokens
- **Clock Skew Tolerance**: Allows 5 seconds of clock difference between systems
- **Replay Attack Protection**: Each JWT includes a unique `jti` (JWT ID) that's tracked to prevent reuse

### Implementation Details:
- Uses `jose` library for RFC 7519 compliant JWT handling
- Stores secrets in environment variables, never hardcoded
- Implements proper error handling to avoid leaking sensitive information

## 2. SSRF (Server-Side Request Forgery) Prevention

### Attack Vector: External Service Access via Internal Proxy
**How it's blocked:**
- **Whitelist Approach**: Only allows requests to pre-defined, approved domains
- **DNS Resolution Protection**: Resolves hostnames to IP addresses and validates against private network ranges
- **IP Address Blocking**: Explicitly blocks private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x, etc.)
- **Port Filtering**: Blocks access to sensitive ports (22, 25, 110, 143, 1433, 3306, 5432, 6379, 27017)
- **URL Pattern Validation**: Blocks suspicious patterns like hexadecimal IPs, directory traversal, and authentication bypass attempts
- **Header Sanitization**: Only forwards safe headers, strips dangerous ones like `Set-Cookie`, `Location`, etc.

### Implementation Details:
- Uses Node.js DNS module to resolve hostnames before making requests
- Maintains configurable allowlist of approved domains
- Implements proper timeout and resource limits

## 3. SIWE (Sign-In With Ethereum) Security

### Attack Vector: SIWE Replay Attacks
**How it's blocked:**
- **Single-Use Nonces**: Each nonce is generated with `nanoid(32)` and marked as used after first verification
- **Session Binding**: Nonces are optionally bound to specific user sessions
- **Expiration Enforcement**: Nonces expire after 10 minutes automatically
- **Message Integrity**: Validates all EIP-4361 message fields including domain, URI, and chain ID
- **Signature Verification**: Uses official `siwe` library to verify cryptographic signatures
- **Address Validation**: Validates Ethereum address format using `viem` library

### Implementation Details:
- Nonces stored in memory with automatic cleanup (use Redis in production)
- Cryptographically secure random generation using `nanoid`
- Proper EIP-4361 compliance with all required fields validated

## 4. Multi-Tenant Isolation

### Attack Vector: Cross-Tenant Data Access
**How it's blocked:**
- **Tenant ID Extraction**: Validates tenant ID from multiple sources (headers, subdomain, URL path)
- **User-Tenant Binding**: Verifies user belongs to the requested tenant via custom claims
- **Request Authorization**: Enforces tenant-specific access controls on every request
- **RBAC Integration**: Combines tenant isolation with role-based access controls
- **Path Validation**: Prevents users from accessing other tenants' resources via crafted URLs

### Implementation Details:
- Validates tenant ID format (alphanumeric with hyphens/underscores)
- Uses custom Firebase claims for tenant binding
- Implements tenant-aware middleware for all protected routes

## 5. Input Validation (Zod Schemas)

### Attack Vector: Injection and Malformed Input
**How it's blocked:**
- **Strict Schema Definitions**: Every input is validated against precise Zod schemas
- **Whitelist Approach**: Only allows known, expected fields (`.strict()` method)
- **Type Enforcement**: Validates data types, lengths, formats, and ranges
- **Sanitization**: Transforms inputs (e.g., trimming whitespace, lowercasing emails)
- **Common Attack Prevention**: Blocks common passwords, disposable emails, SQL injection patterns

### Implementation Details:
- Comprehensive schemas for all user inputs
- Custom refinements for business logic validation
- Detailed error messages that don't leak system information

## 6. Session Management Security

### Attack Vector: Session Hijacking and Fixation
**How it's blocked:**
- **Secure Cookies**: All session cookies use `HttpOnly`, `Secure`, and `SameSite=strict` flags
- **Short Expirations**: Sessions expire after 24 hours with refresh mechanisms
- **CSRF Protection**: SameSite=strict prevents cross-site request forgery
- **Secure Transmission**: Cookies only transmitted over HTTPS in production
- **Session Regeneration**: New session tokens generated on privilege changes

### Implementation Details:
- Separate cookie handling for different authentication methods
- Proper cookie path and domain scoping
- Secure fallback mechanisms

## 7. Rate Limiting and Brute Force Protection

### Attack Vector: Credential Stuffing and Brute Force
**How it's blocked:**
- **Login Attempt Tracking**: Tracks failed login attempts per email/IP
- **Automatic Lockout**: Temporarily locks accounts after 5 failed attempts
- **Time-Based Resets**: Lockouts expire after 15 minutes
- **Memory Management**: Automatic cleanup of old attempt records

### Implementation Details:
- Configurable thresholds and time windows
- Memory-efficient tracking (use Redis in production)
- Proper logging without exposing sensitive information

## 8. Cryptographic Standards Compliance

### Attack Vector: Weak Encryption and Hashing
**How it's blocked:**
- **NIST-Approved Algorithms**: Uses HMAC SHA-256 for signatures
- **Secure Random Generation**: Cryptographically secure random values
- **Proper Key Management**: Secrets stored in environment variables
- **Salt Usage**: Automatic salting for password hashing (handled by Firebase)

### Implementation Details:
- No custom crypto implementations
- Industry-standard libraries only
- Regular security updates and patches

## 9. Error Handling and Information Disclosure

### Attack Vector: Information Leakage
**How it's blocked:**
- **Generic Error Messages**: No system-specific details in user-facing errors
- **Detailed Logging**: Full error details logged server-side only
- **Stack Trace Protection**: Stack traces never exposed to clients
- **Safe Defaults**: Fails closed, never fails open

### Implementation Details:
- Structured logging with PII sanitization
- Centralized error handling middleware
- Security-focused error categorization

## 10. Production Security Headers

### Attack Vector: Client-Side Exploits
**How it's blocked:**
- **Content Security Policy**: Restricts resource loading to trusted sources
- **XSS Protection**: Browser-based XSS prevention headers
- **Clickjacking Defense**: Frame-ancestors policy prevents clickjacking
- **Transport Security**: HSTS enforces HTTPS usage

### Implementation Details:
- Comprehensive security header implementation
- Regular security header audits
- Performance-optimized policies

This security architecture provides defense in depth against all major attack vectors while maintaining usability and performance. Each layer reinforces the others, creating a robust security posture suitable for production environments handling real users and financial transactions.