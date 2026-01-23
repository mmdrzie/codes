# Key Management Documentation

## Overview

This document outlines the key management system implemented for the QuantumIQ Financial platform. The system provides automated key rotation, secure storage, and versioning for various types of cryptographic keys.

## Key Types

The system manages four primary types of keys:

1. **Session Keys**: Used for session management and authentication
2. **JWT Keys**: Used for signing and verifying JSON Web Tokens
3. **API Keys**: Used for API authentication and authorization
4. **Database Encryption Keys**: Used for encrypting sensitive data at rest

## Key Lifecycle

### Generation
- Keys are generated using AWS KMS with FIPS 140-2 validated cryptographic modules
- Each key type has a specific algorithm:
  - Session & API keys: AES-256
  - JWT keys: RSA-2048
  - Database keys: AES-256

### Rotation
- Automatic rotation occurs every 90 days by default
- Manual rotation can be triggered via the CLI tool
- Emergency rotation is available for compromised keys

### Versioning
- Each key rotation creates a new version with an incremented number
- Historical keys are retained for decryption of previously encrypted data
- Default retention policy keeps 10 versions of each key type

## Key Rotation Process

1. **New Key Creation**: Generate a new key in AWS KMS
2. **Version Update**: Update the current key version in the registry
3. **Application Update**: Deploy new key to all application instances
4. **Historical Retention**: Move old key to historical storage
5. **Verification**: Confirm new key functionality

## Emergency Procedures

### Key Compromise Response
If a key is suspected to be compromised:

1. Immediately trigger emergency rotation for the affected key type
2. Generate a new key and update the current version
3. Assess the scope of potential data exposure
4. Monitor for unauthorized access using the compromised key
5. Implement additional monitoring if needed

### CLI Commands
```bash
# Rotate a specific key type
npm run rotate-keys -- session
npm run rotate-keys -- jwt
npm run rotate-keys -- api
npm run rotate-keys -- database

# List available key types
npm run rotate-keys -- --list

# Dry run (no actual rotation)
npm run rotate-keys -- --dry-run session
```

## Compliance Requirements

### FIPS 140-2
- All cryptographic operations use FIPS 140-2 validated algorithms
- AES-256 for symmetric encryption
- RSA-2048 for asymmetric operations
- SHA-256 for hashing operations

### Key Storage
- Active keys are stored in AWS KMS
- Historical keys are encrypted and stored in Redis with time-based retention
- No plaintext keys are stored in application code or configuration

## Architecture

### Components
- `KeyRotationManager`: Orchestrates the rotation process
- `KMSIntegration`: Interfaces with AWS KMS
- `KeyVersioning`: Manages key version history
- `CryptoOperations`: Provides encryption/decryption functions
- `rotate-keys.ts`: CLI tool for manual rotations

### Data Flow
1. Application requests encryption/decryption
2. CryptoOperations retrieves current key from KeyVersioning
3. If decrypting with old data, KeyVersioning finds appropriate historical key
4. KMSIntegration handles actual cryptographic operations
5. KeyRotationManager periodically rotates keys based on schedule

## Backup and Recovery

### Key Backup
- All keys are backed up in AWS KMS with built-in redundancy
- Historical key versions are stored in encrypted form in Redis
- Regular backups of key registry are maintained

### Recovery Process
In case of system failure:
1. Restore key registry from backup
2. Reconnect to AWS KMS to retrieve active keys
3. Rebuild historical key mappings if needed
4. Resume normal operations with existing keys

## Monitoring and Alerts

- Key rotation success/failure is logged
- Failed rotation attempts trigger alerts
- Key usage statistics are monitored
- Unauthorized key access attempts are detected and reported

## Security Considerations

- Keys are never stored in plaintext
- Access to key management functions is restricted
- All key operations are logged for audit purposes
- Network communication uses TLS encryption
- Regular security assessments of the key management system