import { jwtVerify, type JWTPayload } from 'jose';
import { logger } from './logger';

// JWT Secret - should be set in environment variables
const JWT_SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET || 'default_secret_for_dev'
);

// Default audience and issuer - should be configured per environment
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'your-app-audience';
const JWT_ISSUER = process.env.JWT_ISSUER || 'your-app-issuer';

export interface TokenPayload extends JWTPayload {
  userId: string;
  tenantId?: string;
  roles?: string[];
  permissions?: string[];
  jti?: string; // JWT ID for replay protection
}

/**
 * Secure JWT verification function
 */
export async function verifyAccessToken(token: string): Promise<TokenPayload | null> {
  try {
    // Verify the JWT signature and claims
    const { payload } = await jwtVerify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      audience: JWT_AUDIENCE,
      issuer: JWT_ISSUER,
      clockTolerance: '5s', // Allow 5 seconds of clock skew
    });

    // Validate required fields
    if (!payload.userId) {
      logger.warn('JWT missing required userId field');
      return null;
    }

    // Check for expiration (duplicate check since jwtVerify does this, but explicit is better)
    if (payload.exp && Date.now() >= payload.exp * 1000) {
      logger.warn('JWT token expired');
      return null;
    }

    // Check if token is not yet valid
    if (payload.nbf && Date.now() < payload.nbf * 1000) {
      logger.warn('JWT token not yet valid');
      return null;
    }

    // Verify issuer if specified
    if (payload.iss && payload.iss !== JWT_ISSUER) {
      logger.warn('JWT issuer mismatch', { expected: JWT_ISSUER, actual: payload.iss });
      return null;
    }

    // Verify audience if specified
    if (payload.aud) {
      const expectedAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!expectedAud.includes(JWT_AUDIENCE)) {
        logger.warn('JWT audience mismatch', { expected: JWT_AUDIENCE, actual: payload.aud });
        return null;
      }
    }

    // Validate JWT ID to prevent replay attacks
    if (payload.jti) {
      const isReplayAttack = await checkForReplayAttack(payload.jti);
      if (isReplayAttack) {
        logger.warn('Potential replay attack detected', { jti: payload.jti });
        return null;
      }
    }

    return payload as TokenPayload;
  } catch (error: any) {
    logger.error('JWT verification failed', { 
      error: error.message, 
      stack: error.stack 
    });
    
    // Different error types require different responses
    if (error?.message?.includes('JWTExpired')) {
      logger.warn('JWT token expired');
    } else if (error?.message?.includes('JWTSignatureVerificationFailed')) {
      logger.warn('JWT signature verification failed - potential token forgery');
    } else if (error?.message?.includes('JWTAudienceInvalid') || error?.message?.includes('JWTIssuerInvalid')) {
      logger.warn('JWT claim validation failed');
    }
    
    return null;
  }
}

/**
 * Check for replay attacks using JWT ID (jti)
 * In production, use Redis or database for this
 */
const usedJtiStore = new Set<string>();
const JWT_CLEANUP_INTERVAL = 60 * 60 * 1000; // 1 hour

// Clean up old JTIs periodically
setInterval(() => {
  usedJtiStore.clear(); // In production, implement proper TTL
}, JWT_CLEANUP_INTERVAL);

async function checkForReplayAttack(jti: string): Promise<boolean> {
  if (usedJtiStore.has(jti)) {
    return true; // Replay attack detected
  }
  
  usedJtiStore.add(jti);
  return false;
}