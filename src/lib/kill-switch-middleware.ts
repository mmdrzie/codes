import { NextRequest, NextResponse } from 'next/server';
import KillSwitchManager, { EmergencyLevel } from './kill-switch/emergency-controls';

// Initialize the kill switch manager
const killSwitchManager = KillSwitchManager.getInstance();

/**
 * Kill Switch Middleware
 * Checks the current emergency level and blocks operations accordingly
 */
export async function killSwitchMiddleware(request: NextRequest): Promise<NextResponse> {
  try {
    // Get the current emergency level
    const currentLevel = await killSwitchManager.getCurrentEmergencyLevel();
    
    // Get the operation type from the request (method + path)
    const operation = `${request.method} ${request.nextUrl.pathname}`;
    
    // Check if the operation should be blocked based on current emergency level
    const isBlocked = await killSwitchManager.isOperationBlocked(operation);
    
    if (isBlocked) {
      // Operation is blocked due to emergency level
      return NextResponse.json(
        {
          error: 'Operation blocked due to emergency level',
          emergencyLevel: currentLevel,
          operation,
          timestamp: new Date().toISOString()
        },
        { status: 423 } // Locked status code for blocked operations
      );
    }
    
    // If the request includes an account ID in the path or body, check if the account is frozen
    const accountId = extractAccountIdFromRequest(request);
    if (accountId) {
      const isAccountFrozen = await killSwitchManager.isAccountFrozen(accountId);
      if (isAccountFrozen) {
        return NextResponse.json(
          {
            error: 'Account is frozen due to emergency action',
            accountId,
            timestamp: new Date().toISOString()
          },
          { status: 403 } // Forbidden status for frozen accounts
        );
      }
    }
    
    // Operation is allowed, continue with the request
    return NextResponse.next();
  } catch (error) {
    console.error('Error in kill switch middleware:', error);
    
    // On error, we might want to err on the side of caution
    // For now, let's allow the request to continue to avoid blocking legitimate traffic
    // due to a middleware failure
    return NextResponse.next();
  }
}

/**
 * Extract account ID from the request
 * This is a simplified implementation - in reality, you'd have more sophisticated logic
 */
function extractAccountIdFromRequest(request: NextRequest): string | null {
  try {
    // Check URL params for account ID patterns
    const url = request.url;
    const accountIdPattern = /\/accounts?\/([a-zA-Z0-9_-]+)/;
    const match = url.match(accountIdPattern);
    
    if (match && match[1]) {
      return match[1];
    }
    
    // Check if it's a user-specific endpoint
    const userIdPattern = /\/users?\/([a-zA-Z0-9_-]+)/;
    const userMatch = url.match(userIdPattern);
    
    if (userMatch && userMatch[1]) {
      return userMatch[1];
    }
    
    // For POST/PUT requests, check the body for account information
    // (Note: We can't access request body in middleware, so this would need to be in API routes)
    
    return null;
  } catch (error) {
    console.error('Error extracting account ID from request:', error);
    return null;
  }
}

/**
 * Higher-order function to wrap API routes with kill switch protection
 */
export function withKillSwitchProtection<T extends (...args: any[]) => any>(handler: T) {
  return async (...args: Parameters<T>): Promise<ReturnType<T> | NextResponse> => {
    const request = args[0] as NextRequest;
    
    // Get the current emergency level
    const currentLevel = await killSwitchManager.getCurrentEmergencyLevel();
    
    // Get the operation type from the request
    const operation = `${request.method} ${request.nextUrl.pathname}`;
    
    // Check if the operation should be blocked
    const isBlocked = await killSwitchManager.isOperationBlocked(operation);
    
    if (isBlocked) {
      return NextResponse.json(
        {
          error: 'Operation blocked due to emergency level',
          emergencyLevel: currentLevel,
          operation,
          timestamp: new Date().toISOString()
        },
        { status: 423 }
      ) as ReturnType<T>;
    }
    
    // Check if the account is frozen
    const accountId = extractAccountIdFromRequest(request);
    if (accountId) {
      const isAccountFrozen = await killSwitchManager.isAccountFrozen(accountId);
      if (isAccountFrozen) {
        return NextResponse.json(
          {
            error: 'Account is frozen due to emergency action',
            accountId,
            timestamp: new Date().toISOString()
          },
          { status: 403 }
        ) as ReturnType<T>;
      }
    }
    
    // Proceed with the original handler
    return handler(...args);
  };
}

// Export default middleware function
export default killSwitchMiddleware;