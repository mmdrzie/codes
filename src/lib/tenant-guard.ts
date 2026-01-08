import { NextRequest, NextResponse } from 'next/server';
import { verifyAccessToken } from './token';
import { logger } from './logger';

export interface TenantUser {
  userId: string;
  tenantId: string;
  roles: string[];
  permissions: string[];
}

/**
 * Multi-tenant authorization guard
 * Enforces strict tenant isolation and user permissions
 */
export class TenantGuard {
  /**
   * Extract tenant ID from request
   */
  static extractTenantId(request: NextRequest): string | null {
    // Check for tenant in various locations
    const tenantId = 
      request.headers.get('x-tenant-id') ||
      request.nextUrl.searchParams.get('tenantId') ||
      this.extractTenantFromSubdomain(request) ||
      this.extractTenantFromPath(request);
    
    return tenantId || null;
  }

  /**
   * Extract tenant from subdomain (e.g., tenant1.example.com)
   */
  private static extractTenantFromSubdomain(request: NextRequest): string | null {
    try {
      const host = request.headers.get('host');
      if (!host) return null;
      
      const parts = host.split('.');
      if (parts.length >= 3) {
        return parts[0]; // tenant1.example.com -> tenant1
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Extract tenant from path (e.g., /tenant/tenant1/api/...)
   */
  private static extractTenantFromPath(request: NextRequest): string | null {
    const path = request.nextUrl.pathname;
    const match = path.match(/^\/tenant\/([^\/]+)/);
    return match ? match[1] : null;
  }

  /**
   * Verify user has access to the specified tenant
   */
  static async authorizeRequest(request: NextRequest): Promise<{ authorized: boolean; user?: TenantUser; error?: string }> {
    try {
      // Extract JWT token from request
      const token = this.extractToken(request);
      if (!token) {
        return { authorized: false, error: 'No authentication token provided' };
      }

      // Verify JWT token and extract user data
      const tokenPayload = await verifyAccessToken(token);
      if (!tokenPayload) {
        return { authorized: false, error: 'Invalid or expired token' };
      }

      // Extract requested tenant ID
      const requestedTenantId = this.extractTenantId(request);
      
      // For user-specific endpoints, use user's assigned tenant
      if (!requestedTenantId && request.nextUrl.pathname.includes('/api/users/')) {
        // User can only access their own data in their tenant
        return {
          authorized: tokenPayload.userId === request.nextUrl.pathname.split('/')[3], // Extract user ID from path
          user: {
            userId: tokenPayload.userId,
            tenantId: tokenPayload.tenantId || 'default',
            roles: tokenPayload.roles || [],
            permissions: tokenPayload.permissions || []
          },
          error: tokenPayload.userId === request.nextUrl.pathname.split('/')[3] ? undefined : 'Cannot access another user\'s data'
        };
      }

      // Verify tenant access
      if (!requestedTenantId) {
        return { 
          authorized: false, 
          error: 'No tenant specified in request' 
        };
      }

      // Check if user belongs to the requested tenant
      if (tokenPayload.tenantId !== requestedTenantId) {
        logger.warn('Tenant access violation', {
          userId: tokenPayload.userId,
          requestedTenant: requestedTenantId,
          userTenant: tokenPayload.tenantId,
          path: request.nextUrl.pathname
        });
        
        return { 
          authorized: false, 
          error: 'Cross-tenant access not allowed' 
        };
      }

      // Check user roles and permissions
      const user: TenantUser = {
        userId: tokenPayload.userId,
        tenantId: tokenPayload.tenantId,
        roles: tokenPayload.roles || [],
        permissions: tokenPayload.permissions || []
      };

      // Apply role-based access control
      const hasAccess = this.checkPermissions(user, request);
      if (!hasAccess) {
        return { 
          authorized: false, 
          error: 'Insufficient permissions for this operation' 
        };
      }

      return { 
        authorized: true, 
        user 
      };

    } catch (error) {
      logger.error('Tenant guard error', { error: (error as Error).message, path: request.nextUrl.pathname });
      return { 
        authorized: false, 
        error: 'Authorization system error' 
      };
    }
  }

  /**
   * Check if user has required permissions for the request
   */
  private static checkPermissions(user: TenantUser, request: NextRequest): boolean {
    const path = request.nextUrl.pathname;
    const method = request.method;

    // Admin users have full access
    if (user.roles.includes('admin')) {
      return true;
    }

    // Define permission rules
    const permissionRules: Array<{
      pathPattern: RegExp;
      method: string;
      requiredPermissions: string[];
      allowedRoles?: string[];
    }> = [
      {
        pathPattern: /^\/api\/tenant\/.*\/users\/.*$/,
        method: 'GET',
        requiredPermissions: ['user:read'],
        allowedRoles: ['admin', 'manager', 'user']
      },
      {
        pathPattern: /^\/api\/tenant\/.*\/users\/.*$/,
        method: 'POST|PUT|PATCH',
        requiredPermissions: ['user:write'],
        allowedRoles: ['admin', 'manager']
      },
      {
        pathPattern: /^\/api\/tenant\/.*\/users\/.*$/,
        method: 'DELETE',
        requiredPermissions: ['user:delete'],
        allowedRoles: ['admin']
      },
      {
        pathPattern: /^\/api\/tenant\/.*\/admin/,
        method: '.*',
        requiredPermissions: ['admin:access'],
        allowedRoles: ['admin']
      },
      {
        pathPattern: /^\/api\/tenant\/.*\/settings/,
        method: 'GET',
        requiredPermissions: ['settings:read'],
        allowedRoles: ['admin', 'manager']
      },
      {
        pathPattern: /^\/api\/tenant\/.*\/settings/,
        method: 'POST|PUT|PATCH',
        requiredPermissions: ['settings:write'],
        allowedRoles: ['admin']
      }
    ];

    // Find matching rule
    const matchingRule = permissionRules.find(rule => 
      rule.pathPattern.test(path) && 
      new RegExp(rule.method).test(method)
    );

    if (!matchingRule) {
      // Default: require user role for any tenant access
      return user.roles.includes('user') || user.roles.includes('admin') || user.roles.includes('manager');
    }

    // Check if user has required role
    if (matchingRule.allowedRoles && !matchingRule.allowedRoles.some(role => user.roles.includes(role))) {
      return false;
    }

    // Check if user has required permissions
    const hasRequiredPermissions = matchingRule.requiredPermissions.every(perm => 
      user.permissions.includes(perm)
    );

    return hasRequiredPermissions;
  }

  /**
   * Extract token from various sources
   */
  private static extractToken(request: NextRequest): string | null {
    // Check Authorization header
    const authHeader = request.headers.get('authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    // Check for session cookie
    const cookies = request.cookies.getAll();
    const sessionCookie = cookies.find(c => c.name === '__session');
    if (sessionCookie) {
      return sessionCookie.value;
    }

    return null;
  }
}

/**
 * Middleware helper for tenant guard
 */
export async function withTenantGuard(request: NextRequest, handler: (user: TenantUser) => Promise<NextResponse>): Promise<NextResponse> {
  const authResult = await TenantGuard.authorizeRequest(request);
  
  if (!authResult.authorized) {
    return NextResponse.json(
      { error: 'Unauthorized', message: authResult.error },
      { status: 403 }
    );
  }

  return handler(authResult.user!);
}