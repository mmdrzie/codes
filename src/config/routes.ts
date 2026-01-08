/**
 * Centralized route configuration for authentication and public routes
 */
export const ROUTE_CONFIG = {
  /**
   * Public routes that don't require authentication
   */
  PUBLIC_ROUTES: [
    '/',
    '/login',
    '/register',
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/wallet/nonce',
    '/api/auth/wallet',
    '/api/auth/refresh',
    '/api/auth/sync-firebase',
    '/api/auth/logout',
    '/api/web3/nonce',
    '/api/web3/signin',
    '/api/auth/session'
  ] as const,

  /**
   * Public API routes that don't require authentication
   */
  PUBLIC_API_ROUTES: [
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/wallet/nonce',
    '/api/auth/wallet',
    '/api/auth/refresh',
    '/api/auth/sync-firebase',
    '/api/web3/nonce',
    '/api/web3/signin',
    '/api/auth/session'
  ] as const,

  /**
   * Authentication API routes
   */
  AUTH_API_ROUTES: [
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/logout',
    '/api/auth/refresh',
    '/api/auth/session',
    '/api/auth/wallet',
    '/api/auth/wallet/nonce',
    '/api/auth/sync-firebase',
    '/api/web3/nonce',
    '/api/web3/signin'
  ] as const,

  /**
   * Protected API routes (require authentication)
   */
  PROTECTED_API_ROUTES: [
    '/api/auth/profile',
    '/api/auth/change-password',
    '/api/auth/verify-token',
    '/api/user/',
    '/api/admin/'
  ] as const
} as const;

/**
 * Check if a route is public (doesn't require authentication)
 */
export function isPublicRoute(pathname: string): boolean {
  return ROUTE_CONFIG.PUBLIC_ROUTES.some(route => 
    pathname === route || 
    pathname.startsWith(route + '/') ||
    (route.endsWith('/') && pathname.startsWith(route))
  );
}

/**
 * Check if a route is a public API route
 */
export function isPublicApiRoute(pathname: string): boolean {
  return ROUTE_CONFIG.PUBLIC_API_ROUTES.some(route => 
    pathname === route || 
    pathname.startsWith(route + '/') ||
    (route.endsWith('/') && pathname.startsWith(route))
  );
}

/**
 * Check if a route requires authentication
 */
export function isProtectedRoute(pathname: string): boolean {
  return !isPublicRoute(pathname);
}

/**
 * Check if a route is an authentication API route
 */
export function isAuthApiRoute(pathname: string): boolean {
  return ROUTE_CONFIG.AUTH_API_ROUTES.some(route => 
    pathname === route || 
    pathname.startsWith(route + '/') ||
    (route.endsWith('/') && pathname.startsWith(route))
  );
}