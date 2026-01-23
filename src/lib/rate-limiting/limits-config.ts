export interface RateLimitRule {
  windowMs: number;     // Window size in milliseconds
  maxRequests: number;  // Max requests allowed in the window
  keyPrefix: string;    // Prefix for Redis keys
  message?: string;     // Custom message for exceeded limit
}

export interface EndpointRateLimits {
  [endpoint: string]: RateLimitRule[];
}

export interface GlobalRateLimits {
  ip: RateLimitRule[];
  account: RateLimitRule[];
  global: RateLimitRule[];
}

export class LimitsConfig {
  /**
   * Defines rate limits for different endpoint categories
   */
  static getEndpointLimits(): EndpointRateLimits {
    return {
      // Authentication endpoints (more restrictive)
      '/api/auth/login': [
        {
          windowMs: 15 * 60 * 1000, // 15 minutes
          maxRequests: 5,           // 5 attempts per 15 minutes
          keyPrefix: 'rl:auth:login:ip'
        },
        {
          windowMs: 60 * 60 * 1000, // 1 hour
          maxRequests: 10,          // 10 attempts per hour
          keyPrefix: 'rl:auth:login:ip:hourly'
        }
      ],
      '/api/auth/register': [
        {
          windowMs: 60 * 60 * 1000, // 1 hour
          maxRequests: 3,           // 3 registrations per hour per IP
          keyPrefix: 'rl:auth:register:ip'
        }
      ],
      '/api/auth/forgot-password': [
        {
          windowMs: 15 * 60 * 1000, // 15 minutes
          maxRequests: 3,           // 3 requests per 15 minutes
          keyPrefix: 'rl:auth:forgot:ip'
        }
      ],
      '/api/auth/reset-password': [
        {
          windowMs: 15 * 60 * 1000, // 15 minutes
          maxRequests: 5,           // 5 attempts per 15 minutes
          keyPrefix: 'rl:auth:reset:ip'
        }
      ],

      // Account-sensitive endpoints
      '/api/account/settings': [
        {
          windowMs: 60 * 1000,      // 1 minute
          maxRequests: 10,          // 10 requests per minute
          keyPrefix: 'rl:account:settings:ip'
        },
        {
          windowMs: 60 * 60 * 1000, // 1 hour
          maxRequests: 100,         // 100 requests per hour
          keyPrefix: 'rl:account:settings:account'
        }
      ],
      '/api/account/change-email': [
        {
          windowMs: 60 * 60 * 1000, // 1 hour
          maxRequests: 2,           // 2 email changes per hour
          keyPrefix: 'rl:account:email:account'
        }
      ],
      '/api/account/change-password': [
        {
          windowMs: 60 * 60 * 1000, // 1 hour
          maxRequests: 5,           // 5 password changes per hour
          keyPrefix: 'rl:account:password:account'
        }
      ],

      // Transaction endpoints
      '/api/transactions/create': [
        {
          windowMs: 60 * 60 * 1000, // 1 hour
          maxRequests: 50,          // 50 transactions per hour
          keyPrefix: 'rl:tx:create:account'
        },
        {
          windowMs: 24 * 60 * 60 * 1000, // 24 hours
          maxRequests: 200,              // 200 transactions per day
          keyPrefix: 'rl:tx:create:account:daily'
        }
      ],
      '/api/transactions/list': [
        {
          windowMs: 60 * 1000,      // 1 minute
          maxRequests: 30,          // 30 list requests per minute
          keyPrefix: 'rl:tx:list:account'
        }
      ],

      // General API endpoints (more generous)
      '/api/user/profile': [
        {
          windowMs: 60 * 1000,      // 1 minute
          maxRequests: 60,          // 60 requests per minute
          keyPrefix: 'rl:user:profile:ip'
        }
      ],
      '/api/dashboard/data': [
        {
          windowMs: 60 * 1000,      // 1 minute
          maxRequests: 100,         // 100 requests per minute
          keyPrefix: 'rl:dashboard:data:ip'
        }
      ]
    };
  }

  /**
   * Defines global rate limits that apply across all endpoints
   */
  static getGlobalLimits(): GlobalRateLimits {
    return {
      ip: [
        {
          windowMs: 60 * 1000,      // 1 minute
          maxRequests: 500,         // 500 requests per minute per IP
          keyPrefix: 'rl:global:ip:minutely'
        },
        {
          windowMs: 60 * 60 * 1000, // 1 hour
          maxRequests: 5000,        // 5000 requests per hour per IP
          keyPrefix: 'rl:global:ip:hourly'
        }
      ],
      account: [
        {
          windowMs: 60 * 1000,      // 1 minute
          maxRequests: 200,         // 200 requests per minute per account
          keyPrefix: 'rl:global:account:minutely'
        },
        {
          windowMs: 60 * 60 * 1000, // 1 hour
          maxRequests: 2000,        // 2000 requests per hour per account
          keyPrefix: 'rl:global:account:hourly'
        }
      ],
      global: [
        {
          windowMs: 60 * 1000,      // 1 minute
          maxRequests: 10000,       // 10000 requests per minute globally
          keyPrefix: 'rl:global:all:minutely'
        }
      ]
    };
  }

  /**
   * Gets limits for a specific endpoint
   */
  static getEndpointLimit(endpoint: string): RateLimitRule[] {
    const endpointLimits = this.getEndpointLimits();
    return endpointLimits[endpoint] || [];
  }

  /**
   * Gets default limits for unknown endpoints
   */
  static getDefaultLimits(): RateLimitRule[] {
    return [
      {
        windowMs: 60 * 1000,      // 1 minute
        maxRequests: 100,         // 100 requests per minute
        keyPrefix: 'rl:default:ip'
      }
    ];
  }

  /**
   * Checks if an endpoint has special (higher) limits for authenticated users
   */
  static isAuthenticatedEnhancedLimits(endpoint: string): boolean {
    // These endpoints get higher limits for authenticated users
    const enhancedEndpoints = [
      '/api/transactions/list',
      '/api/dashboard/data',
      '/api/user/profile'
    ];

    return enhancedEndpoints.includes(endpoint);
  }

  /**
   * Gets enhanced limits for authenticated users
   */
  static getAuthenticatedEnhancedLimits(endpoint: string): RateLimitRule[] {
    if (!this.isAuthenticatedEnhancedLimits(endpoint)) {
      return [];
    }

    // Return enhanced limits for this specific endpoint
    switch (endpoint) {
      case '/api/transactions/list':
        return [
          {
            windowMs: 60 * 1000,      // 1 minute
            maxRequests: 200,         // 200 requests per minute for authenticated users
            keyPrefix: 'rl:tx:list:auth:account'
          }
        ];
      case '/api/dashboard/data':
        return [
          {
            windowMs: 60 * 1000,      // 1 minute
            maxRequests: 200,         // 200 requests per minute for authenticated users
            keyPrefix: 'rl:dashboard:data:auth:account'
          }
        ];
      case '/api/user/profile':
        return [
          {
            windowMs: 60 * 1000,      // 1 minute
            maxRequests: 200,         // 200 requests per minute for authenticated users
            keyPrefix: 'rl:user:profile:auth:account'
          }
        ];
      default:
        return [];
    }
  }
}