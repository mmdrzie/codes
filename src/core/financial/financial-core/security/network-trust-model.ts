import { IncomingMessage } from 'http';
import { logger } from '../logger';

export interface TrustedProxyConfig {
  trustedProxies: string[];
  forwardedHeaders: {
    clientIp: string[];
    forwardedHost: string[];
    forwardedProto: string[];
  };
  strictAllowList: boolean; // If true, reject all non-trusted proxies
  clientIpAllowList: string[]; // Additional allow-list for client IPs
}

export class NetworkTrustModel {
  private readonly config: TrustedProxyConfig;
  private readonly trustedProxyRegexes: RegExp[];
  private readonly clientIpAllowListRegexes: RegExp[];

  constructor(config: Partial<TrustedProxyConfig> = {}) {
    this.config = {
      trustedProxies: config.trustedProxies || [],
      clientIpAllowList: config.clientIpAllowList || [],
      strictAllowList: config.strictAllowList ?? false,
      forwardedHeaders: {
        clientIp: config.forwardedHeaders?.clientIp || ['x-forwarded-for', 'x-real-ip'],
        forwardedHost: config.forwardedHeaders?.forwardedHost || ['x-forwarded-host'],
        forwardedProto: config.forwardedHeaders?.forwardedProto || ['x-forwarded-proto']
      }
    };

    // Precompile regexes for trusted proxies
    this.trustedProxyRegexes = this.config.trustedProxies.map(pattern => {
      // Convert CIDR notation to regex or exact match
      if (pattern.includes('/')) {
        // Simple CIDR to regex conversion (simplified)
        const [ip, bits] = pattern.split('/');
        const escapedIp = ip.replace(/\./g, '\\.');
        return new RegExp(`^${escapedIp}.*`);
      }
      return new RegExp(`^${pattern.replace(/\./g, '\\.').replace(/\*/g, '.*')}$`);
    });

    // Precompile regexes for client IP allow-list
    this.clientIpAllowListRegexes = this.config.clientIpAllowList.map(pattern => {
      if (pattern.includes('/')) {
        const [ip, bits] = pattern.split('/');
        const escapedIp = ip.replace(/\./g, '\\.');
        return new RegExp(`^${escapedIp}.*`);
      }
      return new RegExp(`^${pattern.replace(/\./g, '\\.').replace(/\*/g, '.*')}$`);
    });

    logger.info('Network Trust Model initialized', {
      component: 'network-security',
      trustedProxies: this.config.trustedProxies,
      clientIpAllowList: this.config.clientIpAllowList,
      strictAllowList: this.config.strictAllowList
    });
  }

  /**
   * Get the true client IP address, validating against trusted proxies
   */
  getClientIpAddress(req: IncomingMessage): string {
    const socketRemoteAddress = req.socket.remoteAddress;
    
    // If strict allow-list is enabled, validate the client IP
    if (this.config.strictAllowList && socketRemoteAddress && !this.isClientIpAllowed(socketRemoteAddress)) {
      logger.securityEvent('Client IP not in allow-list', {
        component: 'network-security',
        clientIp: socketRemoteAddress,
        allowList: this.config.clientIpAllowList
      });
      
      // In strict mode, return a safe default or block the request
      // For now, we'll return a special value that indicates the IP is not trusted
      return 'UNTRUSTED_CLIENT_IP';
    }
    
    // If the direct remote address is trusted, use it
    if (socketRemoteAddress && this.isTrustedProxy(socketRemoteAddress)) {
      // Parse forwarded headers to get the original client IP
      const forwardedFor = this.getFirstForwardedIp(req);
      if (forwardedFor) {
        logger.debug('Client IP determined via trusted proxy', {
          component: 'network-security',
          socketRemoteAddress,
          forwardedFor,
          clientIp: forwardedFor
        });
        return forwardedFor;
      }
    }
    
    // If the remote address is not trusted, don't trust any forwarded headers
    // Return the direct socket address as the only trusted source
    logger.debug('Client IP from direct connection (no trusted proxy)', {
      component: 'network-security',
      socketRemoteAddress,
      clientIp: socketRemoteAddress
    });
    
    return socketRemoteAddress || 'unknown';
  }

  /**
   * Check if a client IP is in the allow-list
   */
  private isClientIpAllowed(ip: string): boolean {
    if (this.clientIpAllowListRegexes.length === 0) {
      return true; // No allow-list means all IPs are allowed
    }
    
    return this.clientIpAllowListRegexes.some(regex => regex.test(ip));
  }

  /**
   * Get the true protocol (http/https) respecting trusted proxy headers
   */
  getProtocol(req: IncomingMessage): string {
    const socketRemoteAddress = req.socket.remoteAddress;
    
    if (socketRemoteAddress && this.isTrustedProxy(socketRemoteAddress)) {
      const proto = this.getFirstHeaderValue(req, this.config.forwardedHeaders.forwardedProto);
      if (proto) {
        return proto.toLowerCase();
      }
    }
    
    // Default to the socket's encryption status if no trusted proxy
    return (req as any).connection?.encrypted ? 'https' : 'http';
  }

  /**
   * Get the true host respecting trusted proxy headers
   */
  getHost(req: IncomingMessage): string {
    const socketRemoteAddress = req.socket.remoteAddress;
    
    if (socketRemoteAddress && this.isTrustedProxy(socketRemoteAddress)) {
      const host = this.getFirstHeaderValue(req, this.config.forwardedHeaders.forwardedHost);
      if (host) {
        return host;
      }
    }
    
    return req.headers.host || 'unknown';
  }

  /**
   * Validate request integrity by checking for conflicting headers
   */
  validateRequestIntegrity(req: IncomingMessage): {
    valid: boolean;
    issues: string[];
  } {
    const issues: string[] = [];
    
    const socketRemoteAddress = req.socket.remoteAddress;
    const isTrusted = this.isTrustedProxy(socketRemoteAddress);
    const isAllowed = this.isClientIpAllowed(socketRemoteAddress || '');
    
    if (!isTrusted || !isAllowed) {
      // Check if untrusted clients are sending forwarded headers (potential spoofing)
      for (const headerName of [
        ...this.config.forwardedHeaders.clientIp,
        ...this.config.forwardedHeaders.forwardedHost,
        ...this.config.forwardedHeaders.forwardedProto
      ]) {
        const value = req.headers[headerName];
        if (value) {
          issues.push(`Untrusted client sent ${headerName} header: ${value}`);
        }
      }
      
      // If strict allow-list is enabled and IP is not allowed, block the request
      if (this.config.strictAllowList && !isAllowed) {
        issues.push(`Client IP ${socketRemoteAddress} is not in the allow-list`);
      }
    }
    
    return {
      valid: issues.length === 0,
      issues
    };
  }

  private isTrustedProxy(ip: string | undefined): boolean {
    if (!ip) return false;
    
    return this.trustedProxyRegexes.some(regex => regex.test(ip));
  }

  private getFirstForwardedIp(req: IncomingMessage): string | null {
    for (const headerName of this.config.forwardedHeaders.clientIp) {
      const value = req.headers[headerName];
      if (value) {
        // Handle comma-separated IPs (x-forwarded-for can have multiple)
        const ips = Array.isArray(value) ? value.join(',').split(',') : value.toString().split(',');
        
        // Return the leftmost IP (original client) that is not a private IP
        for (const ip of ips) {
          const trimmedIp = ip.trim();
          
          // Skip private/reserved IPs that might be internal to the proxy
          if (!this.isPrivateIp(trimmedIp)) {
            return trimmedIp;
          }
        }
      }
    }
    
    return null;
  }

  private getFirstHeaderValue(req: IncomingMessage, headerNames: string[]): string | null {
    for (const headerName of headerNames) {
      const value = req.headers[headerName];
      if (value) {
        return Array.isArray(value) ? value[0] : value.toString();
      }
    }
    return null;
  }

  private isPrivateIp(ip: string): boolean {
    // Simple check for private IP ranges
    return /^10\./.test(ip) ||
           /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
           /^192\.168\./.test(ip) ||
           /^127\./.test(ip) ||
           /^::1/.test(ip) ||
           /^fc00:/i.test(ip) ||
           /^fe80:/i.test(ip);
  }
}

// Default configuration for common proxy setups
export const DEFAULT_TRUSTED_PROXY_CONFIG: TrustedProxyConfig = {
  trustedProxies: [
    '127.0.0.1',
    '::1',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    // Common cloud provider ranges would go here in production
  ],
  clientIpAllowList: [], // Empty means allow all IPs, populate with specific ranges in production
  strictAllowList: false, // Set to true in production for extra security
  forwardedHeaders: {
    clientIp: ['x-forwarded-for', 'x-real-ip', 'x-client-ip'],
    forwardedHost: ['x-forwarded-host'],
    forwardedProto: ['x-forwarded-proto']
  }
};

// Global instance
let networkTrustModel: NetworkTrustModel | null = null;

export function getNetworkTrustModel(): NetworkTrustModel {
  if (!networkTrustModel) {
    networkTrustModel = new NetworkTrustModel(DEFAULT_TRUSTED_PROXY_CONFIG);
  }
  return networkTrustModel;
}