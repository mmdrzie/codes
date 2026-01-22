import { IncomingMessage } from 'http';
import { logger } from '../logger';

export interface TrustedProxyConfig {
  trustedProxies: string[];
  forwardedHeaders: {
    clientIp: string[];
    forwardedHost: string[];
    forwardedProto: string[];
  };
}

export class NetworkTrustModel {
  private readonly config: TrustedProxyConfig;
  private readonly trustedProxyRegexes: RegExp[];

  constructor(config: Partial<TrustedProxyConfig> = {}) {
    this.config = {
      trustedProxies: config.trustedProxies || [],
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

    logger.info('Network Trust Model initialized', {
      component: 'network-security',
      trustedProxies: this.config.trustedProxies
    });
  }

  /**
   * Get the true client IP address, validating against trusted proxies
   */
  getClientIpAddress(req: IncomingMessage): string {
    const socketRemoteAddress = req.socket.remoteAddress;
    
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
    
    if (!isTrusted) {
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