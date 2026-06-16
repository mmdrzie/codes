/**
 * Enterprise-Grade Redis Infrastructure
 * 
 * Provides fail-closed Redis client with circuit breaker pattern
 * Ensures production never silently degrades security
 */

import Redis, { Cluster } from 'ioredis';
import { logger } from '../utils/logger';

export interface RedisConfig {
  mode: 'standalone' | 'cluster' | 'sentinel';
  hosts?: Array<{ host: string; port: number }>;
  password?: string;
  db?: number;
  masterName?: string;
  sentinelPassword?: string;
  enableTLS?: boolean;
  maxRetriesPerRequest?: number;
  retryDelayOnFailover?: number;
  connectTimeout?: number;
  keepAlive?: number;
}

export interface CircuitBreakerState {
  failures: number;
  lastFailureTime: number;
  state: 'closed' | 'open' | 'half-open';
  nextAttempt: number;
}

export class CircuitBreaker {
  private state: CircuitBreakerState = {
    failures: 0,
    lastFailureTime: 0,
    state: 'closed',
    nextAttempt: 0,
  };

  private readonly failureThreshold: number;
  private readonly resetTimeout: number;
  private readonly halfOpenMaxRequests: number;
  private halfOpenRequests: number = 0;

  constructor(
    failureThreshold: number = 5,
    resetTimeout: number = 30000,
    halfOpenMaxRequests: number = 3
  ) {
    this.failureThreshold = failureThreshold;
    this.resetTimeout = resetTimeout;
    this.halfOpenMaxRequests = halfOpenMaxRequests;
  }

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state.state === 'open') {
      if (Date.now() < this.state.nextAttempt) {
        const error = new Error('Circuit breaker is open - service unavailable');
        error.name = 'CircuitBreakerOpenError';
        throw error;
      }
      // Transition to half-open
      this.state.state = 'half-open';
      this.halfOpenRequests = 0;
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    if (this.state.state === 'half-open') {
      this.halfOpenRequests++;
      if (this.halfOpenRequests >= this.halfOpenMaxRequests) {
        this.state.state = 'closed';
        this.state.failures = 0;
      }
    } else {
      this.state.failures = Math.max(0, this.state.failures - 1);
    }
  }

  private onFailure(): void {
    this.state.failures++;
    this.state.lastFailureTime = Date.now();

    if (this.state.failures >= this.failureThreshold) {
      this.state.state = 'open';
      this.state.nextAttempt = Date.now() + this.resetTimeout;
      logger.error('Circuit breaker opened', {
        failures: this.state.failures,
        resetAt: new Date(this.state.nextAttempt).toISOString(),
      });
    }
  }

  getState(): CircuitBreakerState {
    return { ...this.state };
  }
}

export class EnterpriseRedisClient {
  private client: Redis | Cluster | null = null;
  private circuitBreaker: CircuitBreaker;
  private config: RedisConfig;
  private isConnected: boolean = false;
  private connectionPromise: Promise<void> | null = null;

  constructor(config: RedisConfig) {
    this.config = config;
    this.circuitBreaker = new CircuitBreaker(
      config.maxRetriesPerRequest ? config.maxRetriesPerRequest : 5,
      config.retryDelayOnFailover ? config.retryDelayOnFailover : 30000,
      3
    );
  }

  /**
   * Initialize Redis connection - FAILS CLOSED if unavailable
   */
  async connect(): Promise<void> {
    if (this.isConnected) {
      return;
    }

    if (this.connectionPromise) {
      return this.connectionPromise;
    }

    this.connectionPromise = (async () => {
      try {
        await this.circuitBreaker.execute(async () => {
          this.client = await this.createRedisClient();
          
          return new Promise<void>((resolve, reject) => {
            if (!this.client) {
              reject(new Error('Failed to create Redis client'));
              return;
            }

            this.client.on('connect', () => {
              logger.info('Redis connected');
            });

            this.client.on('ready', () => {
              this.isConnected = true;
              logger.info('Redis ready');
              resolve();
            });

            this.client.on('error', (error) => {
              this.isConnected = false;
              logger.error('Redis error', { error: error.message });
              reject(error);
            });

            this.client.on('close', () => {
              this.isConnected = false;
              logger.warn('Redis connection closed');
            });

            this.client.on('reconnecting', () => {
              logger.info('Redis reconnecting');
            });
          });
        });
      } catch (error) {
        this.isConnected = false;
        logger.error('Redis connection failed - CRITICAL SECURITY DEPENDENCY', {
          error: (error as Error).message,
          config: { mode: this.config.mode },
        });
        throw new Error(
          `CRITICAL: Redis infrastructure unavailable. System cannot operate securely. ${
            (error as Error).message
          }`
        );
      } finally {
        this.connectionPromise = null;
      }
    })();

    return this.connectionPromise;
  }

  private async createRedisClient(): Promise<Redis | Cluster> {
    const commonOptions: Redis.CommonOptions = {
      password: this.config.password,
      db: this.config.db || 0,
      maxRetriesPerRequest: this.config.maxRetriesPerRequest || 3,
      retryDelayOnFailover: this.config.retryDelayOnFailover || 100,
      connectTimeout: this.config.connectTimeout || 10000,
      keepAlive: this.config.keepAlive || 30000,
      tls: this.config.enableTLS
        ? {
            rejectUnauthorized: true,
          }
        : undefined,
    };

    switch (this.config.mode) {
      case 'cluster':
        if (!this.config.hosts || this.config.hosts.length === 0) {
          throw new Error('Cluster mode requires hosts configuration');
        }
        return new Cluster(
          this.config.hosts.map((h) => ({
            host: h.host,
            port: h.port,
            ...commonOptions,
          })),
          {
            redisOptions: commonOptions,
            scaleReads: 'slave',
          }
        );

      case 'sentinel':
        if (!this.config.masterName || !this.config.hosts) {
          throw new Error('Sentinel mode requires masterName and hosts');
        }
        return new Redis({
          sentinels: this.config.hosts,
          name: this.config.masterName,
          sentinelPassword: this.config.sentinelPassword,
          ...commonOptions,
        });

      case 'standalone':
      default:
        if (!this.config.hosts || this.config.hosts.length === 0) {
          throw new Error('Standalone mode requires at least one host');
        }
        return new Redis({
          host: this.config.hosts[0].host,
          port: this.config.hosts[0].port,
          ...commonOptions,
        });
    }
  }

  /**
   * Atomic GET operation with circuit breaker
   */
  async get(key: string): Promise<string | null> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    return this.circuitBreaker.execute(async () => {
      const result = await this.client!.get(key);
      return result;
    });
  }

  /**
   * Atomic SETEX operation with circuit breaker
   */
  async setex(key: string, ttl: number, value: string): Promise<'OK'> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    return this.circuitBreaker.execute(async () => {
      const result = await this.client!.setex(key, ttl, value);
      return result as 'OK';
    });
  }

  /**
   * Atomic DELETE operation with circuit breaker
   */
  async del(key: string): Promise<number> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    return this.circuitBreaker.execute(async () => {
      const result = await this.client!.del(key);
      return result;
    });
  }

  /**
   * Execute Lua script atomically with circuit breaker
   */
  async eval(luaScript: string, keys: string[], args: string[]): Promise<any> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    return this.circuitBreaker.execute(async () => {
      const result = await this.client!.eval(luaScript, keys.length, ...keys, ...args);
      return result;
    });
  }

  /**
   * Atomic INCR operation with circuit breaker
   */
  async incr(key: string): Promise<number> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    return this.circuitBreaker.execute(async () => {
      const result = await this.client!.incr(key);
      return result;
    });
  }

  /**
   * Set operations with circuit breaker
   */
  async sadd(key: string, ...members: string[]): Promise<number> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    return this.circuitBreaker.execute(async () => {
      const result = await this.client!.sadd(key, ...members);
      return result;
    });
  }

  async smembers(key: string): Promise<string[]> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    return this.circuitBreaker.execute(async () => {
      const result = await this.client!.smembers(key);
      return result;
    });
  }

  async srem(key: string, ...members: string[]): Promise<number> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    return this.circuitBreaker.execute(async () => {
      const result = await this.client!.srem(key, ...members);
      return result;
    });
  }

  async scard(key: string): Promise<number> {
    if (!this.client) {
      throw new Error('Redis not initialized');
    }

    return this.circuitBreaker.execute(async () => {
      const result = await this.client!.scard(key);
      return result;
    });
  }

  /**
   * Health check - returns false if unhealthy
   */
  async healthCheck(): Promise<boolean> {
    if (!this.client || !this.isConnected) {
      return false;
    }

    try {
      const result = await this.circuitBreaker.execute(async () => {
        return await this.client!.ping();
      });
      return result === 'PONG';
    } catch {
      return false;
    }
  }

  /**
   * Graceful shutdown
   */
  async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.quit();
      this.client = null;
      this.isConnected = false;
      logger.info('Redis disconnected gracefully');
    }
  }

  /**
   * Get circuit breaker state for monitoring
   */
  getCircuitBreakerState(): CircuitBreakerState {
    return this.circuitBreaker.getState();
  }

  /**
   * Check if Redis is available and healthy
   */
  isHealthy(): boolean {
    return this.isConnected && this.circuitBreaker.getState().state !== 'open';
  }
}

// Singleton instance with lazy initialization
let enterpriseRedisClient: EnterpriseRedisClient | null = null;

export function getEnterpriseRedisClient(): EnterpriseRedisClient {
  if (!enterpriseRedisClient) {
    const config: RedisConfig = {
      mode: (process.env.REDIS_MODE as 'standalone' | 'cluster' | 'sentinel') || 'standalone',
      password: process.env.REDIS_PASSWORD,
      db: parseInt(process.env.REDIS_DB || '0'),
      masterName: process.env.REDIS_MASTER_NAME || 'mymaster',
      sentinelPassword: process.env.REDIS_SENTINEL_PASSWORD,
      enableTLS: process.env.REDIS_TLS_ENABLED === 'true',
      maxRetriesPerRequest: parseInt(process.env.REDIS_MAX_RETRIES || '3'),
      retryDelayOnFailover: parseInt(process.env.REDIS_RETRY_DELAY || '100'),
      connectTimeout: parseInt(process.env.REDIS_CONNECT_TIMEOUT || '10000'),
    };

    // Parse hosts based on mode
    if (config.mode === 'cluster' || config.mode === 'sentinel') {
      const hostsEnv = process.env.REDIS_HOSTS || process.env.REDIS_SENTINEL_HOSTS;
      if (hostsEnv) {
        config.hosts = hostsEnv.split(',').map((hostPort) => {
          const [host, port] = hostPort.split(':');
          return { host, port: parseInt(port) };
        });
      }
    } else {
      config.hosts = [
        {
          host: process.env.REDIS_HOST || 'localhost',
          port: parseInt(process.env.REDIS_PORT || '6379'),
        },
      ];
    }

    enterpriseRedisClient = new EnterpriseRedisClient(config);
  }

  return enterpriseRedisClient;
}

/**
 * Initialize Redis and validate connectivity - FAILS CLOSED
 */
export async function initializeRedisInfrastructure(): Promise<EnterpriseRedisClient> {
  const client = getEnterpriseRedisClient();
  await client.connect();
  
  if (!client.isHealthy()) {
    throw new Error('CRITICAL: Redis infrastructure health check failed');
  }
  
  return client;
}
