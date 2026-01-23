import Redis from 'ioredis';
import { CircuitBreaker } from '../circuit-breaker';

interface RedisConfig {
  host?: string;
  port?: number;
  password?: string;
  db?: number;
  sentinel?: boolean;
  sentinelHosts?: Array<{ host: string; port: number }>;
  masterName?: string;
}

class RedisClient {
  private redis: Redis.Redis | null = null;
  private circuitBreaker: CircuitBreaker;
  private config: RedisConfig;

  constructor(config: RedisConfig = {}) {
    this.config = {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
      db: parseInt(process.env.REDIS_DB || '0'),
      ...config
    };
    
    this.circuitBreaker = new CircuitBreaker({
      timeout: 3000,
      errorThresholdPercentage: 50,
      resetTimeout: 30000
    });
    
    this.initializeRedis();
  }

  private initializeRedis() {
    try {
      if (this.config.sentinel && this.config.sentinelHosts && this.config.masterName) {
        // Initialize with Sentinel
        this.redis = new Redis({
          sentinels: this.config.sentinelHosts,
          name: this.config.masterName,
          password: this.config.password,
          db: this.config.db,
          retryDelayOnFailover: 100,
          maxRetriesPerRequest: 3,
          enableReadyCheck: true,
          lazyConnect: true,
        });
      } else {
        // Initialize with standalone Redis
        this.redis = new Redis({
          host: this.config.host,
          port: this.config.port,
          password: this.config.password,
          db: this.config.db,
          retryDelayOnFailover: 100,
          maxRetriesPerRequest: 3,
          enableReadyCheck: true,
          lazyConnect: true,
        });
      }

      this.setupEventHandlers();
    } catch (error) {
      console.error('Failed to initialize Redis client:', error);
      throw error;
    }
  }

  private setupEventHandlers() {
    if (!this.redis) return;

    this.redis.on('connect', () => {
      console.log('Connected to Redis');
    });

    this.redis.on('ready', () => {
      console.log('Redis is ready');
    });

    this.redis.on('error', (error) => {
      console.error('Redis Error:', error);
      this.circuitBreaker.recordFailure();
    });

    this.redis.on('reconnecting', () => {
      console.log('Reconnecting to Redis...');
    });

    this.redis.on('close', () => {
      console.log('Redis connection closed');
    });
  }

  public async connect(): Promise<void> {
    if (!this.redis) {
      throw new Error('Redis client not initialized');
    }
    
    try {
      await this.redis.connect();
    } catch (error) {
      console.error('Failed to connect to Redis:', error);
      throw error;
    }
  }

  public async disconnect(): Promise<void> {
    if (this.redis) {
      await this.redis.quit();
      this.redis = null;
    }
  }

  public async get(key: string): Promise<string | null> {
    if (!this.redis) {
      throw new Error('Redis client not initialized');
    }

    try {
      const result = await this.circuitBreaker.call(async () => {
        return await this.redis!.get(key);
      });
      
      return result;
    } catch (error) {
      console.warn(`Cache miss for key ${key}:`, error);
      // Graceful degradation - return null instead of throwing
      return null;
    }
  }

  public async set(key: string, value: string, ttl?: number): Promise<boolean> {
    if (!this.redis) {
      throw new Error('Redis client not initialized');
    }

    try {
      const result = await this.circuitBreaker.call(async () => {
        if (ttl !== undefined) {
          return await this.redis!.setex(key, ttl, value);
        } else {
          return await this.redis!.set(key, value);
        }
      });
      
      return result === 'OK';
    } catch (error) {
      console.error(`Failed to set key ${key}:`, error);
      return false; // Graceful degradation
    }
  }

  public async del(key: string): Promise<number> {
    if (!this.redis) {
      throw new Error('Redis client not initialized');
    }

    try {
      const result = await this.circuitBreaker.call(async () => {
        return await this.redis!.del(key);
      });
      
      return result;
    } catch (error) {
      console.error(`Failed to delete key ${key}:`, error);
      return 0; // Graceful degradation
    }
  }

  public async healthCheck(): Promise<boolean> {
    try {
      if (!this.redis) {
        return false;
      }
      
      // Test connection with PING
      const result = await this.redis.ping();
      return result === 'PONG';
    } catch (error) {
      console.error('Redis health check failed:', error);
      return false;
    }
  }

  public async ping(): Promise<string> {
    if (!this.redis) {
      throw new Error('Redis client not initialized');
    }
    
    return await this.redis.ping();
  }

  public getClient(): Redis.Redis | null {
    return this.redis;
  }
}

// Singleton instance
let redisClient: RedisClient | null = null;

export const getRedisClient = (): RedisClient => {
  if (!redisClient) {
    const config: RedisConfig = {
      sentinel: process.env.REDIS_SENTINEL === 'true',
      masterName: process.env.REDIS_MASTER_NAME || 'mymaster',
    };

    if (process.env.REDIS_SENTINEL_HOSTS) {
      const sentinelHosts = process.env.REDIS_SENTINEL_HOSTS.split(',').map(hostPort => {
        const [host, port] = hostPort.split(':');
        return { host, port: parseInt(port) };
      });
      config.sentinelHosts = sentinelHosts;
    }

    redisClient = new RedisClient(config);
  }
  
  return redisClient;
};

export default RedisClient;