import Redis from 'ioredis';

interface SentinelConfig {
  hosts: Array<{ host: string; port: number }>;
  masterName: string;
  password?: string;
  sentinelPassword?: string;
}

class RedisSentinel {
  private config: SentinelConfig;
  private masterRedis: Redis | null = null;
  private replicaRedis: Redis | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;

  constructor(config: SentinelConfig) {
    this.config = config;
  }

  /**
   * Connect to Redis master via Sentinel
   */
  public async connectToMaster(): Promise<Redis> {
    if (this.masterRedis) {
      return this.masterRedis;
    }

    const redisOptions = {
      sentinels: this.config.hosts.map(h => ({ host: h.host, port: h.port })),
      name: this.config.masterName,
      password: this.config.password,
      sentinelPassword: this.config.sentinelPassword,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      lazyConnect: true,
      role: 'master'
    };

    this.masterRedis = new Redis(redisOptions);

    this.setupEventHandlers(this.masterRedis, 'MASTER');

    try {
      await this.masterRedis.connect();
      console.log('Connected to Redis Master via Sentinel');
      return this.masterRedis;
    } catch (error) {
      console.error('Failed to connect to Redis Master:', error);
      throw error;
    }
  }

  /**
   * Connect to Redis replica via Sentinel
   */
  public async connectToReplica(): Promise<Redis> {
    if (this.replicaRedis) {
      return this.replicaRedis;
    }

    const redisOptions = {
      sentinels: this.config.hosts.map(h => ({ host: h.host, port: h.port })),
      name: this.config.masterName,
      password: this.config.password,
      sentinelPassword: this.config.sentinelPassword,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      lazyConnect: true,
      role: 'slave'
    };

    this.replicaRedis = new Redis(redisOptions);

    this.setupEventHandlers(this.replicaRedis, 'REPLICA');

    try {
      await this.replicaRedis.connect();
      console.log('Connected to Redis Replica via Sentinel');
      return this.replicaRedis;
    } catch (error) {
      console.error('Failed to connect to Redis Replica:', error);
      throw error;
    }
  }

  /**
   * Setup event handlers for monitoring connection state
   */
  private setupEventHandlers(redis: Redis, type: string) {
    redis.on('connect', () => {
      console.log(`${type} Redis connected`);
      this.reconnectAttempts = 0; // Reset on successful connection
    });

    redis.on('ready', () => {
      console.log(`${type} Redis is ready`);
    });

    redis.on('error', (error) => {
      console.error(`${type} Redis Error:`, error);
    });

    redis.on('reconnecting', () => {
      console.log(`${type} Redis reconnecting...`);
      this.handleReconnection(type);
    });

    redis.on('close', () => {
      console.log(`${type} Redis connection closed`);
    });

    redis.on('end', () => {
      console.log(`${type} Redis connection ended`);
    });
  }

  /**
   * Handle reconnection logic
   */
  private handleReconnection(type: string) {
    this.reconnectAttempts++;
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error(`${type} Redis max reconnection attempts reached. Initiating failover...`);
      this.initiateFailover();
    }
  }

  /**
   * Monitor master status and initiate failover if needed
   */
  public async monitorMasterStatus(): Promise<void> {
    try {
      const master = await this.connectToMaster();
      const info = await master.info('replication');
      
      // Parse replication info to check if this is still the master
      if (!info.includes('role:master')) {
        console.log('Current master has changed, initiating failover...');
        await this.initiateFailover();
      }
    } catch (error) {
      console.error('Error monitoring master status:', error);
      await this.initiateFailover();
    }
  }

  /**
   * Initiate failover process
   */
  private async initiateFailover(): Promise<void> {
    console.log('Initiating Redis failover...');
    
    try {
      // Close existing connections
      if (this.masterRedis) {
        await this.masterRedis.quit();
        this.masterRedis = null;
      }
      
      if (this.replicaRedis) {
        await this.replicaRedis.quit();
        this.replicaRedis = null;
      }
      
      // Wait before attempting to reconnect
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Reconnect to new master
      await this.connectToMaster();
      console.log('Redis failover completed successfully');
    } catch (error) {
      console.error('Redis failover failed:', error);
      throw error;
    }
  }

  /**
   * Promote replica to master
   */
  public async promoteReplicaToMaster(): Promise<void> {
    console.log('Promoting replica to master...');
    
    try {
      // First connect to replica
      const replica = await this.connectToReplica();
      
      // Execute slaveof command to break replication
      await replica.slaveof('NO', 'ONE');
      
      // Update references
      this.masterRedis = replica;
      this.replicaRedis = null;
      
      console.log('Replica promoted to master successfully');
    } catch (error) {
      console.error('Failed to promote replica to master:', error);
      throw error;
    }
  }

  /**
   * Get master Redis instance
   */
  public getMaster(): Redis | null {
    return this.masterRedis;
  }

  /**
   * Get replica Redis instance
   */
  public getReplica(): Redis | null {
    return this.replicaRedis;
  }

  /**
   * Disconnect all connections
   */
  public async disconnect(): Promise<void> {
    if (this.masterRedis) {
      await this.masterRedis.quit();
      this.masterRedis = null;
    }
    
    if (this.replicaRedis) {
      await this.replicaRedis.quit();
      this.replicaRedis = null;
    }
  }

  /**
   * Get connection string for current master
   */
  public getConnectionString(): string {
    if (this.masterRedis) {
      const options = this.masterRedis.options;
      return `redis://${options.username || ''}:${options.password || ''}@${options.host}:${options.port}/${options.db}`;
    }
    return '';
  }
}

// Singleton instance
let redisSentinel: RedisSentinel | null = null;

export const getRedisSentinel = (): RedisSentinel => {
  if (!redisSentinel) {
    const sentinelHosts = process.env.REDIS_SENTINEL_HOSTS?.split(',') || ['localhost:26379'];
    const hosts = sentinelHosts.map(hostPort => {
      const [host, port] = hostPort.split(':');
      return { host, port: parseInt(port) };
    });
    
    redisSentinel = new RedisSentinel({
      hosts,
      masterName: process.env.REDIS_MASTER_NAME || 'mymaster',
      password: process.env.REDIS_PASSWORD,
      sentinelPassword: process.env.REDIS_SENTINEL_PASSWORD,
    });
  }
  
  return redisSentinel;
};

export default RedisSentinel;