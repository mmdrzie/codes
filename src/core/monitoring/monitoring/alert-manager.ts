import { Redis } from 'ioredis';

export interface Alert {
  id: string;
  timestamp: Date;
  severity: 'INFO' | 'WARN' | 'HIGH' | 'CRITICAL';
  title: string;
  description: string;
  sourceIp?: string;
  userId?: string;
  eventId?: string;
  acknowledged?: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
  resolved?: boolean;
  resolvedBy?: string;
  resolvedAt?: Date;
  details: Record<string, any>;
}

export interface AlertChannel {
  name: string;
  send(alert: Alert): Promise<void>;
}

export class AlertManager {
  private redis: Redis;
  private channels: Map<string, AlertChannel>;
  private deduplicationWindow: number; // milliseconds

  constructor(redisUrl?: string, deduplicationWindowMs: number = 300000) { // 5 minutes default
    this.redis = new Redis(redisUrl || process.env.REDIS_URL || 'redis://localhost:6379');
    this.channels = new Map();
    this.deduplicationWindow = deduplicationWindowMs;
    
    // Initialize default channels
    this.initializeDefaultChannels();
  }

  /**
   * Initializes default alert channels
   */
  private initializeDefaultChannels(): void {
    // Email channel
    this.channels.set('email', {
      name: 'email',
      send: async (alert: Alert) => {
        console.log(`[EMAIL_CHANNEL] Sending alert: ${alert.title} - Severity: ${alert.severity}`);
        // In a real implementation, this would send an email
      }
    });

    // Slack channel
    this.channels.set('slack', {
      name: 'slack',
      send: async (alert: Alert) => {
        console.log(`[SLACK_CHANNEL] Sending alert: ${alert.title} - Severity: ${alert.severity}`);
        // In a real implementation, this would post to a Slack webhook
      }
    });

    // PagerDuty channel
    this.channels.set('pagerduty', {
      name: 'pagerduty',
      send: async (alert: Alert) => {
        console.log(`[PAGERDUTY_CHANNEL] Sending alert: ${alert.title} - Severity: ${alert.severity}`);
        // In a real implementation, this would trigger a PagerDuty incident
      }
    });

    // SMS channel
    this.channels.set('sms', {
      name: 'sms',
      send: async (alert: Alert) => {
        console.log(`[SMS_CHANNEL] Sending alert: ${alert.title} - Severity: ${alert.severity}`);
        // In a real implementation, this would send an SMS
      }
    });
  }

  /**
   * Creates a new alert
   */
  async createAlert(alert: Omit<Alert, 'id'>): Promise<Alert> {
    const newAlert: Alert = {
      ...alert,
      id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
    };

    // Check for duplicates
    if (await this.isDuplicateAlert(newAlert)) {
      console.log(`[ALERT_MANAGER] Duplicate alert detected: ${newAlert.title}`);
      return newAlert;
    }

    // Save alert to Redis
    const alertKey = `alert:${newAlert.id}`;
    await this.redis.setex(alertKey, 86400 * 7, JSON.stringify(newAlert)); // Keep for 7 days

    // Add to alerts list sorted by timestamp
    await this.redis.zadd('alerts_list', newAlert.timestamp.getTime(), newAlert.id);

    // Add to severity-based lists
    await this.redis.zadd(`alerts_severity:${newAlert.severity.toLowerCase()}`, 
                          newAlert.timestamp.getTime(), newAlert.id);

    // Send alert to appropriate channels based on severity
    await this.routeAlertToChannels(newAlert);

    console.log(`[ALERT_MANAGER] Created alert: ${newAlert.id} - ${newAlert.title}`);

    return newAlert;
  }

  /**
   * Checks if an alert is a duplicate
   */
  private async isDuplicateAlert(alert: Alert): Promise<boolean> {
    // Create a hash of the alert content (excluding timestamp and ID)
    const alertHash = await this.generateAlertHash(alert);
    const hashKey = `alert_hash:${alertHash}`;
    
    // Check if this exact alert was already sent recently
    const existingTimestamp = await this.redis.get(hashKey);
    
    if (existingTimestamp) {
      const existingTime = parseInt(existingTimestamp);
      const currentTime = Date.now();
      
      // If the same alert was sent within the deduplication window, it's a duplicate
      return (currentTime - existingTime) < this.deduplicationWindow;
    }

    // Store this alert hash with current timestamp
    await this.redis.setex(hashKey, Math.ceil(this.deduplicationWindow / 1000), Date.now().toString());
    
    return false;
  }

  /**
   * Generates a hash for an alert to identify duplicates
   */
  private async generateAlertHash(alert: Alert): Promise<string> {
    // For simplicity, we'll create a basic hash from the alert properties
    // In a real implementation, use a proper hashing function
    const crypto = await import('crypto');
    const content = JSON.stringify({
      title: alert.title,
      description: alert.description,
      severity: alert.severity,
      sourceIp: alert.sourceIp,
      userId: alert.userId,
      details: alert.details
    });
    
    return crypto.createHash('md5').update(content).digest('hex');
  }

  /**
   * Routes an alert to appropriate channels based on severity
   */
  private async routeAlertToChannels(alert: Alert): Promise<void> {
    const channelsToSend: string[] = [];

    switch (alert.severity) {
      case 'CRITICAL':
        channelsToSend.push('email', 'slack', 'pagerduty', 'sms');
        break;
      case 'HIGH':
        channelsToSend.push('email', 'slack', 'pagerduty');
        break;
      case 'WARN':
        channelsToSend.push('email', 'slack');
        break;
      case 'INFO':
        channelsToSend.push('email');
        break;
    }

    // Send to each channel concurrently
    const promises = channelsToSend.map(channelName => {
      const channel = this.channels.get(channelName);
      if (channel) {
        return channel.send(alert);
      }
      return Promise.resolve();
    });

    try {
      await Promise.all(promises);
    } catch (error) {
      console.error('[ALERT_MANAGER] Error sending alert to channels:', error);
    }
  }

  /**
   * Acknowledges an alert
   */
  async acknowledgeAlert(alertId: string, acknowledgedBy: string): Promise<boolean> {
    const alertKey = `alert:${alertId}`;
    const alertData = await this.redis.get(alertKey);

    if (!alertData) {
      return false;
    }

    const alert = JSON.parse(alertData) as Alert;
    alert.acknowledged = true;
    alert.acknowledgedBy = acknowledgedBy;
    alert.acknowledgedAt = new Date();

    // Update the alert in Redis
    await this.redis.setex(alertKey, 86400 * 7, JSON.stringify(alert));

    console.log(`[ALERT_MANAGER] Alert ${alertId} acknowledged by ${acknowledgedBy}`);

    return true;
  }

  /**
   * Resolves an alert
   */
  async resolveAlert(alertId: string, resolvedBy: string): Promise<boolean> {
    const alertKey = `alert:${alertId}`;
    const alertData = await this.redis.get(alertKey);

    if (!alertData) {
      return false;
    }

    const alert = JSON.parse(alertData) as Alert;
    alert.resolved = true;
    alert.resolvedBy = resolvedBy;
    alert.resolvedAt = new Date();

    // Update the alert in Redis
    await this.redis.setex(alertKey, 86400 * 7, JSON.stringify(alert));

    console.log(`[ALERT_MANAGER] Alert ${alertId} resolved by ${resolvedBy}`);

    return true;
  }

  /**
   * Gets an alert by ID
   */
  async getAlertById(alertId: string): Promise<Alert | null> {
    const alertKey = `alert:${alertId}`;
    const alertData = await this.redis.get(alertKey);

    if (!alertData) {
      return null;
    }

    return JSON.parse(alertData) as Alert;
  }

  /**
   * Gets all alerts (with pagination)
   */
  async getAlerts(page: number = 1, limit: number = 50, severity?: 'INFO' | 'WARN' | 'HIGH' | 'CRITICAL'): Promise<Alert[]> {
    const start = (page - 1) * limit;
    const end = start + limit - 1;

    let alertsListKey = 'alerts_list';
    if (severity) {
      alertsListKey = `alerts_severity:${severity.toLowerCase()}`;
    }

    const alertIds = await this.redis.zrevrange(alertsListKey, start, end);
    const alerts: Alert[] = [];

    for (const id of alertIds) {
      const alert = await this.getAlertById(id);
      if (alert) {
        alerts.push(alert);
      }
    }

    return alerts;
  }

  /**
   * Gets active (unresolved) alerts
   */
  async getActiveAlerts(): Promise<Alert[]> {
    // Get all alerts and filter for unresolved ones
    const allAlerts = await this.getAlerts(1, 1000); // Get first 1000 alerts
    return allAlerts.filter(alert => !alert.resolved);
  }

  /**
   * Gets alert statistics
   */
  async getAlertStats(): Promise<{
    total: number;
    critical: number;
    high: number;
    warn: number;
    info: number;
    acknowledged: number;
    unresolved: number;
  }> {
    const total = await this.redis.zcount('alerts_list', '-inf', '+inf');
    const critical = await this.redis.zcount('alerts_severity:critical', '-inf', '+inf');
    const high = await this.redis.zcount('alerts_severity:high', '-inf', '+inf');
    const warn = await this.redis.zcount('alerts_severity:warn', '-inf', '+inf');
    const info = await this.redis.zcount('alerts_severity:info', '-inf', '+inf');

    // For acknowledged/unresolved counts, we'd need to iterate through alerts
    // For performance, returning placeholder values in this implementation
    return {
      total,
      critical,
      high,
      warn,
      info,
      acknowledged: 0, // Would require iteration to calculate accurately
      unresolved: total // Placeholder
    };
  }

  /**
   * Adds a custom alert channel
   */
  addChannel(name: string, channel: AlertChannel): void {
    this.channels.set(name, channel);
  }

  /**
   * Removes an alert channel
   */
  removeChannel(name: string): void {
    this.channels.delete(name);
  }
}