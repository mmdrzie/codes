import { Redis } from 'ioredis';
import { AlertManager } from './alert-manager';
import { ThreatDetection } from './threat-detection';
import { GeographicAnomaly } from './geographic-anomaly';

export interface SecurityEvent {
  id: string;
  timestamp: Date;
  eventType: string;
  severity: 'INFO' | 'WARN' | 'HIGH' | 'CRITICAL';
  sourceIp: string;
  userId?: string;
  userAgent?: string;
  endpoint?: string;
  details: Record<string, any>;
}

export interface AnomalyDetectionResult {
  isAnomaly: boolean;
  confidence: number; // 0-1
  threatType?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
}

export class SecurityMonitor {
  private redis: Redis;
  private alertManager: AlertManager;
  private threatDetection: ThreatDetection;
  private geographicAnomaly: GeographicAnomaly;

  constructor(redisUrl?: string) {
    this.redis = new Redis(redisUrl || process.env.REDIS_URL || 'redis://localhost:6379');
    this.alertManager = new AlertManager();
    this.threatDetection = new ThreatDetection();
    this.geographicAnomaly = new GeographicAnomaly();
  }

  /**
   * Processes a security event for anomaly detection
   */
  async processSecurityEvent(event: SecurityEvent): Promise<void> {
    try {
      // Store the event in Redis for analysis
      const eventKey = `security_event:${event.id}`;
      await this.redis.setex(eventKey, 86400, JSON.stringify(event)); // Keep for 24 hours

      // Add to security events stream for real-time processing
      await this.redis.xadd('security_events_stream', '*', 'event', JSON.stringify(event));

      // Perform anomaly detection
      const anomalyResult = await this.detectAnomalies(event);

      if (anomalyResult.isAnomaly) {
        // Create security alert
        await this.alertManager.createAlert({
          id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          timestamp: new Date(),
          severity: anomalyResult.severity === 'CRITICAL' ? 'CRITICAL' : 
                   anomalyResult.severity === 'HIGH' ? 'HIGH' : 'WARN',
          title: `Security Anomaly Detected: ${anomalyResult.threatType}`,
          description: anomalyResult.description,
          sourceIp: event.sourceIp,
          userId: event.userId,
          eventId: event.id,
          details: {
            ...event.details,
            confidence: anomalyResult.confidence,
            threatType: anomalyResult.threatType
          }
        });
      }

      // Perform geographic anomaly check if IP is involved
      if (event.sourceIp) {
        const geoResult = await this.geographicAnomaly.checkGeographicAnomaly(
          event.sourceIp,
          event.userId
        );

        if (geoResult.isAnomaly) {
          await this.alertManager.createAlert({
            id: `geo_alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            timestamp: new Date(),
            severity: geoResult.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
            title: `Geographic Anomaly: Impossible Travel`,
            description: geoResult.description,
            sourceIp: event.sourceIp,
            userId: event.userId,
            eventId: event.id,
            details: {
              ...event.details,
              previousLocation: geoResult.previousLocation,
              currentLocation: geoResult.currentLocation,
              distance: geoResult.distance,
              timeDelta: geoResult.timeDelta
            }
          });
        }
      }

      // Add to security events log
      await this.redis.zadd(
        'security_events_log',
        event.timestamp.getTime(),
        JSON.stringify(event)
      );

      console.log(`[SECURITY_MONITOR] Processed event ${event.id} at ${event.timestamp.toISOString()}`);
    } catch (error) {
      console.error('[SECURITY_MONITOR] Error processing security event:', error);
    }
  }

  /**
   * Detects anomalies in security events
   */
  private async detectAnomalies(event: SecurityEvent): Promise<AnomalyDetectionResult> {
    // Check for various threat patterns
    const threatChecks = await Promise.all([
      this.threatDetection.checkBruteForceAttempt(event),
      this.threatDetection.checkCredentialStuffing(event),
      this.threatDetection.checkAccountEnumeration(event),
      this.threatDetection.checkSQLInjection(event),
      this.threatDetection.checkXSSAttempt(event),
      this.threatDetection.checkDDoS(event),
      this.threatDetection.checkUnusualDataAccess(event),
      this.threatDetection.checkPrivilegeEscalation(event),
      this.threatDetection.checkDataExfiltration(event)
    ]);

    // Find the highest severity threat
    let highestThreat: AnomalyDetectionResult | null = null;
    for (const check of threatChecks) {
      if (check.isAnomaly) {
        if (!highestThreat || this.getSeverityLevel(check.severity) > this.getSeverityLevel(highestThreat.severity)) {
          highestThreat = check;
        }
      }
    }

    return highestThreat || {
      isAnomaly: false,
      confidence: 0,
      severity: 'LOW',
      description: 'No anomalies detected'
    };
  }

  /**
   * Gets numeric severity level for comparison
   */
  private getSeverityLevel(severity: string): number {
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return 4;
      case 'HIGH': return 3;
      case 'MEDIUM': return 2;
      case 'LOW': return 1;
      default: return 0;
    }
  }

  /**
   * Monitors for specific threat patterns in real-time
   */
  async startRealTimeMonitoring(): Promise<void> {
    console.log('[SECURITY_MONITOR] Starting real-time monitoring...');

    // Monitor the security events stream
    this.monitorSecurityEventsStream();

    // Start periodic checks
    this.startPeriodicChecks();
  }

  /**
   * Monitors the security events stream for new events
   */
  private async monitorSecurityEventsStream(): Promise<void> {
    // This would typically use Redis streams with blocking reads
    // For now, we'll set up a listener
    setInterval(async () => {
      try {
        // Read security events from stream (non-blocking approach for simplicity)
        const events = await this.redis.xrange('security_events_stream', '-', '+', 'COUNT', 10);
        
        for (const event of events) {
          const eventData = JSON.parse(event[1][1] as string) as SecurityEvent;
          await this.processSecurityEvent(eventData);
          
          // Acknowledge the event by removing it from the stream
          await this.redis.xdel('security_events_stream', event[0]);
        }
      } catch (error) {
        console.error('[SECURITY_MONITOR] Error reading security events stream:', error);
      }
    }, 1000); // Check every second
  }

  /**
   * Starts periodic security checks
   */
  private async startPeriodicChecks(): Promise<void> {
    // Check for brute force attempts every 30 seconds
    setInterval(async () => {
      await this.performBruteForceCheck();
    }, 30000);

    // Check for account enumeration every minute
    setInterval(async () => {
      await this.performAccountEnumerationCheck();
    }, 60000);

    // Check for data access anomalies every 2 minutes
    setInterval(async () => {
      await this.performDataAccessAnomalyCheck();
    }, 120000);
  }

  /**
   * Performs brute force check
   */
  private async performBruteForceCheck(): Promise<void> {
    // This would check for multiple failed login attempts in a short period
    // Implementation would involve querying Redis for recent login failures
    console.log('[SECURITY_MONITOR] Performing brute force check...');
  }

  /**
   * Performs account enumeration check
   */
  private async performAccountEnumerationCheck(): Promise<void> {
    // This would check for sequential requests to user-specific endpoints
    // Implementation would involve analyzing access patterns
    console.log('[SECURITY_MONITOR] Performing account enumeration check...');
  }

  /**
   * Performs data access anomaly check
   */
  private async performDataAccessAnomalyCheck(): Promise<void> {
    // This would check for unusual data access patterns
    // Implementation would involve comparing current access to baseline behavior
    console.log('[SECURITY_MONITOR] Performing data access anomaly check...');
  }

  /**
   * Gets recent security events
   */
  async getRecentSecurityEvents(limit: number = 100): Promise<SecurityEvent[]> {
    try {
      const events = await this.redis.zrevrange('security_events_log', 0, limit - 1, 'WITHSCORES');
      return events
        .filter((_, index) => index % 2 === 0) // Only take the even indices (the JSON strings)
        .map(eventJson => JSON.parse(eventJson as string) as SecurityEvent);
    } catch (error) {
      console.error('[SECURITY_MONITOR] Error getting recent security events:', error);
      return [];
    }
  }

  /**
   * Gets security metrics
   */
  async getSecurityMetrics(): Promise<{
    totalEvents: number;
    highSeverityEvents: number;
    criticalEvents: number;
    threatsDetected: number;
  }> {
    try {
      const totalEvents = await this.redis.zcount('security_events_log', '-inf', '+inf');
      
      // Count high severity events (would need to filter by severity in a real implementation)
      // For now, return placeholder values
      return {
        totalEvents,
        highSeverityEvents: 0,
        criticalEvents: 0,
        threatsDetected: 0
      };
    } catch (error) {
      console.error('[SECURITY_MONITOR] Error getting security metrics:', error);
      return {
        totalEvents: 0,
        highSeverityEvents: 0,
        criticalEvents: 0,
        threatsDetected: 0
      };
    }
  }
}