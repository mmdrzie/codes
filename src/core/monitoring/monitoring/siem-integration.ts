import axios from 'axios';

export interface SecurityEventLog {
  timestamp: string;
  host: string;
  source: string;
  sourcetype?: string;
  event: {
    src_ip: string;
    dest_ip?: string;
    user: string;
    action: string;
    outcome: 'success' | 'failure';
    severity: 'low' | 'medium' | 'high' | 'critical';
    category: string;
    details: Record<string, any>;
  };
}

export interface CEFEvent {
  deviceVendor: string;
  deviceProduct: string;
  deviceVersion: string;
  signatureId: string;
  name: string;
  severity: number; // 0-10 scale
  extensions: Record<string, string | number>;
}

export class SIEMIntegration {
  private splunkUrl?: string;
  private splunkToken?: string;
  private elasticUrl?: string;
  private elasticApiKey?: string;
  private datadogApiKey?: string;

  constructor() {
    this.splunkUrl = process.env.SPLUNK_HEC_URL;
    this.splunkToken = process.env.SPLUNK_HEC_TOKEN;
    this.elasticUrl = process.env.ELASTICSEARCH_URL;
    this.elasticApiKey = process.env.ELASTICSEARCH_API_KEY;
    this.datadogApiKey = process.env.DATADOG_API_KEY;
  }

  /**
   * Sends a security event to Splunk
   */
  async sendToSplunk(event: SecurityEventLog): Promise<boolean> {
    if (!this.splunkUrl || !this.splunkToken) {
      console.warn('[SIEM] Splunk configuration missing, skipping event');
      return false;
    }

    try {
      const response = await axios.post(
        this.splunkUrl,
        { event: JSON.stringify(event) },
        {
          headers: {
            'Authorization': `Splunk ${this.splunkToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      console.log(`[SIEM] Event sent to Splunk: ${response.status}`);
      return response.status === 200;
    } catch (error) {
      console.error('[SIEM] Error sending event to Splunk:', error);
      return false;
    }
  }

  /**
   * Sends a security event to Elasticsearch
   */
  async sendToElasticsearch(event: SecurityEventLog): Promise<boolean> {
    if (!this.elasticUrl || !this.elasticApiKey) {
      console.warn('[SIEM] Elasticsearch configuration missing, skipping event');
      return false;
    }

    try {
      const index = `security-events-${new Date().toISOString().split('T')[0].replace(/-/g, '.')}`;
      const url = `${this.elasticUrl}/${index}/_doc`;

      const response = await axios.post(
        url,
        event,
        {
          headers: {
            'Authorization': `ApiKey ${this.elasticApiKey}`,
            'Content-Type': 'application/json'
          }
        }
      );

      console.log(`[SIEM] Event sent to Elasticsearch: ${response.status}`);
      return response.status === 201;
    } catch (error) {
      console.error('[SIEM] Error sending event to Elasticsearch:', error);
      return false;
    }
  }

  /**
   * Sends a security event to Datadog
   */
  async sendToDatadog(event: SecurityEventLog): Promise<boolean> {
    if (!this.datadogApiKey) {
      console.warn('[SIEM] Datadog API key missing, skipping event');
      return false;
    }

    try {
      const url = 'https://http-intake.logs.datadoghq.com/api/v2/logs';

      // Transform our event to Datadog format
      const datadogEvent = {
        ddsource: event.source,
        ddtags: `env:${process.env.NODE_ENV || 'production'},service:quantumiq-financial`,
        hostname: event.host,
        message: `${event.event.action} - ${event.event.outcome}`,
        service: 'quantumiq-financial',
        status: event.event.severity,
        timestamp: new Date(event.timestamp).getTime(),
        ...event.event.details
      };

      const response = await axios.post(
        url,
        [datadogEvent], // Datadog accepts batched events
        {
          headers: {
            'DD-API-KEY': this.datadogApiKey,
            'Content-Type': 'application/json'
          }
        }
      );

      console.log(`[SIEM] Event sent to Datadog: ${response.status}`);
      return response.status === 202;
    } catch (error) {
      console.error('[SIEM] Error sending event to Datadog:', error);
      return false;
    }
  }

  /**
   * Formats an event in CEF (Common Event Format)
   */
  formatCEFEvent(event: SecurityEventLog): string {
    // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    const cefVersion = '0';
    const deviceVendor = 'QuantumIQ';
    const deviceProduct = 'Financial Platform';
    const deviceVersion = '1.0';
    const signatureId = event.event.category.replace(/\s+/g, '_').toUpperCase();
    const name = event.event.action;
    
    // Map our severity to CEF severity (0-10 scale)
    let cefSeverity = 3; // Default to medium
    switch (event.event.severity) {
      case 'low': cefSeverity = 2; break;
      case 'medium': cefSeverity = 5; break;
      case 'high': cefSeverity = 8; break;
      case 'critical': cefSeverity = 10; break;
    }

    // Build extensions
    let extensions = `src=${event.event.src_ip}`;
    if (event.event.dest_ip) extensions += ` dst=${event.event.dest_ip}`;
    if (event.event.user) extensions += ` suser=${event.event.user}`;
    extensions += ` cs1Label=action cs1=${event.event.action}`;
    extensions += ` cs2Label=outcome cs2=${event.event.outcome}`;
    extensions += ` cn1Label=severity cn1=${cefSeverity}`;

    // Add any additional details
    for (const [key, value] of Object.entries(event.event.details)) {
      const formattedKey = key.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
      extensions += ` cs3Label=${key} cs3=${value}`;
    }

    return `CEF:${cefVersion}|${deviceVendor}|${deviceProduct}|${deviceVersion}|${signatureId}|${name}|${cefSeverity}|${extensions}`;
  }

  /**
   * Sends an event in CEF format to a SIEM
   */
  async sendCEFToSIEM(cefMessage: string, target: 'splunk' | 'elastic' | 'datadog' | 'all' = 'all'): Promise<boolean> {
    const results: boolean[] = [];

    if (target === 'splunk' || target === 'all') {
      results.push(await this.sendCEFToSplunk(cefMessage));
    }

    if (target === 'elastic' || target === 'all') {
      results.push(await this.sendCEFToElastic(cefMessage));
    }

    if (target === 'datadog' || target === 'all') {
      results.push(await this.sendCEFToDatadog(cefMessage));
    }

    return results.every(result => result);
  }

  /**
   * Sends CEF message to Splunk
   */
  private async sendCEFToSplunk(cefMessage: string): Promise<boolean> {
    if (!this.splunkUrl || !this.splunkToken) {
      console.warn('[SIEM] Splunk configuration missing, skipping CEF event');
      return false;
    }

    try {
      const response = await axios.post(
        this.splunkUrl,
        { event: cefMessage },
        {
          headers: {
            'Authorization': `Splunk ${this.splunkToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      console.log(`[SIEM] CEF event sent to Splunk: ${response.status}`);
      return response.status === 200;
    } catch (error) {
      console.error('[SIEM] Error sending CEF event to Splunk:', error);
      return false;
    }
  }

  /**
   * Sends CEF message to Elasticsearch
   */
  private async sendCEFToElastic(cefMessage: string): Promise<boolean> {
    if (!this.elasticUrl || !this.elasticApiKey) {
      console.warn('[SIEM] Elasticsearch configuration missing, skipping CEF event');
      return false;
    }

    try {
      const index = `cef-events-${new Date().toISOString().split('T')[0].replace(/-/g, '.')}`;
      const url = `${this.elasticUrl}/${index}/_doc`;
      
      const event = {
        '@timestamp': new Date().toISOString(),
        message: cefMessage,
        source: 'CEF',
        raw_cef: cefMessage
      };

      const response = await axios.post(
        url,
        event,
        {
          headers: {
            'Authorization': `ApiKey ${this.elasticApiKey}`,
            'Content-Type': 'application/json'
          }
        }
      );

      console.log(`[SIEM] CEF event sent to Elasticsearch: ${response.status}`);
      return response.status === 201;
    } catch (error) {
      console.error('[SIEM] Error sending CEF event to Elasticsearch:', error);
      return false;
    }
  }

  /**
   * Sends CEF message to Datadog
   */
  private async sendCEFToDatadog(cefMessage: string): Promise<boolean> {
    if (!this.datadogApiKey) {
      console.warn('[SIEM] Datadog API key missing, skipping CEF event');
      return false;
    }

    try {
      const url = 'https://http-intake.logs.datadoghq.com/api/v2/logs';

      const datadogEvent = {
        ddsource: 'CEF',
        ddtags: `env:${process.env.NODE_ENV || 'production'},service:quantumiq-financial,sourcetype:cef`,
        hostname: 'quantumiq-financial',
        message: cefMessage,
        service: 'quantumiq-financial',
        timestamp: Date.now(),
        raw_cef: cefMessage
      };

      const response = await axios.post(
        url,
        [datadogEvent], // Datadog accepts batched events
        {
          headers: {
            'DD-API-KEY': this.datadogApiKey,
            'Content-Type': 'application/json'
          }
        }
      );

      console.log(`[SIEM] CEF event sent to Datadog: ${response.status}`);
      return response.status === 202;
    } catch (error) {
      console.error('[SIEM] Error sending CEF event to Datadog:', error);
      return false;
    }
  }

  /**
   * Transforms a security event to our internal format
   */
  transformToInternalFormat(event: any): SecurityEventLog {
    return {
      timestamp: new Date().toISOString(),
      host: process.env.HOSTNAME || 'unknown',
      source: 'quantumiq-financial',
      sourcetype: 'security:event',
      event: {
        src_ip: event.src_ip || event.sourceIp || 'unknown',
        dest_ip: event.dest_ip || event.destinationIp,
        user: event.user_id || event.userId || 'unknown',
        action: event.action || event.type || 'unknown',
        outcome: event.success === false || event.outcome === 'failure' ? 'failure' : 'success',
        severity: event.severity || 'medium',
        category: event.category || 'general',
        details: event.details || {}
      }
    };
  }

  /**
   * Sends a security event to all configured SIEM systems
   */
  async sendToAllSIEMs(event: SecurityEventLog): Promise<boolean> {
    const results = await Promise.allSettled([
      this.sendToSplunk(event),
      this.sendToElasticsearch(event),
      this.sendToDatadog(event)
    ]);

    // Return true if at least one succeeded
    return results.some(result => 
      result.status === 'fulfilled' && result.value === true
    );
  }

  /**
   * Checks if SIEM integration is properly configured
   */
  isConfigured(): boolean {
    return !!(this.splunkUrl && this.splunkToken) ||
           !!(this.elasticUrl && this.elasticApiKey) ||
           !!this.datadogApiKey;
  }
}