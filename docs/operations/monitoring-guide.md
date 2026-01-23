# Monitoring and Observability Guide

## Overview
This document provides comprehensive guidance for setting up, configuring, and maintaining monitoring and observability for the application. It covers metrics collection, alerting, dashboard creation, and on-call procedures.

## Document Information
- **Version:** 2.1
- **Last Updated:** January 23, 2026
- **Owner:** DevOps Team
- **Review Cycle:** Quarterly

---

## 1. Monitoring Stack Architecture

### 1.1 Components Overview

#### Metrics Collection
- **Prometheus**: Primary time-series database for metrics collection
- **Node Exporter**: System metrics collection from servers
- **Application Metrics**: Custom metrics from application code
- **CloudWatch**: AWS infrastructure metrics (when applicable)

#### Log Aggregation
- **Fluent Bit**: Log forwarding agent
- **Elasticsearch**: Log storage and indexing
- **Logstash**: Log processing and transformation
- **Kibana**: Log visualization and searching

#### Tracing
- **Jaeger**: Distributed tracing backend
- **OpenTelemetry**: Application tracing instrumentation
- **Zipkin**: Alternative tracing backend

#### Alerting
- **Alertmanager**: Prometheus alert routing and deduplication
- **PagerDuty**: On-call scheduling and escalation
- **Slack/Teams**: Alert notifications
- **Email**: Backup notification method

### 1.2 Data Flow Architecture

```
Application → OpenTelemetry → Jaeger/Zipkin (Traces)
     ↓
Custom Metrics → Prometheus → Alertmanager → PagerDuty
     ↓
System Metrics → Node Exporter → Prometheus
     ↓
Logs → Fluent Bit → Elasticsearch → Kibana
```

---

## 2. Metrics Collection

### 2.1 Application Metrics

#### Core Business Metrics
```typescript
// Example metric definitions
const metrics = {
  // User engagement
  active_users: 'counter - number of active users per minute',
  user_registrations: 'counter - new user registrations',
  login_attempts: 'counter - authentication attempts',
  
  // API performance
  api_requests_total: 'counter - total API requests by endpoint',
  api_duration_seconds: 'histogram - API response time distribution',
  api_errors_total: 'counter - error responses by code',
  
  // Business transactions
  orders_processed: 'counter - successful order completions',
  payment_attempts: 'counter - payment processing attempts',
  payment_success_rate: 'gauge - percentage of successful payments',
  
  // Resource utilization
  active_sessions: 'gauge - current active user sessions',
  concurrent_users: 'gauge - number of concurrently active users'
};
```

#### System Metrics
- CPU utilization (%)
- Memory usage (%)
- Disk I/O operations
- Network throughput
- File descriptor usage
- Process count

#### Database Metrics
- Query execution time
- Connection pool usage
- Active connections
- Slow query count
- Deadlock occurrences
- Replication lag

#### Cache Metrics
- Hit rate percentage
- Eviction rate
- Memory usage
- Connection count
- Command processing time

### 2.2 Metric Naming Conventions

#### Standard Format
```
namespace_subsystem_metricName_unit
```

#### Examples
- `app_http_requests_total` (counter)
- `app_http_request_duration_seconds` (histogram)
- `app_db_connections_active` (gauge)
- `app_cache_hit_ratio` (gauge)

#### Labels Best Practices
- Use consistent label names across metrics
- Keep label cardinality low (< 10 values)
- Use descriptive labels: `method`, `status`, `handler`, `instance`

---

## 3. Alert Configuration

### 3.1 Critical Alerts (P1 - Immediate Response Required)

#### System Health
| Alert Name | Condition | Description | Runbook |
|------------|-----------|-------------|---------|
| InstanceDown | up == 0 | Server/application is not responding | [RUNBOOK-001] |
| HighCPUUsage | avg by(instance) (rate(process_cpu_seconds_total[5m])) * 100 > 90 | CPU usage consistently above 90% | [RUNBOOK-002] |
| HighMemoryUsage | (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 90 | Memory usage above 90% | [RUNBOOK-003] |
| DiskSpaceCrit | (node_filesystem_size_bytes - node_filesystem_free_bytes) / node_filesystem_size_bytes * 100 > 95 | Less than 5% disk space remaining | [RUNBOOK-004] |

#### Application Health
| Alert Name | Condition | Description | Runbook |
|------------|-----------|-------------|---------|
| APIHighErrorRate | rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05 | More than 5% of requests returning 5xx errors | [RUNBOOK-005] |
| APISlowResponse | histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 2.0 | 95th percentile response time above 2 seconds | [RUNBOOK-006] |
| DatabaseDown | mysql_up == 0 | Database connection lost | [RUNBOOK-007] |
| CacheDown | redis_up == 0 | Redis cache unavailable | [RUNBOOK-008] |

### 3.2 Warning Alerts (P2 - Investigate Within 1 Hour)

#### Performance Degradation
| Alert Name | Condition | Description | Runbook |
|------------|-----------|-------------|---------|
| APIModerateErrorRate | rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.01 | More than 1% of requests returning 5xx errors | [RUNBOOK-009] |
| HighLatency | histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1.0 | 95th percentile response time above 1 second | [RUNBOOK-010] |
| DatabaseSlowQueries | rate(mysql_slow_queries_total[5m]) > 5 | More than 5 slow queries per minute | [RUNBOOK-011] |

#### Resource Utilization
| Alert Name | Condition | Description | Runbook |
|------------|-----------|-------------|---------|
| HighCPUUsageWarning | avg by(instance) (rate(process_cpu_seconds_total[5m])) * 100 > 75 | CPU usage consistently above 75% | [RUNBOOK-012] |
| HighMemoryUsageWarning | (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 80 | Memory usage above 80% | [RUNBOOK-013] |

### 3.3 Informational Alerts (P3 - Monitor Trend)

#### Traffic Anomalies
| Alert Name | Condition | Description | Runbook |
|------------|-----------|-------------|---------|
| TrafficSpikes | rate(http_requests_total[5m]) > avg_over_time(rate(http_requests_total[5m])[1h]) * 2 | Traffic more than 2x average | [RUNBOOK-014] |
| TrafficDrops | rate(http_requests_total[5m]) < avg_over_time(rate(http_requests_total[5m])[1h]) * 0.5 | Traffic less than 50% of average | [RUNBOOK-015] |

### 3.4 Alert Routing and Grouping

#### Alertmanager Configuration
```yaml
route:
  group_by: ['alertname', 'service', 'severity']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 12h
  receiver: 'default'
  routes:
    - match:
        severity: critical
      receiver: 'critical-team'
      group_wait: 10s
      repeat_interval: 1h
    - match:
        service: database
      receiver: 'db-team'
    - match:
        service: frontend
      receiver: 'frontend-team'

receivers:
  - name: 'default'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/...'
        channel: '#alerts'
  - name: 'critical-team'
    pagerduty_configs:
      - routing_key: '...'
        severity: 'critical'
```

---

## 4. Dashboard Setup

### 4.1 Key Performance Indicators (KPIs)

#### System Health Dashboard
- Overall system uptime
- Error rate trends
- Response time percentiles (50th, 95th, 99th)
- Throughput metrics
- Resource utilization

#### Business Metrics Dashboard
- Daily/Monthly Active Users
- Conversion rates
- Revenue metrics
- User engagement metrics
- Feature adoption rates

#### Technical Debt Dashboard
- Code coverage trends
- Security vulnerability counts
- Performance regression indicators
- Technical metric trends

### 4.2 Dashboard Best Practices

#### Layout Principles
- Top-left: Most critical information
- Left-right reading flow
- Consistent color schemes
- Appropriate chart types for data
- Clear titles and descriptions

#### Chart Recommendations
- **Time series**: Line charts for trend analysis
- **Current state**: Gauges for resource utilization
- **Comparisons**: Bar charts for categorical data
- **Distributions**: Histograms for response time distributions
- **Correlations**: Scatter plots for relationship analysis

---

## 5. SLA Monitoring

### 5.1 SLA Definitions

#### Availability SLA
- **Target**: 99.9% monthly uptime
- **Measurement**: Total minutes of downtime / total minutes in month
- **Exclusions**: Scheduled maintenance windows (max 4 hours/month)

#### Performance SLA
- **Target**: 95th percentile response time < 200ms
- **Measurement**: API response time percentiles
- **Exclusions**: Maintenance periods, DDoS attacks

#### Error Rate SLA
- **Target**: < 0.1% error rate
- **Measurement**: Percentage of failed requests
- **Exclusions**: Client-side errors (4xx), planned maintenance

### 5.2 SLA Tracking

#### SLI Calculation
```promql
# Availability SLI
sum(up{job="my-app"}) / count(up{job="my-app"})

# Latency SLI (percentage of requests under 200ms)
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) < 0.2

# Error Rate SLI
sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m]))
```

#### SLA Reporting
- Weekly SLA reports to stakeholders
- Monthly SLA summary in executive dashboard
- Quarterly SLA trend analysis
- Annual SLA compliance certification

---

## 6. On-Call Procedures

### 6.1 On-Call Schedule

#### Rotation Schedule
- **Primary On-Call**: 24/7 coverage
- **Secondary On-Call**: Escalation contact
- **Manager On-Call**: Executive notification
- **Schedule**: Rotating weekly among senior engineers

#### Escalation Path
1. Primary on-call engineer (immediate)
2. Secondary on-call engineer (+30 minutes)
3. Engineering manager (+1 hour)
4. VP of Engineering (+2 hours)
5. CTO (+4 hours)

### 6.2 Incident Response Process

#### Page Review (First 5 Minutes)
1. Read alert description and context
2. Check related metrics and logs
3. Determine if real incident or false positive
4. Acknowledge alert appropriately

#### Initial Response (Next 15 Minutes)
1. Assess impact and severity
2. Begin mitigation if possible
3. Create incident ticket
4. Notify stakeholders if needed
5. Document initial findings

#### Resolution (Ongoing)
1. Continue mitigation efforts
2. Update incident ticket regularly
3. Communicate status to team
4. Implement permanent fix
5. Document post-mortem

### 6.3 Runbook Examples

#### RUNBOOK-001: Instance Down
**Symptoms**: Application server is not responding to health checks
**Initial Actions**:
1. SSH to server and check process status
2. Check system logs: `/var/log/syslog`, application logs
3. Verify network connectivity
4. Check resource utilization (CPU, memory, disk)

**Resolution Steps**:
1. Restart application if process crashed
2. Scale up if resource constrained
3. Replace instance if hardware failure
4. Update monitoring configuration if false positive

#### RUNBOOK-005: High API Error Rate
**Symptoms**: More than 5% of requests returning 5xx errors
**Initial Actions**:
1. Check application logs for error patterns
2. Review recent deployments
3. Check database connectivity
4. Monitor downstream service health

**Resolution Steps**:
1. Roll back recent changes if correlated
2. Increase resources if capacity issue
3. Fix application bugs if code issue
4. Update alert thresholds if legitimate traffic pattern

---

## 7. Monitoring Implementation

### 7.1 Application Instrumentation

#### Metrics Collection Setup
```javascript
// Example application metrics setup
import promClient from 'prom-client';

// Create custom metrics
const httpRequestDuration = new promClient.Histogram({
  name: 'app_http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status'],
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
});

const activeUsers = new promClient.Gauge({
  name: 'app_active_users',
  help: 'Number of currently active users'
});

// Middleware to collect metrics
app.use((req, res, next) => {
  const end = httpRequestDuration.startTimer();
  
  res.on('finish', () => {
    end({ 
      method: req.method,
      route: req.route?.path || req.path,
      status: res.statusCode 
    });
  });
  
  next();
});
```

#### Health Check Endpoints
```javascript
// Health check implementation
app.get('/health', async (req, res) => {
  try {
    // Check database connectivity
    await db.checkConnection();
    
    // Check external dependencies
    await externalService.healthCheck();
    
    // Check system resources
    const memoryUsage = process.memoryUsage();
    if (memoryUsage.heapUsed > 0.9 * memoryUsage.heapTotal) {
      throw new Error('High memory usage');
    }
    
    res.status(200).json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      version: process.env.npm_package_version,
      checks: {
        database: 'ok',
        external_service: 'ok',
        memory: 'normal'
      }
    });
  } catch (error) {
    res.status(503).json({
      status: 'error',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});
```

### 7.2 Infrastructure Monitoring

#### Server Monitoring Setup
```bash
# Install Node Exporter on servers
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
tar xvfz node_exporter-1.6.1.linux-amd64.tar.gz
cd node_exporter-1.6.1.linux-amd64
./node_exporter &

# Configure Prometheus to scrape Node Exporter
# prometheus.yml
scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['server1:9100', 'server2:9100', 'server3:9100']
```

#### Log Forwarding Configuration
```yaml
# Fluent Bit configuration
[SERVICE]
    Flush         1
    Log_Level     info
    Daemon        off
    Parsers_File  parsers.conf

[INPUT]
    Name              tail
    Path              /var/log/app/*.log
    Parser            json
    Tag               app.*

[FILTER]
    Name                modify
    Match               app.*
    Add                 service app

[OUTPUT]
    Name            es
    Match           *
    Host            elasticsearch
    Port            9200
    Logstash_Format On
    Logstash_Prefix app
```

---

## 8. Advanced Monitoring Patterns

### 8.1 Anomaly Detection

#### Statistical Anomaly Detection
```promql
# Detect anomalies in request rate
avg_over_time(rate(http_requests_total[5m])[1h]) +
stddev_over_time(rate(http_requests_total[5m])[1h]) * 2 <
rate(http_requests_total[5m])

# Detect anomalies in response time
histogram_quantile(0.95, avg_over_time(rate(http_request_duration_seconds_bucket[5m])[1h])) +
histogram_quantile(0.95, stddev_over_time(rate(http_request_duration_seconds_bucket[5m])[1h])) * 2 <
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))
```

#### Machine Learning-Based Detection
- Use CloudWatch Anomaly Detection (AWS)
- Implement custom ML models for complex patterns
- Seasonal trend analysis
- Predictive alerting

### 8.2 Cost Optimization

#### Monitoring Cost Management
- Sample logs to reduce volume
- Use appropriate retention periods
- Filter out unnecessary metrics
- Use cost-effective storage tiers

#### Alert Optimization
- Reduce alert noise with intelligent grouping
- Implement alert fatigue prevention
- Use escalation policies to avoid over-notification
- Regular alert review and cleanup

---

## 9. Monitoring Best Practices

### 9.1 Golden Signals
Focus monitoring on four key signals:

1. **Latency**: Time to process requests
2. **Traffic**: Request volume
3. **Errors**: Rate of failed requests
4. **Saturation**: Resource utilization

### 9.2 The RED Method
For service-level monitoring:

1. **Rate**: Requests per second
2. **Errors**: Errors per second
3. **Duration**: Distribution of request latencies

### 9.3 The USE Method
For infrastructure monitoring:

1. **Utilization**: Percentage of time resource is busy
2. **Saturation**: Degree to which resource is overloaded
3. **Errors**: Count of error events

### 9.4 Four Types of Dashboards
1. **Executive Dashboard**: High-level business metrics
2. **Operational Dashboard**: Real-time system health
3. **Troubleshooting Dashboard**: Detailed diagnostic information
4. **Capacity Planning Dashboard**: Historical trends and forecasting

---

## 10. Appendix

### 10.1 Quick Reference Commands

#### Prometheus Queries
```promql
# Current error rate
sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m]))

# 95th percentile response time
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# Active users in last 5 minutes
count(count by(user_id) (http_requests_total{path="/api/*"}[5m]))

# Database connection usage
mysql_global_status_threads_connected / mysql_global_variables_max_connections
```

#### Common Debugging Commands
```bash
# Check current alerts
curl http://prometheus:9090/api/v1/alerts

# Check recent logs
curl -X GET "http://elasticsearch:9200/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-1h"
      }
    }
  }
}'

# Check tracing data
curl http://jaeger:16686/api/traces?service=my-service&limit=100
```

### 10.2 Troubleshooting Common Issues

#### High Cardinality Metrics
- Symptoms: Prometheus memory usage growing rapidly
- Solution: Review metric labels, remove high-cardinality dimensions
- Prevention: Implement metric validation in CI/CD

#### Alert Fatigue
- Symptoms: Too many low-priority alerts
- Solution: Adjust alert thresholds, improve signal-to-noise ratio
- Prevention: Regular alert review and optimization

#### Missing Data
- Symptoms: Gaps in monitoring dashboards
- Solution: Check scraper configurations, network connectivity
- Prevention: Implement monitoring for monitoring systems

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | Mar 2025 | DevOps Team | Initial release |
| 1.1 | Jun 2025 | DevOps Team | Added tracing section |
| 1.2 | Sep 2025 | DevOps Team | Updated alert configurations |
| 2.0 | Dec 2025 | DevOps Team | Major revision with new architecture |
| 2.1 | Jan 2026 | DevOps Team | Added advanced patterns and best practices |

---

## Approval

**DevOps Lead:** _________________ **Date:** _______

**Platform Engineer:** _________________ **Date:** _______

**Security Engineer:** _________________ **Date:** _______