'use client';

import React, { useState, useEffect } from 'react';

interface Alert {
  id: string;
  timestamp: string;
  severity: 'INFO' | 'WARN' | 'HIGH' | 'CRITICAL';
  title: string;
  description: string;
  sourceIp?: string;
  userId?: string;
  acknowledged?: boolean;
  resolved?: boolean;
}

interface SecurityMetric {
  totalEvents: number;
  highSeverityEvents: number;
  criticalEvents: number;
  threatsDetected: number;
}

const SecurityDashboard: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [metrics, setMetrics] = useState<SecurityMetric>({
    totalEvents: 0,
    highSeverityEvents: 0,
    criticalEvents: 0,
    threatsDetected: 0
  });
  const [loading, setLoading] = useState(true);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [timeRange, setTimeRange] = useState<'1h' | '6h' | '24h' | '7d'>('1h');

  // Fetch alerts and metrics
  useEffect(() => {
    const fetchData = async () => {
      try {
        // Mock data for demonstration
        const mockAlerts: Alert[] = [
          {
            id: 'alert-1',
            timestamp: new Date(Date.now() - 300000).toISOString(), // 5 minutes ago
            severity: 'CRITICAL',
            title: 'SQL Injection Attempt',
            description: 'SQL injection attempt detected from IP 192.168.1.100',
            sourceIp: '192.168.1.100',
            userId: 'user-123',
            acknowledged: false,
            resolved: false
          },
          {
            id: 'alert-2',
            timestamp: new Date(Date.now() - 600000).toISOString(), // 10 minutes ago
            severity: 'HIGH',
            title: 'Brute Force Attack',
            description: 'Multiple failed login attempts detected',
            sourceIp: '203.0.113.45',
            userId: 'user-456',
            acknowledged: true,
            resolved: true
          },
          {
            id: 'alert-3',
            timestamp: new Date(Date.now() - 1200000).toISOString(), // 20 minutes ago
            severity: 'WARN',
            title: 'Unusual Login Time',
            description: 'User logged in at unusual time',
            sourceIp: '198.51.100.22',
            userId: 'user-789',
            acknowledged: false,
            resolved: false
          }
        ];

        const mockMetrics: SecurityMetric = {
          totalEvents: 1245,
          highSeverityEvents: 23,
          criticalEvents: 3,
          threatsDetected: 12
        };

        setAlerts(mockAlerts);
        setMetrics(mockMetrics);
        setLoading(false);

        // In a real implementation, we would fetch from the API:
        /*
        const alertsResponse = await fetch(`/api/admin/monitoring/alerts?status=active&limit=50`);
        const alertsData = await alertsResponse.json();
        setAlerts(alertsData.data || []);

        // Fetch metrics
        const metricsResponse = await fetch(`/api/admin/monitoring/metrics`);
        const metricsData = await metricsResponse.json();
        setMetrics(metricsData.data || {});
        */
      } catch (error) {
        console.error('Error fetching security data:', error);
        setLoading(false);
      }
    };

    fetchData();

    // Refresh data every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [timeRange]);

  const handleAcknowledgeAlert = async (alertId: string) => {
    try {
      // In a real implementation, we would make an API call:
      /*
      const response = await fetch(`/api/admin/monitoring/alerts/${alertId}/acknowledge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userEmail: 'admin@example.com' })
      });

      if (response.ok) {
        setAlerts(prev => prev.map(alert => 
          alert.id === alertId ? { ...alert, acknowledged: true } : alert
        ));
      }
      */
      
      // For demo purposes, update locally
      setAlerts(prev => prev.map(alert => 
        alert.id === alertId ? { ...alert, acknowledged: true } : alert
      ));
    } catch (error) {
      console.error('Error acknowledging alert:', error);
    }
  };

  const handleResolveAlert = async (alertId: string) => {
    try {
      // In a real implementation, we would make an API call:
      /*
      const response = await fetch(`/api/admin/monitoring/alerts/${alertId}/resolve`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userEmail: 'admin@example.com' })
      });

      if (response.ok) {
        setAlerts(prev => prev.map(alert => 
          alert.id === alertId ? { ...alert, resolved: true } : alert
        ));
      }
      */
      
      // For demo purposes, update locally
      setAlerts(prev => prev.map(alert => 
        alert.id === alertId ? { ...alert, resolved: true } : alert
      ));
    } catch (error) {
      console.error('Error resolving alert:', error);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-red-500';
      case 'HIGH': return 'bg-orange-500';
      case 'WARN': return 'bg-yellow-500';
      case 'INFO': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
        <p className="mt-2 text-sm text-gray-600">
          Real-time monitoring of security events and alerts
        </p>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <div className="flex items-center">
              <div className="flex-shrink-0 bg-blue-500 rounded-md p-3">
                <svg className="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Total Events</dt>
                  <dd className="flex items-baseline">
                    <div className="text-2xl font-semibold text-gray-900">{metrics.totalEvents}</div>
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <div className="flex items-center">
              <div className="flex-shrink-0 bg-yellow-500 rounded-md p-3">
                <svg className="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">High Severity</dt>
                  <dd className="flex items-baseline">
                    <div className="text-2xl font-semibold text-gray-900">{metrics.highSeverityEvents}</div>
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <div className="flex items-center">
              <div className="flex-shrink-0 bg-red-500 rounded-md p-3">
                <svg className="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01" />
                </svg>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Critical Events</dt>
                  <dd className="flex items-baseline">
                    <div className="text-2xl font-semibold text-gray-900">{metrics.criticalEvents}</div>
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <div className="flex items-center">
              <div className="flex-shrink-0 bg-green-500 rounded-md p-3">
                <svg className="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Threats Detected</dt>
                  <dd className="flex items-baseline">
                    <div className="text-2xl font-semibold text-gray-900">{metrics.threatsDetected}</div>
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Alert Feed */}
        <div className="lg:col-span-2">
          <div className="bg-white shadow overflow-hidden sm:rounded-lg">
            <div className="px-4 py-5 border-b border-gray-200 sm:px-6">
              <div className="flex items-center justify-between">
                <h3 className="text-lg leading-6 font-medium text-gray-900">Recent Alerts</h3>
                <div className="flex space-x-2">
                  <select
                    value={timeRange}
                    onChange={(e) => setTimeRange(e.target.value as any)}
                    className="block w-full pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm rounded-md"
                  >
                    <option value="1h">Last Hour</option>
                    <option value="6h">Last 6 Hours</option>
                    <option value="24h">Last 24 Hours</option>
                    <option value="7d">Last 7 Days</option>
                  </select>
                </div>
              </div>
            </div>
            <ul className="divide-y divide-gray-200">
              {alerts.length > 0 ? (
                alerts.map((alert) => (
                  <li key={alert.id}>
                    <div className="px-4 py-4 sm:px-6">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(alert.severity)} text-white`}>
                            {alert.severity}
                          </span>
                          <p className="ml-3 text-sm font-medium text-indigo-600 truncate">{alert.title}</p>
                        </div>
                        <div className="flex items-center space-x-2">
                          {alert.acknowledged && (
                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                              Acknowledged
                            </span>
                          )}
                          {alert.resolved && (
                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                              Resolved
                            </span>
                          )}
                          <div className="text-sm text-gray-500">
                            {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </div>
                        </div>
                      </div>
                      <div className="mt-2 sm:flex sm:justify-between">
                        <div className="sm:flex">
                          <p className="flex items-center text-sm text-gray-600">
                            {alert.description}
                          </p>
                        </div>
                        <div className="mt-2 flex items-center text-sm text-gray-500 sm:mt-0">
                          <p className="flex items-center">
                            {alert.sourceIp && (
                              <>
                                <svg className="flex-shrink-0 mr-1.5 h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                                  <path fillRule="evenodd" d="M5.05 4.05a7 7 0 119.9 9.9L10 18.9l-4.95-4.95a7 7 0 010-9.9zM10 11a2 2 0 100-4 2 2 0 000 4z" clipRule="evenodd" />
                                </svg>
                                {alert.sourceIp}
                              </>
                            )}
                          </p>
                        </div>
                      </div>
                      <div className="mt-4 flex space-x-3">
                        {!alert.acknowledged && !alert.resolved && (
                          <>
                            <button
                              onClick={() => handleAcknowledgeAlert(alert.id)}
                              className="inline-flex items-center px-3 py-1 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                            >
                              Acknowledge
                            </button>
                            <button
                              onClick={() => handleResolveAlert(alert.id)}
                              className="inline-flex items-center px-3 py-1 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
                            >
                              Resolve
                            </button>
                          </>
                        )}
                        {alert.acknowledged && !alert.resolved && (
                          <button
                            onClick={() => handleResolveAlert(alert.id)}
                            className="inline-flex items-center px-3 py-1 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
                          >
                            Resolve
                          </button>
                        )}
                      </div>
                    </div>
                  </li>
                ))
              ) : (
                <li>
                  <div className="px-4 py-12 text-center sm:px-6">
                    <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    <h3 className="mt-2 text-sm font-medium text-gray-900">No alerts</h3>
                    <p className="mt-1 text-sm text-gray-500">No security alerts detected in the selected time range.</p>
                  </div>
                </li>
              )}
            </ul>
          </div>
        </div>

        {/* Threat Map & Stats */}
        <div className="space-y-6">
          {/* Threat Map Visualization */}
          <div className="bg-white shadow overflow-hidden sm:rounded-lg">
            <div className="px-4 py-5 border-b border-gray-200 sm:px-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900">Geographic Threat Map</h3>
            </div>
            <div className="px-4 py-5 sm:p-6">
              <div className="aspect-w-16 aspect-h-9 bg-gray-200 border-2 border-dashed rounded-lg" style={{ height: '300px' }}>
                <div className="flex items-center justify-center h-full">
                  <div className="text-center">
                    <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <p className="mt-2 text-sm text-gray-500">Interactive threat map visualization</p>
                    <p className="mt-1 text-xs text-gray-400">Shows threat origins by geographic location</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Top Threat Sources */}
          <div className="bg-white shadow overflow-hidden sm:rounded-lg">
            <div className="px-4 py-5 border-b border-gray-200 sm:px-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900">Top Threat Sources</h3>
            </div>
            <div className="px-4 py-5 sm:p-6">
              <ul className="divide-y divide-gray-200">
                <li className="py-3">
                  <div className="flex items-center">
                    <div className="flex-shrink-0 h-10 w-10 rounded-full bg-red-100 flex items-center justify-center">
                      <span className="text-sm font-medium text-red-800">CN</span>
                    </div>
                    <div className="ml-4">
                      <div className="text-sm font-medium text-gray-900">China</div>
                      <div className="text-sm text-gray-500">42 attacks</div>
                    </div>
                  </div>
                </li>
                <li className="py-3">
                  <div className="flex items-center">
                    <div className="flex-shrink-0 h-10 w-10 rounded-full bg-orange-100 flex items-center justify-center">
                      <span className="text-sm font-medium text-orange-800">RU</span>
                    </div>
                    <div className="ml-4">
                      <div className="text-sm font-medium text-gray-900">Russia</div>
                      <div className="text-sm text-gray-500">28 attacks</div>
                    </div>
                  </div>
                </li>
                <li className="py-3">
                  <div className="flex items-center">
                    <div className="flex-shrink-0 h-10 w-10 rounded-full bg-yellow-100 flex items-center justify-center">
                      <span className="text-sm font-medium text-yellow-800">BR</span>
                    </div>
                    <div className="ml-4">
                      <div className="text-sm font-medium text-gray-900">Brazil</div>
                      <div className="text-sm text-gray-500">19 attacks</div>
                    </div>
                  </div>
                </li>
                <li className="py-3">
                  <div className="flex items-center">
                    <div className="flex-shrink-0 h-10 w-10 rounded-full bg-gray-100 flex items-center justify-center">
                      <span className="text-sm font-medium text-gray-800">US</span>
                    </div>
                    <div className="ml-4">
                      <div className="text-sm font-medium text-gray-900">United States</div>
                      <div className="text-sm text-gray-500">15 attacks</div>
                    </div>
                  </div>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;