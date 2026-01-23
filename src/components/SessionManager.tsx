'use client';

import React, { useState, useEffect } from 'react';
import { format, parseISO } from 'date-fns';

interface Session {
  sessionId: string;
  deviceId: string;
  ipAddress: string;
  userAgent: string;
  deviceType: string;
  browserName: string;
  os: string;
  createdAt: number;
  lastAccessed: number;
  isActive: boolean;
  isCurrent: boolean;
}

const SessionManager: React.FC = () => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Fetch active sessions
  useEffect(() => {
    fetchSessions();
  }, []);

  const fetchSessions = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/auth/sessions');
      
      if (!response.ok) {
        throw new Error('Failed to fetch sessions');
      }
      
      const data = await response.json();
      setSessions(data.sessions || []);
    } catch (err) {
      setError('Failed to load sessions. Please try again.');
      console.error('Error fetching sessions:', err);
    } finally {
      setLoading(false);
    }
  };

  const terminateSession = async (sessionId: string) => {
    try {
      const response = await fetch(`/api/auth/sessions/${sessionId}`, {
        method: 'DELETE',
      });
      
      if (!response.ok) {
        throw new Error('Failed to terminate session');
      }
      
      // Update the UI to reflect the terminated session
      setSessions(prev => prev.map(session => 
        session.sessionId === sessionId ? { ...session, isActive: false } : session
      ));
      
      setNotification({ type: 'success', message: 'Session terminated successfully' });
      setTimeout(() => fetchSessions(), 1000); // Refresh sessions after 1 second
    } catch (err) {
      setNotification({ type: 'error', message: 'Failed to terminate session' });
      console.error('Error terminating session:', err);
    }
  };

  const terminateAllOtherSessions = async () => {
    try {
      const response = await fetch('/api/auth/sessions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ action: 'terminate_all' }),
      });
      
      if (!response.ok) {
        throw new Error('Failed to terminate all other sessions');
      }
      
      setNotification({ type: 'success', message: 'All other sessions terminated successfully' });
      setTimeout(() => fetchSessions(), 1000); // Refresh sessions after 1 second
    } catch (err) {
      setNotification({ type: 'error', message: 'Failed to terminate all other sessions' });
      console.error('Error terminating all other sessions:', err);
    }
  };

  const reportUnauthorizedAccess = async (sessionId: string) => {
    try {
      const response = await fetch('/api/auth/sessions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          action: 'report_unauthorized_access',
          sessionId 
        }),
      });
      
      if (!response.ok) {
        throw new Error('Failed to report unauthorized access');
      }
      
      setNotification({ type: 'success', message: 'Unauthorized access reported successfully' });
    } catch (err) {
      setNotification({ type: 'error', message: 'Failed to report unauthorized access' });
      console.error('Error reporting unauthorized access:', err);
    }
  };

  // Clear notification after 5 seconds
  useEffect(() => {
    if (notification) {
      const timer = setTimeout(() => {
        setNotification(null);
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [notification]);

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto p-6 bg-white rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-6 text-gray-800">Active Sessions</h2>
      
      {notification && (
        <div 
          className={`mb-4 p-4 rounded-md ${
            notification.type === 'success' 
              ? 'bg-green-100 text-green-700' 
              : 'bg-red-100 text-red-700'
          }`}
        >
          {notification.message}
        </div>
      )}
      
      {error && (
        <div className="mb-4 p-4 bg-red-100 text-red-700 rounded-md">
          {error}
        </div>
      )}
      
      <div className="mb-6">
        <button
          onClick={terminateAllOtherSessions}
          className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
        >
          Terminate All Other Sessions
        </button>
      </div>
      
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Device
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Location
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Last Active
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
              <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {sessions.map((session) => (
              <tr key={session.sessionId} className={session.isCurrent ? 'bg-blue-50' : ''}>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="flex items-center">
                    <div className="ml-4">
                      <div className="text-sm font-medium text-gray-900">
                        {session.browserName} on {session.os}
                      </div>
                      <div className="text-sm text-gray-500">
                        {session.deviceType.charAt(0).toUpperCase() + session.deviceType.slice(1)}
                      </div>
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-900">{session.ipAddress}</div>
                  <div className="text-sm text-gray-500 truncate max-w-xs">
                    {session.userAgent.substring(0, 50)}...
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {format(new Date(session.lastAccessed), 'MMM d, yyyy h:mm a')}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                    session.isActive 
                      ? session.isCurrent 
                        ? 'bg-green-100 text-green-800' 
                        : 'bg-blue-100 text-blue-800'
                      : 'bg-gray-100 text-gray-800'
                  }`}>
                    {session.isCurrent ? 'Current' : session.isActive ? 'Active' : 'Inactive'}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  {!session.isCurrent && (
                    <>
                      <button
                        onClick={() => reportUnauthorizedAccess(session.sessionId)}
                        className="text-yellow-600 hover:text-yellow-900 mr-4"
                      >
                        This wasn't me
                      </button>
                      <button
                        onClick={() => terminateSession(session.sessionId)}
                        className="text-red-600 hover:text-red-900"
                      >
                        Terminate
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      
      {sessions.length === 0 && (
        <div className="text-center py-8 text-gray-500">
          No active sessions found
        </div>
      )}
    </div>
  );
};

export default SessionManager;