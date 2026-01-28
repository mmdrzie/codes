'use client';

import React from 'react';
import { AuditEntry, ChangeType } from '@/types/selection';

interface AuditLogTableProps {
  logs: AuditEntry[];
}

const AuditLogTable: React.FC<AuditLogTableProps> = ({ logs }) => {
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-[#262626]">
        <thead>
          <tr>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Change Type</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Previous Value</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">New Value</th>
            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Address</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[#262626]">
          {logs.map((log, index) => (
            <tr key={index} className="hover:bg-[#0f0f0f]">
              <td className="px-4 py-3 text-sm text-gray-400">{log.timestamp.toISOString()}</td>
              <td className="px-4 py-3 text-sm text-gray-400 capitalize">{log.changeType}</td>
              <td className="px-4 py-3 text-sm text-gray-400">{String(log.previousValue)}</td>
              <td className="px-4 py-3 text-sm text-gray-400">{String(log.newValue)}</td>
              <td className="px-4 py-3 text-sm text-gray-400">{log.ipAddress}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default AuditLogTable;