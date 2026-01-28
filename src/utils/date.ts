/**
 * Format a date to ISO 8601 format with milliseconds for display
 */
export function formatDate(date: Date): string {
  // Format to ISO string but make it more readable
  return date.toISOString().replace('T', ' ').substring(0, 19) + '.' + 
         String(date.getMilliseconds()).padStart(3, '0') + 'Z';
}

/**
 * Format a date to a more human-readable form while maintaining precision
 */
export function formatDateTime(date: Date): string {
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short'
  });
}

/**
 * Parse an ISO date string back to a Date object
 */
export function parseDate(dateStr: string): Date {
  return new Date(dateStr);
}

/**
 * Calculate time difference in human-readable format
 */
export function timeAgo(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  
  if (diffSecs < 60) return `${diffSecs}s ago`;
  const diffMins = Math.floor(diffSecs / 60);
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}