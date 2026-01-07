export const ROLE_PERMISSIONS: Record<string, string[]> = {
  admin: [
    'dashboard',
    'analysis',
    'settings',
    'community',
    'news',
  ],
  user: [
    'dashboard',
    'chat',
    'charts',
    'selection',
  ],
};
