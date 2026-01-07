import Link from 'next/link';
import { ROLE_PERMISSIONS } from '@/config/permissions';
import { SIDEBAR_ITEMS } from '@/components/layout/sidebarConfig';
import { useAuth } from '@/features/auth';

/**
 * Legacy Sidebar path kept to avoid breaking existing imports.
 * Prefer using `src/components/layout/Sidebar.tsx`.
 */
export default function Sidebar() {
  const { user, logout } = useAuth();
  const allowed = ROLE_PERMISSIONS[user?.role || 'user'] ?? [];

  return (
    <aside>
      {SIDEBAR_ITEMS
        .filter((item) => allowed.includes(item.key))
        .map((item) => (
          <Link key={item.key} href={item.href}>
            {item.label}
          </Link>
        ))}
      <button onClick={logout}>Logout</button>
    </aside>
  );
}
