import '@/styles/globals.css';
import { AuthProvider } from '@/providers/AuthProvider';

export const metadata = {
  title: 'QuantumIQ',
  description: 'Production SaaS Platform',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-black text-white">
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
