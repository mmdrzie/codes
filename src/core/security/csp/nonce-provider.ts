import { createContext, useContext, ReactNode } from 'react';
import { generateNonce } from '../csp-middleware';

// Create a context for the nonce
const NonceContext = createContext<string>('');

// Provider component to wrap the application
interface NonceProviderProps {
  children: ReactNode;
}

export const NonceProvider = ({ children }: NonceProviderProps) => {
  const nonce = generateNonce();
  
  return (
    <NonceContext.Provider value={nonce}>
      {children}
    </NonceContext.Provider>
  );
};

// Hook to use the nonce in components
export const useNonce = () => {
  const nonce = useContext(NonceContext);
  if (nonce === undefined) {
    throw new Error('useNonce must be used within a NonceProvider');
  }
  return nonce;
};

// Helper function to validate a nonce
export const validateNonce = (providedNonce: string, expectedNonce: string): boolean => {
  // In a real implementation, you'd want to use a constant-time comparison
  // to prevent timing attacks
  return providedNonce === expectedNonce;
};

// Function to generate a nonce script tag for HTML injection
export const generateNonceScriptTag = (scriptContent: string, nonce: string): string => {
  return `<script nonce="${nonce}">${scriptContent}</script>`;
};