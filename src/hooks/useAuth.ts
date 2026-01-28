'use client';

import { useState, useEffect, useContext, createContext, ReactNode } from 'react';
import { AuthUser } from '@/types/auth';

// Define the shape of our auth context
interface AuthContextType {
  user: {
    id: string;
    username: string; // Derived from either Firebase displayName or Web3 address
    email?: string;
  } | null;
  loading: boolean;
}

// Create the auth context
const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
});

// Mock authentication provider for demonstration purposes
// In a real app, this would connect to actual authentication services
const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<AuthContextType['user']>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Simulate checking for existing session
    const checkSession = async () => {
      try {
        // In a real app, this would check for valid tokens, sessions, etc.
        // For now, we'll simulate retrieving user data from a session
        
        // Simulate API call delay
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Check if user is logged in (this would check actual session/tokens in real app)
        const mockUserData = localStorage.getItem('mock-user');
        
        if (mockUserData) {
          const parsedUser = JSON.parse(mockUserData);
          setUser({
            id: parsedUser.id,
            username: parsedUser.username || parsedUser.email?.split('@')[0] || 'user',
            email: parsedUser.email
          });
        }
      } catch (error) {
        console.error('Error checking session:', error);
      } finally {
        setLoading(false);
      }
    };

    checkSession();
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook to use auth context
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Helper function to get derived username from AuthUser
export const getUsernameFromAuthUser = (authUser: AuthUser): string => {
  if (authUser.firebaseUser?.displayName) {
    return authUser.firebaseUser.displayName;
  }
  
  if (authUser.web3User?.address) {
    // Return shortened address as username
    return `${authUser.web3User.address.substring(0, 6)}...${authUser.web3User.address.substring(authUser.web3User.address.length - 4)}`;
  }
  
  if (authUser.firebaseUser?.email) {
    return authUser.firebaseUser.email.split('@')[0];
  }
  
  return 'user';
};

export { AuthContext, AuthProvider };