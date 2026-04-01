import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { api } from './api.ts';
import type { User } from './api.ts';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string, fullName?: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AUTH_HINT_KEY = 'jwp_auth';
const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  // If no auth hint exists, we know the user is logged out — skip loading state
  const [loading, setLoading] = useState(() => !!localStorage.getItem(AUTH_HINT_KEY));

  useEffect(() => {
    // Only call /user/me if there's a session hint — avoids 401 noise for guests
    if (!localStorage.getItem(AUTH_HINT_KEY)) return;

    api.getMe()
      .then(setUser)
      .catch(() => {
        setUser(null);
        localStorage.removeItem(AUTH_HINT_KEY);
      })
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    await api.login(email, password);
    localStorage.setItem(AUTH_HINT_KEY, '1');
    const me = await api.getMe();
    setUser(me);
  }, []);

  const signup = useCallback(async (email: string, password: string, fullName?: string) => {
    await api.signup(email, password, fullName);
    localStorage.setItem(AUTH_HINT_KEY, '1');
    const me = await api.getMe();
    setUser(me);
  }, []);

  const logout = useCallback(async () => {
    await api.logout().catch(() => {});
    localStorage.removeItem(AUTH_HINT_KEY);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, signup, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
