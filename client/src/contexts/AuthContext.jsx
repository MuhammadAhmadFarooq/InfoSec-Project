import { createContext, useContext, useState, useEffect } from 'react';
import { authAPI } from '@/lib/api';
import { generateKeyPair, exportPublicKey } from '@/lib/crypto';
import { storePrivateKey, getPrivateKey, logSecurityEvent } from '@/lib/storage';

const AuthContext = createContext(undefined);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [pendingLogin, setPendingLogin] = useState(null); // For 2FA flow

  useEffect(() => {
    const t = localStorage.getItem('token');
    const u = localStorage.getItem('user');
    if (t && u) {
      setToken(t);
      setUser(JSON.parse(u));
    }
    setIsLoading(false);
  }, []);

  const register = async (username, password, keyType = 'ECC') => {
    const keys = await generateKeyPair(keyType);
    const publicKeyPem = await exportPublicKey(keys.publicKey);

    const res = await authAPI.register(username, password, publicKeyPem, keyType);

    // Store all keys including signing keys for ECC
    await storePrivateKey(res.user.id, { 
      privateKey: keys.privateKey, 
      publicKey: keys.publicKey, 
      signingKey: keys.signingKey,
      verifyKey: keys.verifyKey,
      keyType 
    });

    setToken(res.token);
    setUser(res.user);
    localStorage.setItem('token', res.token);
    localStorage.setItem('user', JSON.stringify(res.user));

    await logSecurityEvent({ type: 'auth', message: `Registered: ${username}` });
  };

  const login = async (username, password, totpCode = null) => {
    const res = await authAPI.login(username, password, totpCode);

    // Check if 2FA is required
    if (res.requires2FA) {
      setPendingLogin({ username, password });
      return { requires2FA: true };
    }

    // Complete login
    const keys = await getPrivateKey(res.user.id);
    if (!keys) throw new Error('No private key found on this device');

    setToken(res.token);
    setUser(res.user);
    setPendingLogin(null);
    localStorage.setItem('token', res.token);
    localStorage.setItem('user', JSON.stringify(res.user));

    await logSecurityEvent({ type: 'auth', message: `Logged in: ${username}` });
    return { success: true };
  };

  const complete2FALogin = async (totpCode) => {
    if (!pendingLogin) throw new Error('No pending login');
    return login(pendingLogin.username, pendingLogin.password, totpCode);
  };

  const cancelPendingLogin = () => {
    setPendingLogin(null);
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    setPendingLogin(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  };

  return (
    <AuthContext.Provider value={{ 
      user, 
      token, 
      login, 
      register, 
      logout, 
      isLoading,
      pendingLogin,
      complete2FALogin,
      cancelPendingLogin
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth used outside provider');
  return ctx;
};