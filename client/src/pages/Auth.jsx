import { useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Shield, Lock, Key, Smartphone, ArrowLeft } from 'lucide-react';
import { toast } from 'sonner';

const Auth = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [keyType, setKeyType] = useState('ECC');
  const [isLoading, setIsLoading] = useState(false);
  const [totpCode, setTotpCode] = useState('');

  const { login, register, pendingLogin, complete2FALogin, cancelPendingLogin } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      if (isLogin) {
        const result = await login(username, password);
        if (result?.requires2FA) {
          toast.info('Please enter your 2FA code');
        } else {
          toast.success('Logged in successfully');
          navigate('/chat');
        }
      } else {
        await register(username, password, keyType);
        toast.success('Account created successfully');
        navigate('/chat');
      }
    } catch (error) {
      toast.error(error.response?.data?.error || error.message || 'Authentication failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handle2FASubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const result = await complete2FALogin(totpCode);
      if (result?.success) {
        toast.success('Logged in successfully');
        navigate('/chat');
      }
    } catch (error) {
      toast.error(error.response?.data?.error || error.message || '2FA verification failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCancel2FA = () => {
    cancelPendingLogin();
    setTotpCode('');
  };

  // Show 2FA verification form
  if (pendingLogin) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted p-4">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(14,165,233,0.1),transparent_50%)]" />

        <Card className="w-full max-w-md relative backdrop-blur-sm border-primary/20">
          <CardHeader className="text-center space-y-2">
            <div className="mx-auto w-16 h-16 rounded-2xl bg-gradient-to-br from-primary to-secondary flex items-center justify-center mb-2">
              <Smartphone className="w-8 h-8 text-primary-foreground" />
            </div>
            <CardTitle className="text-2xl font-bold">Two-Factor Authentication</CardTitle>
            <CardDescription className="text-base">
              Enter the 6-digit code from your authenticator app
            </CardDescription>
          </CardHeader>

          <CardContent>
            <form onSubmit={handle2FASubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="totp">Authentication Code</Label>
                <Input
                  id="totp"
                  type="text"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  required
                  maxLength={6}
                  className="bg-input border-border text-center text-2xl tracking-widest"
                  placeholder="000000"
                  autoComplete="one-time-code"
                />
              </div>

              <Button type="submit" className="w-full" disabled={isLoading || totpCode.length !== 6}>
                {isLoading ? 'Verifying...' : 'Verify'}
              </Button>

              <Button 
                type="button" 
                variant="ghost" 
                className="w-full" 
                onClick={handleCancel2FA}
              >
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back to Login
              </Button>
            </form>

            <div className="mt-4 p-3 bg-muted rounded-lg border border-border">
              <p className="text-xs text-muted-foreground text-center">
                You can also use a backup code if you don't have access to your authenticator
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted p-4">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(14,165,233,0.1),transparent_50%)]" />

      <Card className="w-full max-w-md relative backdrop-blur-sm border-primary/20">
        <CardHeader className="text-center space-y-2">
          <div className="mx-auto w-16 h-16 rounded-2xl bg-gradient-to-br from-primary to-secondary flex items-center justify-center mb-2">
            <Shield className="w-8 h-8 text-primary-foreground" />
          </div>
          <CardTitle className="text-3xl font-bold">SecureComm</CardTitle>
          <CardDescription className="text-base">
            End-to-End Encrypted Messaging System
          </CardDescription>
        </CardHeader>

        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="bg-input border-border"
                placeholder="Enter your username"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="bg-input border-border"
                placeholder="Enter your password"
              />
            </div>

            {!isLogin && (
              <div className="space-y-2">
                <Label>Encryption Key Type</Label>
                <div className="flex gap-3">
                  <Button
                    type="button"
                    variant={keyType === 'ECC' ? 'default' : 'outline'}
                    onClick={() => setKeyType('ECC')}
                    className="flex-1"
                  >
                    <Key className="w-4 h-4 mr-2" />
                    ECC P-256
                  </Button>
                  <Button
                    type="button"
                    variant={keyType === 'RSA' ? 'default' : 'outline'}
                    onClick={() => setKeyType('RSA')}
                    className="flex-1"
                  >
                    <Lock className="w-4 h-4 mr-2" />
                    RSA-2048
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {keyType === 'ECC' ? 'Elliptic Curve (faster, smaller keys)' : 'RSA (traditional, widely supported)'}
                </p>
              </div>
            )}

            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? 'Loading...' : (isLogin ? 'Login' : 'Create Account')}
            </Button>
          </form>

          <div className="mt-6 text-center">
            <button
              type="button"
              onClick={() => setIsLogin(!isLogin)}
              className="text-sm text-primary hover:underline"
            >
              {isLogin ? "Don't have an account? Register" : 'Already have an account? Login'}
            </button>
          </div>

          <div className="mt-6 p-3 bg-muted rounded-lg border border-border">
            <p className="text-xs text-muted-foreground text-center">
              Your private keys are generated and stored only on your device using Web Crypto API + IndexedDB
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Auth;