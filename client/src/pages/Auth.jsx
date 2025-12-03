import { useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Shield, Lock, Key, Smartphone, ArrowLeft, Sparkles, Zap } from 'lucide-react';
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
      <div className="min-h-screen flex items-center justify-center p-4 relative overflow-hidden">
        {/* Animated background */}
        <div className="absolute inset-0 bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,hsl(152_70%_45%/0.1),transparent_50%)]" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_right,hsl(160_50%_35%/0.08),transparent_50%)]" />
        
        {/* Floating orbs */}
        <div className="absolute top-20 left-20 w-72 h-72 bg-green-500/10 rounded-full blur-3xl animate-float" />
        <div className="absolute bottom-20 right-20 w-96 h-96 bg-green-600/5 rounded-full blur-3xl animate-float" style={{ animationDelay: '1s' }} />

        <Card className="w-full max-w-md relative glass glow-border animate-scale-in">
          <CardHeader className="text-center space-y-4">
            <div className="mx-auto w-20 h-20 rounded-2xl bg-gradient-to-br from-green-500 to-green-600 flex items-center justify-center animate-pulse-glow">
              <Smartphone className="w-10 h-10 text-gray-900" />
            </div>
            <CardTitle className="text-2xl font-bold bg-gradient-to-r from-green-400 to-green-500 bg-clip-text text-transparent">
              Two-Factor Authentication
            </CardTitle>
            <CardDescription className="text-gray-400">
              Enter the 6-digit code from your authenticator app
            </CardDescription>
          </CardHeader>

          <CardContent>
            <form onSubmit={handle2FASubmit} className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="totp" className="text-gray-300">Authentication Code</Label>
                <Input
                  id="totp"
                  type="text"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replaceAll(/\D/g, '').slice(0, 6))}
                  required
                  maxLength={6}
                  className="bg-gray-800/50 border-gray-700 text-center text-3xl tracking-[0.5em] font-mono h-14 input-glow focus:border-green-500/50 transition-all duration-300"
                  placeholder="••••••"
                  autoComplete="one-time-code"
                />
              </div>

              <Button 
                type="submit" 
                className="w-full h-12 btn-primary-glow text-gray-900 font-semibold text-base" 
                disabled={isLoading || totpCode.length !== 6}
              >
                {isLoading ? (
                  <span className="flex items-center gap-2">
                    <div className="w-5 h-5 border-2 border-gray-900/30 border-t-gray-900 rounded-full animate-spin" />
                    Verifying...
                  </span>
                ) : (
                  <span className="flex items-center gap-2">
                    <Shield className="w-5 h-5" />
                    Verify & Login
                  </span>
                )}
              </Button>

              <Button 
                type="button" 
                variant="ghost" 
                className="w-full text-gray-400 hover:text-green-400 hover:bg-gray-800/50 transition-all duration-300" 
                onClick={handleCancel2FA}
              >
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back to Login
              </Button>
            </form>

            <div className="mt-6 p-4 bg-gray-800/30 rounded-xl border border-gray-700/50">
              <p className="text-xs text-gray-500 text-center">
                💡 You can also use a backup code if you don't have access to your authenticator
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative overflow-hidden">
      {/* Animated background */}
      <div className="absolute inset-0 bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,hsl(152_70%_45%/0.1),transparent_50%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_right,hsl(160_50%_35%/0.08),transparent_50%)]" />
      
      {/* Grid pattern */}
      <div className="absolute inset-0 bg-[linear-gradient(hsl(152_70%_45%/0.03)_1px,transparent_1px),linear-gradient(90deg,hsl(152_70%_45%/0.03)_1px,transparent_1px)] bg-[size:50px_50px]" />
      
      {/* Floating orbs */}
      <div className="absolute top-10 left-10 w-72 h-72 bg-green-500/10 rounded-full blur-3xl animate-float" />
      <div className="absolute bottom-10 right-10 w-96 h-96 bg-green-600/5 rounded-full blur-3xl animate-float" style={{ animationDelay: '1.5s' }} />
      <div className="absolute top-1/2 left-1/4 w-48 h-48 bg-green-400/5 rounded-full blur-2xl animate-float" style={{ animationDelay: '0.5s' }} />

      <Card className="w-full max-w-md relative glass glow-border animate-scale-in">
        <CardHeader className="text-center space-y-4 pb-2">
          <div className="mx-auto w-24 h-24 rounded-3xl bg-gradient-to-br from-green-500 to-green-600 flex items-center justify-center animate-pulse-glow shadow-lg shadow-green-500/20">
            <Shield className="w-12 h-12 text-gray-900" />
          </div>
          <div className="space-y-2">
            <CardTitle className="text-4xl font-bold bg-gradient-to-r from-green-400 via-green-500 to-green-400 bg-clip-text text-transparent animate-gradient bg-[length:200%_auto]">
              SecureComm
            </CardTitle>
            <CardDescription className="text-gray-400 flex items-center justify-center gap-2">
              <Lock className="w-4 h-4 text-green-500" />
              End-to-End Encrypted Messaging
            </CardDescription>
          </div>
        </CardHeader>

        <CardContent className="pt-6">
          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2 animate-slide-up" style={{ animationDelay: '0.1s' }}>
              <Label htmlFor="username" className="text-gray-300 flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-green-500" />
                Username
              </Label>
              <Input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="bg-gray-800/50 border-gray-700 h-12 input-glow focus:border-green-500/50 transition-all duration-300 placeholder:text-gray-600"
                placeholder="Enter your username"
              />
            </div>

            <div className="space-y-2 animate-slide-up" style={{ animationDelay: '0.2s' }}>
              <Label htmlFor="password" className="text-gray-300 flex items-center gap-2">
                <Lock className="w-4 h-4 text-green-500" />
                Password
              </Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="bg-gray-800/50 border-gray-700 h-12 input-glow focus:border-green-500/50 transition-all duration-300 placeholder:text-gray-600"
                placeholder="Enter your password"
              />
            </div>

            {!isLogin && (
              <div className="space-y-3 animate-slide-up" style={{ animationDelay: '0.3s' }}>
                <Label className="text-gray-300 flex items-center gap-2">
                  <Key className="w-4 h-4 text-green-500" />
                  Encryption Key Type
                </Label>
                <div className="flex gap-3">
                  <Button
                    type="button"
                    variant={keyType === 'ECC' ? 'default' : 'outline'}
                    onClick={() => setKeyType('ECC')}
                    className={`flex-1 h-12 transition-all duration-300 ${
                      keyType === 'ECC' 
                        ? 'btn-primary-glow text-gray-900 font-semibold' 
                        : 'bg-gray-800/50 border-gray-700 hover:border-green-500/50 hover:bg-gray-800'
                    }`}
                  >
                    <Zap className="w-4 h-4 mr-2" />
                    ECC P-256
                  </Button>
                  <Button
                    type="button"
                    variant={keyType === 'RSA' ? 'default' : 'outline'}
                    onClick={() => setKeyType('RSA')}
                    className={`flex-1 h-12 transition-all duration-300 ${
                      keyType === 'RSA' 
                        ? 'btn-primary-glow text-gray-900 font-semibold' 
                        : 'bg-gray-800/50 border-gray-700 hover:border-green-500/50 hover:bg-gray-800'
                    }`}
                  >
                    <Lock className="w-4 h-4 mr-2" />
                    RSA-2048
                  </Button>
                </div>
                <p className="text-xs text-gray-500 flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                  {keyType === 'ECC' ? 'Elliptic Curve — faster, smaller keys, modern' : 'RSA — traditional, widely supported'}
                </p>
              </div>
            )}

            <Button 
              type="submit" 
              className="w-full h-12 btn-primary-glow text-gray-900 font-semibold text-base animate-slide-up mt-6" 
              style={{ animationDelay: '0.4s' }}
              disabled={isLoading}
            >
              {isLoading ? (
                <span className="flex items-center gap-2">
                  <div className="w-5 h-5 border-2 border-gray-900/30 border-t-gray-900 rounded-full animate-spin" />
                  {isLogin ? 'Logging in...' : 'Creating Account...'}
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <Shield className="w-5 h-5" />
                  {isLogin ? 'Secure Login' : 'Create Secure Account'}
                </span>
              )}
            </Button>
          </form>

          <div className="mt-6 text-center animate-fade-in" style={{ animationDelay: '0.5s' }}>
            <button
              type="button"
              onClick={() => setIsLogin(!isLogin)}
              className="text-sm text-gray-400 hover:text-green-400 transition-colors duration-300 group"
            >
              {isLogin ? (
                <>Don't have an account? <span className="text-green-500 group-hover:underline">Register</span></>
              ) : (
                <>Already have an account? <span className="text-green-500 group-hover:underline">Login</span></>
              )}
            </button>
          </div>

          <div className="mt-6 p-4 bg-gray-800/30 rounded-xl border border-gray-700/50 animate-slide-up" style={{ animationDelay: '0.6s' }}>
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 rounded-lg bg-green-500/10 flex items-center justify-center flex-shrink-0">
                <Lock className="w-4 h-4 text-green-500" />
              </div>
              <p className="text-xs text-gray-500 leading-relaxed">
                Your private keys are generated and stored <span className="text-green-500">only on your device</span> using Web Crypto API + IndexedDB. We never have access to your keys.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Auth;