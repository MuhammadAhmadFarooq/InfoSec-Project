// src/pages/Chat.jsx
import { useState, useEffect, useRef } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { userAPI, messageAPI, fileAPI, keyExchangeAPI, authAPI } from '@/lib/api';
import { io } from 'socket.io-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Send, Upload, Shield, LogOut, Lock, Key, AlertCircle, CheckCircle2, FileText, Download, Settings, Smartphone, Copy, Check } from 'lucide-react';
import { toast } from 'sonner';
import {
  encryptMessage,
  decryptMessage,
  deriveSharedSecret,
  importPublicKey,
  generateKeyPair,
  exportPublicKey,
  signData,
  verifySignature,
  generateKeyConfirmation,
  encryptFileChunk,
  decryptFileChunk,
  isReplayAttack,
} from '@/lib/crypto';
import {
  getPrivateKey,
  getSessionKey,
  storeSessionKey,
  deleteSessionKey,
  logSecurityEvent,
  getSequenceNumber,
  storeSequenceNumber,
  getSecurityLogs,
} from '@/lib/storage';

// Helper function to format message timestamps
const formatMessageTime = (timestamp) => {
  if (!timestamp) return '';
  const date = new Date(timestamp);
  const now = new Date();
  const isToday = date.toDateString() === now.toDateString();
  
  if (isToday) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  
  // If within the last week, show day name
  const daysDiff = Math.floor((now - date) / (1000 * 60 * 60 * 24));
  if (daysDiff < 7) {
    return date.toLocaleDateString([], { weekday: 'short' }) + ' ' + 
           date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  
  // Otherwise show full date
  return date.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' +
         date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

const Chat = () => {
  const { user, logout } = useAuth();
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [messages, setMessages] = useState([]);
  const [messageInput, setMessageInput] = useState('');
  const [socket, setSocket] = useState(null);
  const [sessionKey, setSessionKey] = useState(null);
  const [sequenceNum, setSequenceNum] = useState(1);
  const [isKeyExchanged, setIsKeyExchanged] = useState(false);
  const [showLogs, setShowLogs] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const scrollRef = useRef(null);
  const fileInputRef = useRef(null);
  
  // 2FA state
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false);
  const [setupData, setSetupData] = useState(null);
  const [verifyCode, setVerifyCode] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [disablePassword, setDisablePassword] = useState('');
  const [backupCodes, setBackupCodes] = useState([]);
  const [copiedSecret, setCopiedSecret] = useState(false);
  
  // Refs to avoid stale closures in socket handlers
  const selectedUserRef = useRef(null);
  const sessionKeyRef = useRef(null);

  // Keep refs in sync with state for socket handlers
  useEffect(() => {
    selectedUserRef.current = selectedUser;
  }, [selectedUser]);
  
  useEffect(() => {
    sessionKeyRef.current = sessionKey;
  }, [sessionKey]);

  useEffect(() => {
    loadUsers();
    connectSocket();
    checkPendingKeyExchanges(); // Check for incoming key exchange requests
    
    // Periodically check for new key exchange requests
    const interval = setInterval(checkPendingKeyExchanges, 5000);

    return () => {
      socket?.disconnect();
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Load 2FA status when settings open
  useEffect(() => {
    if (showSettings) {
      load2FAStatus();
    }
  }, [showSettings]);

  const load2FAStatus = async () => {
    try {
      const status = await authAPI.get2FAStatus();
      setTwoFactorEnabled(status.twoFactorEnabled);
    } catch (err) {
      console.error('Failed to load 2FA status:', err);
    }
  };

  const startSetup2FA = async () => {
    try {
      const data = await authAPI.setup2FA();
      setSetupData(data);
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to setup 2FA');
    }
  };

  const verifyAndEnable2FA = async () => {
    try {
      const result = await authAPI.verify2FA(verifyCode);
      setBackupCodes(result.backupCodes);
      setTwoFactorEnabled(true);
      setSetupData(null);
      setVerifyCode('');
      toast.success('2FA enabled successfully!');
      logSecurityEvent({ type: '2fa_enabled', message: '2FA was enabled for this account' });
    } catch (err) {
      toast.error(err.response?.data?.error || 'Invalid verification code');
    }
  };

  const disable2FA = async () => {
    try {
      await authAPI.disable2FA(disableCode, disablePassword);
      setTwoFactorEnabled(false);
      setDisableCode('');
      setDisablePassword('');
      toast.success('2FA disabled');
      logSecurityEvent({ type: '2fa_disabled', message: '2FA was disabled for this account' });
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to disable 2FA');
    }
  };

  const copySecret = () => {
    if (setupData?.secret) {
      navigator.clipboard.writeText(setupData.secret);
      setCopiedSecret(true);
      setTimeout(() => setCopiedSecret(false), 2000);
    }
  };

  const connectSocket = () => {
    const newSocket = io('http://localhost:5000', {
      auth: { token: localStorage.getItem('token') },
    });

    newSocket.on('connect', () => {
      logSecurityEvent({ type: 'socket', message: 'Connected to server' });
    });

    newSocket.on('new-message', async (data) => {
      // Handle messages regardless of current selected user
      await handleIncomingMessage(data);
    });

    newSocket.on('message-error', (err) => {
      toast.error('Message rejected: ' + err.error);
      logSecurityEvent({ type: 'replay_detected', message: err.error });
    });

    setSocket(newSocket);
  };

  const loadUsers = async () => {
    try {
      const fetched = await userAPI.getAllUsers();
      setUsers(fetched.filter(u => u.id !== user.id && u.username));
    } catch (err) {
      toast.error('Failed to load users');
    }
  };

  const initiateKeyExchange = async (partner) => {
    try {
      // Clear any stale session key before initiating new exchange
      await deleteSessionKey(partner.id);
      
      const myKeys = await getPrivateKey(user.id);
      const { publicKey: ephemPub, privateKey: ephemPriv, signingKey: ephemSigningKey } = await generateKeyPair('ECC');
      const ephemPubPem = await exportPublicKey(ephemPub);
      
      // Use stored signingKey if available, otherwise use ephemeral one
      let signature = 'none';
      try {
        const signKey = myKeys?.signingKey || ephemSigningKey;
        if (signKey) {
          signature = await signData(signKey, `${user.id}${partner.id}${ephemPubPem}`);
        }
      } catch (signErr) {
        console.warn('Signing failed, continuing without signature:', signErr);
      }

      console.log('Initiating key exchange with:', partner.username);
      const { exchangeId } = await keyExchangeAPI.initiate(partner.id, ephemPubPem, signature);
      console.log('Key exchange initiated, exchangeId:', exchangeId);

      toast.loading('Waiting for key exchange...', { id: 'keyex' });

      const check = setInterval(async () => {
        // First check if a session key was established by responding to the other user's exchange
        const existingKey = await getSessionKey(partner.id);
        if (existingKey) {
          clearInterval(check);
          toast.dismiss('keyex');
          toast.success('Secure channel established!');
          setSessionKey(existingKey);
          setIsKeyExchanged(true);
          const seq = (await getSequenceNumber(partner.id)) || 0;
          setSequenceNum(seq + 1);
          // Load messages with the existing key
          try {
            const history = await messageAPI.getConversation(partner.id);
            const decrypted = await Promise.all(history.map(async (m) => {
              try {
                const text = await decryptMessage(m, existingKey);
                return { ...m, text, isMine: m.sender === user.id, fileId: m.fileId };
              } catch {
                return { ...m, text: '[Decryption failed]', isMine: m.sender === user.id };
              }
            }));
            setMessages(decrypted);
          } catch (err) {
            console.error('Failed to load messages:', err);
          }
          return;
        }
        
        // Otherwise check if our initiated exchange was completed
        const initiated = await keyExchangeAPI.getInitiated();
        const done = initiated.find(e => e._id === exchangeId && e.status === 'completed');
        if (done) {
          clearInterval(check);
          toast.dismiss('keyex');
          toast.success('Secure channel established!');
          await completeKeyExchange(done, ephemPriv, partner);
        }
      }, 2000);
    } catch (err) {
      console.error('Key exchange failed:', err);
      toast.error('Key exchange failed');
    }
  };

  const completeKeyExchange = async (exchange, myEphemPriv, partner) => {
    try {
      const partnerEphemPub = await importPublicKey(exchange.responderEphemeralKey);
      const sharedKey = await deriveSharedSecret(myEphemPriv, partnerEphemPub);

      // Ensure consistent string ID
      const partnerId = String(partner.id);
      
      await storeSessionKey(partnerId, sharedKey);
      setSessionKey(sharedKey);
      setIsKeyExchanged(true);
      const seq = (await getSequenceNumber(partnerId)) || 0;
      setSequenceNum(seq + 1);

      // Send key confirmation to prove we derived the correct key
      try {
        const confirmation = await generateKeyConfirmation(sharedKey, user.id, partnerId);
        await keyExchangeAPI.confirm(exchange._id, confirmation);
        logSecurityEvent({ 
          type: 'key_confirmed', 
          message: `Key confirmation sent for session with ${partner.username}` 
        });
      } catch (confirmErr) {
        console.warn('Key confirmation failed:', confirmErr);
      }

      logSecurityEvent({ type: 'key_exchange', message: `Session established with ${partner.username}` });
      
      // Load message history now that we have the key
      try {
        const history = await messageAPI.getConversation(partner.id);
        const decrypted = await Promise.all(history.map(async (m) => {
          try {
            const text = await decryptMessage(m, sharedKey);
            return { ...m, text, isMine: m.sender === user.id, fileId: m.fileId };
          } catch {
            return { ...m, text: '[Decryption failed]', isMine: m.sender === user.id };
          }
        }));
        setMessages(decrypted);
      } catch (err) {
        console.error('Failed to load messages after key exchange:', err);
      }
    } catch (err) {
      console.error('Failed to complete key exchange:', err);
      toast.error('Failed to derive key');
    }
  };

  const checkPendingKeyExchanges = async () => {
    try {
      const pending = await keyExchangeAPI.getPending();
      console.log('Pending key exchanges:', pending.length);
      
      for (const exchange of pending) {
        if (exchange.status === 'pending') {
          // Convert ObjectId to string for consistent key storage
          const initiatorId = String(exchange.initiator._id);
          console.log('Processing key exchange from:', exchange.initiator.username, 'initiatorId:', initiatorId);
          
          // Delete any existing stale session key - a new exchange means we need a fresh key
          await deleteSessionKey(initiatorId);
          console.log('Cleared old session key for', initiatorId);
          
          // Auto-respond to key exchange
          const myKeys = await getPrivateKey(user.id);
          const { publicKey: ephemPub, privateKey: ephemPriv, signingKey: ephemSigningKey } = await generateKeyPair('ECC');
          const ephemPubPem = await exportPublicKey(ephemPub);
          
          // Use stored signingKey if available, otherwise use ephemeral one
          let signature = 'none';
          try {
            const signKey = myKeys?.signingKey || ephemSigningKey;
            if (signKey) {
              signature = await signData(signKey, `${user.id}${initiatorId}${ephemPubPem}`);
            }
          } catch (signErr) {
            console.warn('Signing failed, continuing without signature:', signErr);
          }
          
          await keyExchangeAPI.respond(exchange._id, ephemPubPem, signature);
          console.log('Responded to key exchange:', exchange._id);
          
          // Derive shared secret using HKDF
          const initiatorEphemPub = await importPublicKey(exchange.initiatorEphemeralKey);
          const sharedKey = await deriveSharedSecret(ephemPriv, initiatorEphemPub);
          console.log('Derived shared key for session with:', exchange.initiator.username);
          
          // Store with string ID for consistency
          await storeSessionKey(initiatorId, sharedKey);
          
          // Send key confirmation
          try {
            const confirmation = await generateKeyConfirmation(sharedKey, user.id, initiatorId);
            await keyExchangeAPI.confirm(exchange._id, confirmation);
            logSecurityEvent({ 
              type: 'key_confirmed', 
              message: `Key confirmation sent for session with ${exchange.initiator.username}` 
            });
          } catch (confirmErr) {
            console.warn('Key confirmation failed:', confirmErr);
          }
          
          logSecurityEvent({ 
            type: 'key_exchange_response', 
            message: `Responded to key exchange from ${exchange.initiator.username}` 
          });
          
          toast.success(`Secure channel established with ${exchange.initiator.username}`);
        }
      }
    } catch (err) {
      console.error('Failed to check pending key exchanges:', err);
    }
  };

  const handleUserSelect = async (selected) => {
    setSelectedUser(selected);
    setMessages([]);
    setIsKeyExchanged(false);

    // Check if we already have a session key
    const key = await getSessionKey(selected.id);
    if (key) {
      setSessionKey(key);
      setIsKeyExchanged(true);
      const seq = (await getSequenceNumber(selected.id)) || 0;
      setSequenceNum(seq + 1);
      
      // Load message history only when we have a key
      try {
        const history = await messageAPI.getConversation(selected.id);
        const decrypted = await Promise.all(history.map(async (m) => {
          try {
            const text = await decryptMessage(m, key);
            return { ...m, text, isMine: m.sender === user.id, fileId: m.fileId };
          } catch {
            return { ...m, text: '[Decryption failed]', isMine: m.sender === user.id };
          }
        }));
        setMessages(decrypted);
      } catch (err) {
        console.error('Failed to load messages:', err);
      }
    } else {
      // No existing key, need to do key exchange
      toast.info('Starting secure connection...');
      await initiateKeyExchange(selected);
    }
  };

  const sendMessage = async () => {
    if (!messageInput.trim() || !socket) return;
    
    // Use stored session key for consistency
    const partnerId = String(selectedUser.id);
    const messageKey = await getSessionKey(partnerId);
    
    if (!messageKey) {
      toast.error('No secure connection - please wait for key exchange');
      return;
    }

    const { encryptedMessage, iv, tag } = await encryptMessage(messageInput, messageKey);
    const payload = {
      receiverId: selectedUser.id,
      encryptedMessage,
      iv,
      tag,
      timestamp: Date.now(),
      sequenceNumber: sequenceNum,
    };

    socket.emit('send-message', payload);

    setMessages(prev => [...prev, {
      text: messageInput,
      isMine: true,
      timestamp: payload.timestamp,
    }]);

    await storeSequenceNumber(partnerId, sequenceNum);
    setSequenceNum(n => n + 1);
    setMessageInput('');
    logSecurityEvent({ type: 'message_sent', message: `To ${selectedUser.username}` });
  };

  const handleIncomingMessage = async (data) => {
    try {
      // Get the session key for the sender from storage (not from state to avoid stale values)
      const senderSessionKey = await getSessionKey(data.sender);
      
      if (!senderSessionKey) {
        // No session key for sender - skip decryption
        return;
      }

      const isReplay = await isReplayAttack(data.sender, data.sequenceNumber, data.timestamp, getSequenceNumber, logSecurityEvent);
      if (isReplay) {
        toast.error("Replay attack detected & blocked!");
        return;
      }

      // Update sequence number
      await storeSequenceNumber(data.sender, data.sequenceNumber);
      
      const text = await decryptMessage(data, senderSessionKey);
      
      // Use ref to get current selectedUser (avoids stale closure)
      const currentSelectedUser = selectedUserRef.current;
      
      // Only update messages if this is from the currently selected user
      if (currentSelectedUser && data.sender === currentSelectedUser.id) {
        setMessages(prev => [...prev, { text, isMine: false, timestamp: data.timestamp, fileId: data.fileId }]);
        logSecurityEvent({ type: 'message_received', message: `From ${currentSelectedUser.username}` });
      } else {
        // Message from another user - show notification
        toast.info(`New message from another user`);
        logSecurityEvent({ type: 'message_received', message: `From user ${data.sender} (not in current chat)` });
      }
    } catch (err) {
      console.error('Decrypt error:', err);
      logSecurityEvent({ type: 'decrypt_fail', message: 'Failed to decrypt message' });
    }
  };

  const handleFileSelect = async (e) => {
    const file = e.target.files[0];
    if (!file || !sessionKey) return;

    try {
      toast.loading('Encrypting and uploading file...', { id: 'file-upload' });
      
      const arrayBuffer = await file.arrayBuffer();
      const chunkSize = 1024 * 1024; // 1MB
      const chunks = [];

      // Use stored session key for consistency with decryption
      const selectedPartnerId = String(selectedUser.id);
      const encryptionKey = await getSessionKey(selectedPartnerId);
      
      if (!encryptionKey) {
        throw new Error('No session key available for encryption');
      }

      for (let i = 0; i < arrayBuffer.byteLength; i += chunkSize) {
        const chunk = arrayBuffer.slice(i, i + chunkSize);
        const { encryptedData, iv, tag } = await encryptFileChunk(new Uint8Array(chunk), encryptionKey);
        chunks.push({ encryptedData, iv, tag });
      }

      const fileId = crypto.randomUUID();
      
      await Promise.all(chunks.map((c, i) =>
        fileAPI.uploadChunk({
          fileId,
          chunkIndex: i,
          encryptedChunk: c.encryptedData,
          iv: c.iv,
          tag: c.tag,
          totalChunks: chunks.length,
          filename: file.name,
          mimeType: file.type,
        })
      ));

      const fileMessage = `[File: ${file.name}]`;
      const { encryptedMessage, iv, tag } = await encryptMessage(fileMessage, encryptionKey);
      socket.emit('send-message', {
        receiverId: selectedUser.id,
        encryptedMessage,
        iv,
        tag,
        timestamp: Date.now(),
        sequenceNumber: sequenceNum,
        fileId,
      });

      setMessages(prev => [...prev, { text: fileMessage, isMine: true, fileId, timestamp: Date.now() }]);
      await storeSequenceNumber(selectedUser.id, sequenceNum);
      setSequenceNum(n => n + 1);
      
      toast.dismiss('file-upload');
      toast.success('File sent securely!');
      
      logSecurityEvent({ 
        type: 'file_upload', 
        message: `Encrypted ${file.name} with ${chunks.length} chunks`,
        details: { fileId, filename: file.name }
      });
    } catch (err) {
      console.error('File upload error:', err);
      toast.dismiss('file-upload');
      toast.error('Failed to send file');
    }
  };

  const downloadAndDecryptFile = async (fileId) => {
    try {
      // Get current selected user from ref to avoid stale closures
      const currentSelectedUser = selectedUserRef.current;
      
      if (!currentSelectedUser) {
        throw new Error('No user selected');
      }
      
      // Get session key from storage (more reliable than state)
      const partnerId = String(currentSelectedUser.id);
      const storedSessionKey = await getSessionKey(partnerId);
      
      if (!storedSessionKey) {
        throw new Error('No session key available - please ensure secure connection is established');
      }
      
      toast.loading('Downloading and decrypting file...', { id: 'file-download' });
      
      const res = await fileAPI.downloadFile(fileId);
      
      if (!res || !res.chunks || res.chunks.length === 0) {
        throw new Error('No file chunks found');
      }
      
      const chunks = res.chunks.sort((a, b) => a.chunkIndex - b.chunkIndex);
      
      const decryptedChunks = [];
      for (let index = 0; index < chunks.length; index++) {
        const c = chunks[index];
        try {
          const decrypted = await decryptFileChunk({
            encryptedData: c.encryptedChunk,
            iv: c.iv,
            tag: c.tag
          }, storedSessionKey);
          decryptedChunks.push(decrypted);
        } catch (err) {
          throw new Error(
            `Chunk ${index + 1} decryption failed. This file may have been encrypted with a different session key. ` +
            `Try re-establishing the secure connection or ask the sender to resend the file.`
          );
        }
      }
      
      const blob = new Blob(decryptedChunks, { type: res.mimeType || 'application/octet-stream' });
      
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = res.filename || 'download';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      toast.dismiss('file-download');
      toast.success('File decrypted & downloaded!');
      logSecurityEvent({ type: 'file_download', message: `Downloaded ${res.filename}` });
    } catch (err) {
      toast.dismiss('file-download');
      toast.error(err.message || 'Failed to decrypt file');
      logSecurityEvent({ type: 'file_download_failed', message: err.message });
    }
  };

  return (
    <div className="flex h-screen bg-background">
      {/* Users List */}
      <Card className="w-80 border-r">
        <div className="p-4 border-b flex justify-between items-center">
          <h2 className="font-bold text-lg">Contacts</h2>
          <div className="flex gap-2">
            <Button size="icon" variant="ghost" onClick={() => setShowLogs(true)} title="Security Logs">
              <AlertCircle className="w-4 h-4" />
            </Button>
            <Button size="icon" variant="ghost" onClick={() => setShowSettings(true)} title="Settings">
              <Settings className="w-4 h-4" />
            </Button>
            <Button size="icon" variant="ghost" onClick={logout} title="Logout">
              <LogOut className="w-4 h-4" />
            </Button>
          </div>
        </div>
        <ScrollArea className="h-full">
          {users.map(u => (
            <div
              key={u.id}
              onClick={() => handleUserSelect(u)}
              className={`p-4 hover:bg-muted cursor-pointer ${selectedUser?.id === u.id ? 'bg-muted' : ''}`}
            >
              <div className="flex items-center gap-3">
                <Avatar><AvatarFallback>{u.username?.[0]?.toUpperCase() || '?'}</AvatarFallback></Avatar>
                <div>
                  <p className="font-medium">{u.username || 'Unknown'}</p>
                  {isKeyExchanged && selectedUser?.id === u.id && (
                    <p className="text-xs text-green-600 flex items-center gap-1">
                      <Lock className="w-3 h-3" /> Secure Channel
                    </p>
                  )}
                </div>
              </div>
            </div>
          ))}
        </ScrollArea>
      </Card>

      {/* Chat Area */}
      <div className="flex-1 flex flex-col">
        {selectedUser ? (
          <>
            <div className="p-4 border-b flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Avatar><AvatarFallback>{selectedUser.username?.[0]?.toUpperCase() || '?'}</AvatarFallback></Avatar>
                <div>
                  <p className="font-semibold">{selectedUser.username || 'Unknown'}</p>
                  <p className="text-xs text-green-600">End-to-End Encrypted</p>
                </div>
              </div>
              {isKeyExchanged && <Badge>Secure</Badge>}
            </div>

            <ScrollArea className="flex-1 p-6">
              <div className="space-y-4">
                {messages.map((m, i) => (
                  <div key={i} className={`flex flex-col ${m.isMine ? 'items-end' : 'items-start'}`}>
                    <div className={`max-w-xs lg:max-w-md px-4 py-3 rounded-2xl ${m.isMine ? 'bg-primary text-primary-foreground' : 'bg-muted'}`}>
                      {m.fileId ? (
                        <div className="flex items-center gap-2 cursor-pointer" onClick={() => downloadAndDecryptFile(m.fileId)}>
                          <FileText className="w-5 h-5" />
                          <span>{m.text}</span>
                          <Download className="w-4 h-4" />
                        </div>
                      ) : (
                        <p>{m.text}</p>
                      )}
                    </div>
                    <span className={`text-xs text-muted-foreground mt-1 px-1 ${m.isMine ? 'text-right' : 'text-left'}`}>
                      {formatMessageTime(m.timestamp)}
                    </span>
                  </div>
                ))}
                <div ref={scrollRef} />
              </div>
            </ScrollArea>

            <div className="p-4 border-t">
              <div className="flex gap-3">
                <Input
                  value={messageInput}
                  onChange={e => setMessageInput(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && sendMessage()}
                  placeholder={isKeyExchanged ? "Type a message..." : "Establishing secure connection..."}
                  disabled={!isKeyExchanged}
                />
                <input type="file" ref={fileInputRef} onChange={handleFileSelect} className="hidden" />
                <Button size="icon" onClick={() => fileInputRef.current?.click()} disabled={!isKeyExchanged}>
                  <Upload className="w-4 h-4" />
                </Button>
                <Button onClick={sendMessage} disabled={!isKeyExchanged || !messageInput.trim()}>
                  <Send className="w-4 h-4" />
                </Button>
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <Shield className="w-20 h-20 mx-auto text-primary mb-6" />
              <h1 className="text-3xl font-bold">Secure E2EE Chat</h1>
              <p className="text-muted-foreground mt-2">Select a user to start messaging</p>
            </div>
          </div>
        )}
      </div>

      {/* Security Logs */}
      {showLogs && <SecurityLogsSidebar onClose={() => setShowLogs(false)} />}

      {/* Settings Dialog */}
      <Dialog open={showSettings} onOpenChange={setShowSettings}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Settings className="w-5 h-5" />
              Security Settings
            </DialogTitle>
            <DialogDescription>
              Manage your account security settings
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-6 py-4">
            {/* 2FA Section */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Smartphone className="w-5 h-5 text-primary" />
                  <div>
                    <h4 className="font-medium">Two-Factor Authentication</h4>
                    <p className="text-xs text-muted-foreground">
                      Add an extra layer of security to your account
                    </p>
                  </div>
                </div>
                <Badge variant={twoFactorEnabled ? "default" : "secondary"}>
                  {twoFactorEnabled ? "Enabled" : "Disabled"}
                </Badge>
              </div>

              {!twoFactorEnabled && !setupData && (
                <Button onClick={startSetup2FA} className="w-full">
                  <Shield className="w-4 h-4 mr-2" />
                  Enable 2FA
                </Button>
              )}

              {/* Setup Flow */}
              {setupData && !twoFactorEnabled && (
                <div className="space-y-4 p-4 bg-muted rounded-lg">
                  <div className="text-center">
                    <p className="text-sm font-medium mb-2">Scan this QR code with your authenticator app</p>
                    <div className="bg-white p-4 rounded-lg inline-block">
                      <img 
                        src={`https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(setupData.otpauthUri)}`}
                        alt="2FA QR Code"
                        className="w-36 h-36"
                      />
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <p className="text-xs text-muted-foreground text-center">Or enter this secret manually:</p>
                    <div className="flex gap-2">
                      <Input 
                        value={setupData.secret} 
                        readOnly 
                        className="font-mono text-xs"
                      />
                      <Button size="icon" variant="outline" onClick={copySecret}>
                        {copiedSecret ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <p className="text-sm">Enter the 6-digit code from your app:</p>
                    <Input
                      value={verifyCode}
                      onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      placeholder="000000"
                      className="text-center text-lg tracking-widest"
                      maxLength={6}
                    />
                  </div>

                  <div className="flex gap-2">
                    <Button 
                      variant="outline" 
                      className="flex-1"
                      onClick={() => { setSetupData(null); setVerifyCode(''); }}
                    >
                      Cancel
                    </Button>
                    <Button 
                      className="flex-1"
                      onClick={verifyAndEnable2FA}
                      disabled={verifyCode.length !== 6}
                    >
                      Verify & Enable
                    </Button>
                  </div>
                </div>
              )}

              {/* Show backup codes after enabling */}
              {backupCodes.length > 0 && (
                <div className="space-y-3 p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                  <p className="text-sm font-medium text-yellow-600">⚠️ Save your backup codes!</p>
                  <p className="text-xs text-muted-foreground">
                    These codes can be used if you lose access to your authenticator. Each code can only be used once.
                  </p>
                  <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                    {backupCodes.map((code, i) => (
                      <div key={i} className="bg-background p-2 rounded text-center">{code}</div>
                    ))}
                  </div>
                  <Button 
                    variant="outline" 
                    className="w-full"
                    onClick={() => setBackupCodes([])}
                  >
                    I've saved my codes
                  </Button>
                </div>
              )}

              {/* Disable 2FA */}
              {twoFactorEnabled && backupCodes.length === 0 && (
                <div className="space-y-3 p-4 bg-muted rounded-lg">
                  <p className="text-sm font-medium">Disable Two-Factor Authentication</p>
                  <Input
                    type="password"
                    value={disablePassword}
                    onChange={(e) => setDisablePassword(e.target.value)}
                    placeholder="Your password"
                  />
                  <Input
                    value={disableCode}
                    onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    placeholder="2FA code"
                    className="text-center tracking-widest"
                    maxLength={6}
                  />
                  <Button 
                    variant="destructive" 
                    className="w-full"
                    onClick={disable2FA}
                    disabled={!disablePassword || disableCode.length !== 6}
                  >
                    Disable 2FA
                  </Button>
                </div>
              )}
            </div>

            {/* Account Info */}
            <div className="pt-4 border-t">
              <p className="text-xs text-muted-foreground">
                Logged in as <span className="font-medium">{user?.username}</span>
              </p>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

const SecurityLogsSidebar = ({ onClose }) => {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const load = async () => {
      const all = await getSecurityLogs(100);
      setLogs(all.reverse());
    };
    load();
    const int = setInterval(load, 3000);
    return () => clearInterval(int);
  }, []);

  return (
    <Card className="w-96 border-l h-screen flex flex-col">
      <div className="p-4 border-b flex justify-between items-center">
        <h3 className="font-bold">Security Logs</h3>
        <Button size="icon" variant="ghost" onClick={onClose}>×</Button>
      </div>
      <ScrollArea className="flex-1 p-4">
        <div className="space-y-3 text-xs font-mono">
          {logs.map(log => (
            <div key={log.id} className="p-3 bg-muted rounded">
              <div className="flex justify-between">
                <span className="font-bold text-green-400">{log.type.toUpperCase()}</span>
                <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
              </div>
              <p>{log.message}</p>
            </div>
          ))}
        </div>
      </ScrollArea>
    </Card>
  );
};

export default Chat;