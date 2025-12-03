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
    <div className="flex h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 relative overflow-hidden">
      {/* Background effects */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_left,hsl(152_70%_45%/0.05),transparent_50%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_right,hsl(160_50%_35%/0.03),transparent_50%)]" />
      <div className="absolute inset-0 bg-[linear-gradient(hsl(152_70%_45%/0.02)_1px,transparent_1px),linear-gradient(90deg,hsl(152_70%_45%/0.02)_1px,transparent_1px)] bg-[size:40px_40px]" />
      
      {/* Users List */}
      <Card className="w-80 border-r border-gray-700/50 glass rounded-none flex flex-col relative z-10">
        <div className="p-4 border-b border-gray-700/50 flex justify-between items-center">
          <h2 className="font-bold text-lg bg-gradient-to-r from-green-400 to-green-500 bg-clip-text text-transparent flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            Contacts
          </h2>
          <div className="flex gap-1">
            <Button size="icon" variant="ghost" onClick={() => setShowLogs(true)} title="Security Logs" className="hover:bg-gray-800 hover:text-green-400 transition-all duration-300">
              <AlertCircle className="w-4 h-4" />
            </Button>
            <Button size="icon" variant="ghost" onClick={() => setShowSettings(true)} title="Settings" className="hover:bg-gray-800 hover:text-green-400 transition-all duration-300">
              <Settings className="w-4 h-4" />
            </Button>
            <Button size="icon" variant="ghost" onClick={logout} title="Logout" className="hover:bg-gray-800 hover:text-red-400 transition-all duration-300">
              <LogOut className="w-4 h-4" />
            </Button>
          </div>
        </div>
        <ScrollArea className="flex-1">
          {users.map((u, index) => (
            <div
              key={u.id}
              onClick={() => handleUserSelect(u)}
              className={`contact-item p-4 cursor-pointer animate-slide-in-left ${selectedUser?.id === u.id ? 'active' : ''}`}
              style={{ animationDelay: `${index * 0.05}s` }}
            >
              <div className="flex items-center gap-3">
                <Avatar className="ring-2 ring-gray-700 ring-offset-2 ring-offset-gray-900">
                  <AvatarFallback className="bg-gradient-to-br from-green-500 to-green-600 text-gray-900 font-semibold">
                    {u.username?.[0]?.toUpperCase() || '?'}
                  </AvatarFallback>
                </Avatar>
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-gray-200 truncate">{u.username || 'Unknown'}</p>
                  {isKeyExchanged && selectedUser?.id === u.id && (
                    <p className="text-xs text-green-500 flex items-center gap-1 animate-fade-in">
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
      <div className="flex-1 flex flex-col relative z-10">
        {selectedUser ? (
          <>
            <div className="p-4 border-b border-gray-700/50 glass flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Avatar className="ring-2 ring-green-500/30 ring-offset-2 ring-offset-gray-900">
                  <AvatarFallback className="bg-gradient-to-br from-green-500 to-green-600 text-gray-900 font-semibold">
                    {selectedUser.username?.[0]?.toUpperCase() || '?'}
                  </AvatarFallback>
                </Avatar>
                <div>
                  <p className="font-semibold text-gray-100">{selectedUser.username || 'Unknown'}</p>
                  <p className="text-xs text-green-500 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                    End-to-End Encrypted
                  </p>
                </div>
              </div>
              {isKeyExchanged && (
                <Badge className="bg-green-500/10 text-green-400 border border-green-500/30 security-badge">
                  <Lock className="w-3 h-3 mr-1" />
                  Secure
                </Badge>
              )}
            </div>

            <ScrollArea className="flex-1 p-6">
              <div className="space-y-4 max-w-3xl mx-auto">
                {messages.map((m, i) => (
                  <div 
                    key={i} 
                    className={`flex flex-col ${m.isMine ? 'items-end' : 'items-start'} animate-slide-up`}
                    style={{ animationDelay: `${i * 0.02}s` }}
                  >
                    <div className={`max-w-xs lg:max-w-md px-4 py-3 ${
                      m.isMine 
                        ? 'message-sent text-gray-900 font-medium' 
                        : 'message-received text-gray-100'
                    }`}>
                      {m.fileId ? (
                        <div 
                          className="flex items-center gap-2 cursor-pointer hover:opacity-80 transition-opacity" 
                          onClick={() => downloadAndDecryptFile(m.fileId)}
                        >
                          <FileText className="w-5 h-5" />
                          <span className="flex-1 truncate">{m.text}</span>
                          <Download className="w-4 h-4 animate-bounce-subtle" />
                        </div>
                      ) : (
                        <p>{m.text}</p>
                      )}
                    </div>
                    <span className={`text-xs text-gray-500 mt-1 px-1 ${m.isMine ? 'text-right' : 'text-left'}`}>
                      {formatMessageTime(m.timestamp)}
                    </span>
                  </div>
                ))}
                <div ref={scrollRef} />
              </div>
            </ScrollArea>

            <div className="p-4 border-t border-gray-700/50 glass">
              <div className="flex gap-3 max-w-3xl mx-auto">
                <Input
                  value={messageInput}
                  onChange={e => setMessageInput(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && sendMessage()}
                  placeholder={isKeyExchanged ? "Type a secure message..." : "Establishing secure connection..."}
                  disabled={!isKeyExchanged}
                  className="bg-gray-800/50 border-gray-700 h-12 input-glow focus:border-green-500/50 transition-all duration-300 placeholder:text-gray-600"
                />
                <input type="file" ref={fileInputRef} onChange={handleFileSelect} className="hidden" />
                <Button 
                  size="icon" 
                  onClick={() => fileInputRef.current?.click()} 
                  disabled={!isKeyExchanged}
                  className="h-12 w-12 bg-gray-800 hover:bg-gray-700 border border-gray-700 hover:border-green-500/50 transition-all duration-300"
                >
                  <Upload className="w-5 h-5" />
                </Button>
                <Button 
                  onClick={sendMessage} 
                  disabled={!isKeyExchanged || !messageInput.trim()}
                  className="h-12 px-6 btn-primary-glow text-gray-900 font-semibold"
                >
                  <Send className="w-5 h-5" />
                </Button>
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center animate-scale-in">
              <div className="w-32 h-32 mx-auto mb-8 rounded-3xl bg-gradient-to-br from-green-500/20 to-green-600/10 flex items-center justify-center animate-pulse-glow">
                <Shield className="w-16 h-16 text-green-500 animate-float" />
              </div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-green-400 via-green-500 to-green-400 bg-clip-text text-transparent mb-4">
                Secure E2EE Chat
              </h1>
              <p className="text-gray-500 flex items-center justify-center gap-2">
                <Lock className="w-4 h-4 text-green-500" />
                Select a contact to start encrypted messaging
              </p>
              <div className="mt-8 flex justify-center gap-2">
                <div className="typing-dot"></div>
                <div className="typing-dot"></div>
                <div className="typing-dot"></div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Security Logs */}
      {showLogs && <SecurityLogsSidebar onClose={() => setShowLogs(false)} />}

      {/* Settings Dialog */}
      <Dialog open={showSettings} onOpenChange={setShowSettings}>
        <DialogContent className="max-w-md bg-gray-900 border-gray-700">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-gray-100">
              <div className="w-8 h-8 rounded-lg bg-green-500/10 flex items-center justify-center">
                <Settings className="w-4 h-4 text-green-500" />
              </div>
              Security Settings
            </DialogTitle>
            <DialogDescription className="text-gray-400">
              Manage your account security settings
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-6 py-4">
            {/* 2FA Section */}
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-gray-800/50 rounded-xl border border-gray-700/50">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
                    <Smartphone className="w-5 h-5 text-green-500" />
                  </div>
                  <div>
                    <h4 className="font-medium text-gray-100">Two-Factor Authentication</h4>
                    <p className="text-xs text-gray-500">
                      Add an extra layer of security
                    </p>
                  </div>
                </div>
                <Badge className={twoFactorEnabled 
                  ? "bg-green-500/10 text-green-400 border border-green-500/30" 
                  : "bg-gray-700 text-gray-400 border border-gray-600"
                }>
                  {twoFactorEnabled ? "Enabled" : "Disabled"}
                </Badge>
              </div>

              {!twoFactorEnabled && !setupData && (
                <Button onClick={startSetup2FA} className="w-full h-11 btn-primary-glow text-gray-900 font-semibold">
                  <Shield className="w-4 h-4 mr-2" />
                  Enable 2FA
                </Button>
              )}

              {/* Setup Flow */}
              {setupData && !twoFactorEnabled && (
                <div className="space-y-4 p-4 bg-gray-800/50 rounded-xl border border-gray-700/50">
                  <div className="text-center">
                    <p className="text-sm font-medium mb-3 text-gray-200">Scan with your authenticator app</p>
                    <div className="bg-white p-4 rounded-xl inline-block shadow-lg">
                      <img 
                        src={`https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(setupData.otpauthUri)}`}
                        alt="2FA QR Code"
                        className="w-36 h-36"
                      />
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <p className="text-xs text-gray-500 text-center">Or enter this secret manually:</p>
                    <div className="flex gap-2">
                      <Input 
                        value={setupData.secret} 
                        readOnly 
                        className="font-mono text-xs bg-gray-800 border-gray-700"
                      />
                      <Button size="icon" variant="outline" onClick={copySecret} className="border-gray-700 hover:bg-gray-800 hover:border-green-500/50">
                        {copiedSecret ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <p className="text-sm text-gray-300">Enter the 6-digit code:</p>
                    <Input
                      value={verifyCode}
                      onChange={(e) => setVerifyCode(e.target.value.replaceAll(/\D/g, '').slice(0, 6))}
                      placeholder="000000"
                      className="text-center text-xl tracking-[0.3em] font-mono bg-gray-800 border-gray-700 h-12"
                      maxLength={6}
                    />
                  </div>

                  <div className="flex gap-2">
                    <Button 
                      variant="outline" 
                      className="flex-1 border-gray-700 hover:bg-gray-800"
                      onClick={() => { setSetupData(null); setVerifyCode(''); }}
                    >
                      Cancel
                    </Button>
                    <Button 
                      className="flex-1 btn-primary-glow text-gray-900 font-semibold"
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
                <div className="space-y-3 p-4 bg-yellow-500/5 border border-yellow-500/20 rounded-xl">
                  <p className="text-sm font-medium text-yellow-500 flex items-center gap-2">
                    <span className="text-lg">⚠️</span> Save your backup codes!
                  </p>
                  <p className="text-xs text-gray-500">
                    These codes can be used if you lose access to your authenticator. Each code can only be used once.
                  </p>
                  <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                    {backupCodes.map((code, i) => (
                      <div key={code} className="bg-gray-800 p-2 rounded-lg text-center text-gray-300 border border-gray-700">{code}</div>
                    ))}
                  </div>
                  <Button 
                    variant="outline" 
                    className="w-full border-gray-700 hover:bg-gray-800 hover:border-green-500/50"
                    onClick={() => setBackupCodes([])}
                  >
                    I've saved my codes
                  </Button>
                </div>
              )}

              {/* Disable 2FA */}
              {twoFactorEnabled && backupCodes.length === 0 && (
                <div className="space-y-3 p-4 bg-gray-800/50 rounded-xl border border-gray-700/50">
                  <p className="text-sm font-medium text-gray-200">Disable Two-Factor Authentication</p>
                  <Input
                    type="password"
                    value={disablePassword}
                    onChange={(e) => setDisablePassword(e.target.value)}
                    placeholder="Your password"
                    className="bg-gray-800 border-gray-700"
                  />
                  <Input
                    value={disableCode}
                    onChange={(e) => setDisableCode(e.target.value.replaceAll(/\D/g, '').slice(0, 6))}
                    placeholder="2FA code"
                    className="text-center tracking-[0.3em] font-mono bg-gray-800 border-gray-700"
                    maxLength={6}
                  />
                  <Button 
                    variant="destructive" 
                    className="w-full bg-red-500/10 text-red-400 border border-red-500/30 hover:bg-red-500/20"
                    onClick={disable2FA}
                    disabled={!disablePassword || disableCode.length !== 6}
                  >
                    Disable 2FA
                  </Button>
                </div>
              )}
            </div>

            {/* Account Info */}
            <div className="pt-4 border-t border-gray-700">
              <p className="text-xs text-gray-500">
                Logged in as <span className="font-medium text-green-400">{user?.username}</span>
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
    <Card className="w-96 border-l border-gray-800 h-screen flex flex-col bg-gray-900/95 backdrop-blur-xl">
      <div className="p-4 border-b border-gray-800 flex justify-between items-center">
        <h3 className="font-bold text-gray-100 flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-green-500/10 flex items-center justify-center">
            <Shield className="w-3 h-3 text-green-500" />
          </div>
          Security Logs
        </h3>
        <Button size="icon" variant="ghost" onClick={onClose} className="text-gray-400 hover:text-gray-100 hover:bg-gray-800">
          ×
        </Button>
      </div>
      <ScrollArea className="flex-1 p-4">
        <div className="space-y-3 text-xs font-mono">
          {logs.map(log => (
            <div key={log.id} className="p-3 bg-gray-800/50 rounded-xl border border-gray-700/50 hover:border-green-500/30 transition-all duration-300">
              <div className="flex justify-between mb-1">
                <span className="font-bold text-green-400 text-[10px] px-2 py-0.5 bg-green-500/10 rounded-full">{log.type.toUpperCase()}</span>
                <span className="text-gray-500">{new Date(log.timestamp).toLocaleTimeString()}</span>
              </div>
              <p className="text-gray-300">{log.message}</p>
            </div>
          ))}
        </div>
      </ScrollArea>
    </Card>
  );
};

export default Chat;