import axios from 'axios';

const API_BASE_URL = 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
});

// Automatically add JWT token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const authAPI = {
  register: (username, password, publicKey, keyType = 'ECC') =>
    api.post('/auth/register', { username, password, publicKey, keyType }).then(r => r.data),

  login: (username, password, totpCode = null) =>
    api.post('/auth/login', { username, password, totpCode }).then(r => r.data),
    
  // Two-Factor Authentication
  get2FAStatus: () => api.get('/auth/2fa/status').then(r => r.data),
  
  setup2FA: () => api.post('/auth/2fa/setup').then(r => r.data),
  
  verify2FA: (totpCode) => api.post('/auth/2fa/verify', { totpCode }).then(r => r.data),
  
  disable2FA: (totpCode, password) => 
    api.post('/auth/2fa/disable', { totpCode, password }).then(r => r.data),
};

export const userAPI = {
  getAllUsers: () =>
    api.get('/users').then(res =>
      res.data.map(u => ({
        id: u._id,
        username: u.username,
        publicKey: u.publicKey,
        keyType: u.keyType,
      }))
    ),

  getUserPublicKey: (userId) =>
    api.get(`/users/${userId}/publickey`).then(r => r.data),
};

export const messageAPI = {
  sendMessage: (data) =>
    api.post('/messages', data).then(r => r.data),

  getConversation: (partnerId) =>
    api.get(`/messages/${partnerId}`).then(r => r.data),
};

export const fileAPI = {
  uploadChunk: (data) =>
    api.post('/files/upload-chunk', data).then(r => r.data),

  downloadFile: (fileId) =>
    api.get(`/files/download/${fileId}`).then(r => r.data),
};

export const keyExchangeAPI = {
  initiate: (receiverId, ephemeralPublicKey, signature) =>
    api.post('/keyexchange/initiate', { receiverId, ephemeralPublicKey, signature }).then(r => r.data),

  respond: (exchangeId, ephemeralPublicKey, signature) =>
    api.post('/keyexchange/respond', { exchangeId, ephemeralPublicKey, signature }).then(r => r.data),

  getPending: () => api.get('/keyexchange/pending').then(r => r.data),
  
  getInitiated: () => api.get('/keyexchange/initiated').then(r => r.data),
  
  // Key confirmation - proves both parties derived the same key
  confirm: (exchangeId, confirmationToken) =>
    api.post('/keyexchange/confirm', { exchangeId, confirmationToken }).then(r => r.data),
    
  getStatus: (exchangeId) =>
    api.get(`/keyexchange/status/${exchangeId}`).then(r => r.data),
};

export default api;