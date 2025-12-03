// src/lib/storage.js
const DB_NAME = 'SecureMessengerDB';
const DB_VERSION = 1;
const KEYS_STORE = 'keys';
const LOGS_STORE = 'logs';

function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;

      if (!db.objectStoreNames.contains(KEYS_STORE)) {
        db.createObjectStore(KEYS_STORE);
      }

      if (!db.objectStoreNames.contains(LOGS_STORE)) {
        const logStore = db.createObjectStore(LOGS_STORE, { keyPath: 'id', autoIncrement: true });
        logStore.createIndex('timestamp', 'timestamp');
        logStore.createIndex('type', 'type');
      }
    };
  });
}

export async function storePrivateKey(userId, keyPair) {
  const db = await openDB();
  const tx = db.transaction(KEYS_STORE, 'readwrite');
  const store = tx.objectStore(KEYS_STORE);
  return new Promise((resolve, reject) => {
    const req = store.put(keyPair, userId);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

export async function getPrivateKey(userId) {
  const db = await openDB();
  const tx = db.transaction(KEYS_STORE, 'readonly');
  const store = tx.objectStore(KEYS_STORE);
  return new Promise((resolve, reject) => {
    const req = store.get(userId);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

export async function storeSessionKey(partnerId, sessionKey) {
  const db = await openDB();
  const tx = db.transaction(KEYS_STORE, 'readwrite');
  const store = tx.objectStore(KEYS_STORE);
  return new Promise((resolve, reject) => {
    const req = store.put(sessionKey, `session_${partnerId}`);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

export async function getSessionKey(partnerId) {
  const db = await openDB();
  const tx = db.transaction(KEYS_STORE, 'readonly');
  const store = tx.objectStore(KEYS_STORE);
  return new Promise((resolve, reject) => {
    const req = store.get(`session_${partnerId}`);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

export async function logSecurityEvent(log) {
  const db = await openDB();
  const tx = db.transaction(LOGS_STORE, 'readwrite');
  const store = tx.objectStore(LOGS_STORE);

  console.log(`[SECURITY LOG] ${log.type}:`, log.message, log.details || '');

  return new Promise((resolve, reject) => {
    const req = store.add({ ...log, timestamp: Date.now() });
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

export async function getSecurityLogs(limit = 100) {
  const db = await openDB();
  const tx = db.transaction(LOGS_STORE, 'readonly');
  const store = tx.objectStore(LOGS_STORE);
  const index = store.index('timestamp');

  return new Promise((resolve) => {
    const logs = [];
    let count = 0;
    index.openCursor(null, 'prev').onsuccess = (event) => {
      const cursor = event.target.result;
      if (cursor && count < limit) {
        logs.push(cursor.value);
        count++;
        cursor.continue();
      } else {
        resolve(logs);
      }
    };
  });
}

export async function deleteSessionKey(partnerId) {
  const db = await openDB();
  const tx = db.transaction(KEYS_STORE, 'readwrite');
  const store = tx.objectStore(KEYS_STORE);
  return new Promise((resolve, reject) => {
    const req = store.delete(`session_${partnerId}`);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

export async function storeSequenceNumber(partnerId, seqNum) {
  const db = await openDB();
  const tx = db.transaction(KEYS_STORE, 'readwrite');
  const store = tx.objectStore(KEYS_STORE);
  return new Promise((resolve, reject) => {
    const req = store.put(seqNum, `seq_${partnerId}`);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

export async function getSequenceNumber(partnerId) {
  const db = await openDB();
  const tx = db.transaction(KEYS_STORE, 'readonly');
  const store = tx.objectStore(KEYS_STORE);
  return new Promise((resolve) => {
    const req = store.get(`seq_${partnerId}`);
    req.onsuccess = () => resolve(req.result || 0);
    req.onerror = () => resolve(0);
  });
}