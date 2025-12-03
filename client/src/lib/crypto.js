// src/lib/crypto.js
// Complete, working Web Crypto implementation for your E2EE app

export async function generateKeyPair(keyType = 'ECC') {
  if (keyType === 'RSA') {
    const pair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt']
    );
    return { publicKey: pair.publicKey, privateKey: pair.privateKey, keyType: 'RSA' };
  } else {
    // Generate ECDH key pair for key derivation (includes deriveBits for HKDF support)
    const ecdhPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
    // Generate ECDSA key pair for signing
    const ecdsaPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    return { 
      publicKey: ecdhPair.publicKey, 
      privateKey: ecdhPair.privateKey, 
      signingKey: ecdsaPair.privateKey,
      verifyKey: ecdsaPair.publicKey,
      keyType: 'ECC' 
    };
  }
}

export async function exportPublicKey(publicKey) {
  const exported = await crypto.subtle.exportKey('spki', publicKey);
  const base64 = btoa(String.fromCharCode(...new Uint8Array(exported)));
  const formatted = base64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN PUBLIC KEY-----\n${formatted}\n-----END PUBLIC KEY-----`;
}

export async function importPublicKey(pem, keyType = 'ECC') {
  const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

  const algo = keyType === 'RSA'
    ? { name: 'RSA-OAEP', hash: 'SHA-256' }
    : { name: 'ECDH', namedCurve: 'P-256' };

  return crypto.subtle.importKey('spki', bytes.buffer, algo, true, keyType === 'RSA' ? ['encrypt'] : []);
}

export async function signData(privateKey, data) {
  // We need ECDSA-capable private key – generate with: name: 'ECDSA', namedCurve: 'P-256'
  const encoder = new TextEncoder();
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    encoder.encode(data)
  );
  return arrayBufferToBase64(signature);
}

export async function verifySignature(publicKey, signature, data) {
  try {
    const encoder = new TextEncoder();
    const signatureBuffer = base64ToArrayBuffer(signature);
    
    // Import the public key for ECDSA verification
    const verifyKey = await crypto.subtle.importKey(
      'spki',
      await crypto.subtle.exportKey('spki', publicKey),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );
    
    const isValid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      verifyKey,
      signatureBuffer,
      encoder.encode(data)
    );
    
    return isValid;
  } catch (err) {
    console.error('Signature verification failed:', err);
    return false;
  }
}

// Generate a key confirmation token (proves both parties derived the same key)
export async function generateKeyConfirmation(sessionKey, myId, partnerId) {
  const encoder = new TextEncoder();
  const data = encoder.encode(`KEY_CONFIRM:${myId}:${partnerId}:${Date.now()}`);
  
  // Use the session key to create an HMAC-like confirmation
  const confirmation = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: new Uint8Array(12) }, // Fixed IV for confirmation only
    sessionKey,
    data
  );
  
  return arrayBufferToBase64(confirmation);
}

// Verify key confirmation from the other party
export async function verifyKeyConfirmation(sessionKey, confirmation, expectedPartnerId, myId) {
  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(12) },
      sessionKey,
      base64ToArrayBuffer(confirmation)
    );
    
    const text = new TextDecoder().decode(decrypted);
    // Check if the confirmation contains the expected pattern
    return text.startsWith(`KEY_CONFIRM:${expectedPartnerId}:${myId}:`);
  } catch (err) {
    return false;
  }
}

export async function deriveSharedSecret(myPrivateKey, theirPublicKey) {
  // Use ECDH to derive an AES-GCM key directly
  // The ECDH shared secret is passed through the internal KDF
  const sessionKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: theirPublicKey },
    myPrivateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  return sessionKey;
}

export async function encryptMessage(text, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const data = encoder.encode(text);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );

  const arr = new Uint8Array(ciphertext);
  const ciphertextPart = arr.slice(0, -16);
  const tag = arr.slice(-16);

  return {
    encryptedMessage: arrayBufferToBase64(ciphertextPart),
    iv: arrayBufferToBase64(iv),
    tag: arrayBufferToBase64(tag),
  };
}

export async function decryptMessage({ encryptedMessage, iv, tag }, key) {
  try {
    const ciphertext = base64ToArrayBuffer(encryptedMessage);
    const ivBuf = base64ToArrayBuffer(iv);
    const tagBuf = base64ToArrayBuffer(tag);

    const combined = new Uint8Array(ciphertext.byteLength + tagBuf.byteLength);
    combined.set(new Uint8Array(ciphertext), 0);
    combined.set(new Uint8Array(tagBuf), ciphertext.byteLength);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBuf, tagLength: 128 },
      key,
      combined
    );

    return new TextDecoder().decode(decrypted);
  } catch (err) {
    throw new Error('Decryption failed – possible replay or tampering');
  }
}

export async function encryptFileChunk(chunk, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    chunk
  );

  const arr = new Uint8Array(ciphertext);
  const ciphertextPart = arr.slice(0, -16);
  const tag = arr.slice(-16);
  
  return {
    encryptedData: arrayBufferToBase64(ciphertextPart),
    iv: arrayBufferToBase64(iv),
    tag: arrayBufferToBase64(tag),
  };
}

export async function decryptFileChunk({ encryptedData, iv, tag }, key) {
  try {
    const ciphertext = base64ToArrayBuffer(encryptedData);
    const ivBuf = base64ToArrayBuffer(iv);
    const tagBuf = base64ToArrayBuffer(tag);

    // Combine ciphertext and tag for AES-GCM decryption
    const combined = new Uint8Array(ciphertext.byteLength + tagBuf.byteLength);
    combined.set(new Uint8Array(ciphertext), 0);
    combined.set(new Uint8Array(tagBuf), ciphertext.byteLength);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(ivBuf) },
      key,
      combined.buffer
    );

    return new Uint8Array(decrypted);
  } catch (err) {
    throw new Error('Failed to decrypt file chunk - possible corruption or wrong key');
  }
}

// Updated to accept storage functions as parameters
export async function isReplayAttack(partnerId, incomingSeq, incomingTimestamp, getSequenceNumberFn, logSecurityEventFn) {
  const lastSeq = await getSequenceNumberFn(partnerId);
  const now = Date.now();

  // 1. Sequence number must be > last seen
  if (incomingSeq <= lastSeq) {
    await logSecurityEventFn({
      type: 'replay_detected',
      message: `Replay attack blocked (seq ${incomingSeq} ≤ ${lastSeq})`,
      details: { partnerId, incomingSeq, lastSeq }
    });
    return true;
  }

  // 2. Timestamp must be within 2 minutes
  if (Math.abs(now - incomingTimestamp) > 120000) {
    await logSecurityEventFn({
      type: 'replay_detected',
      message: 'Message too old/new (timestamp attack)',
      details: { partnerId, incomingTimestamp, now }
    });
    return true;
  }

  return false;
}

// Helper functions
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}