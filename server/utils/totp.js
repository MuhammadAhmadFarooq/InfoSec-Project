// TOTP (Time-based One-Time Password) implementation using Node's crypto module
import crypto from 'crypto';

// Base32 encoding/decoding (RFC 4648)
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buffer) {
  const bytes = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  let result = '';
  let bits = 0;
  let value = 0;

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;

    while (bits >= 5) {
      result += BASE32_CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    result += BASE32_CHARS[(value << (5 - bits)) & 31];
  }

  return result;
}

export function base32Decode(str) {
  const cleanStr = str.replace(/=+$/, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const output = [];

  for (let i = 0; i < cleanStr.length; i++) {
    const idx = BASE32_CHARS.indexOf(cleanStr[i]);
    if (idx === -1) continue;

    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(output);
}

// Generate a random secret for TOTP
export function generateSecret(length = 20) {
  const buffer = crypto.randomBytes(length);
  return base32Encode(buffer);
}

// Generate TOTP code
export function generateTOTP(secret, timeStep = 30, digits = 6, algorithm = 'sha1') {
  const time = Math.floor(Date.now() / 1000 / timeStep);
  const timeBuffer = Buffer.alloc(8);
  
  // Write time as big-endian 64-bit integer
  timeBuffer.writeBigInt64BE(BigInt(time));

  const secretBuffer = base32Decode(secret);
  const hmac = crypto.createHmac(algorithm, secretBuffer);
  hmac.update(timeBuffer);
  const hash = hmac.digest();

  // Dynamic truncation
  const offset = hash[hash.length - 1] & 0x0f;
  const binary = 
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

// Verify TOTP code (allows 1 step before and after for clock drift)
export function verifyTOTP(token, secret, window = 1, timeStep = 30, digits = 6) {
  const cleanToken = token.replace(/\s/g, '');
  
  if (cleanToken.length !== digits) {
    return false;
  }

  const currentTime = Math.floor(Date.now() / 1000 / timeStep);

  for (let i = -window; i <= window; i++) {
    const time = currentTime + i;
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeBigInt64BE(BigInt(time));

    const secretBuffer = base32Decode(secret);
    const hmac = crypto.createHmac('sha1', secretBuffer);
    hmac.update(timeBuffer);
    const hash = hmac.digest();

    const offset = hash[hash.length - 1] & 0x0f;
    const binary = 
      ((hash[offset] & 0x7f) << 24) |
      ((hash[offset + 1] & 0xff) << 16) |
      ((hash[offset + 2] & 0xff) << 8) |
      (hash[offset + 3] & 0xff);

    const otp = (binary % Math.pow(10, digits)).toString().padStart(digits, '0');
    
    if (otp === cleanToken) {
      return true;
    }
  }

  return false;
}

// Generate backup codes
export function generateBackupCodes(count = 8) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    codes.push(code.slice(0, 4) + '-' + code.slice(4));
  }
  return codes;
}

// Generate otpauth URI for QR code
export function generateOTPAuthURI(secret, username, issuer = 'SecureChat') {
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedUsername = encodeURIComponent(username);
  return `otpauth://totp/${encodedIssuer}:${encodedUsername}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
}

