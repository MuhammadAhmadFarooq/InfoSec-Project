import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import { logger } from '../utils/logger.js';
import { generateSecret, verifyTOTP, generateBackupCodes, generateOTPAuthURI } from '../utils/totp.js';

export const register = async (req, res) => {
  try {
    const { username, password, publicKey, keyType } = req.body;

    if (!username || !password || !publicKey || !keyType) {
      logger.warn('Registration missing fields', { username, ip: req.ip });
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (!['RSA', 'ECC'].includes(keyType)) {
      return res.status(400).json({ error: 'Invalid keyType' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      logger.warn('Duplicate username attempt', { username });
      return res.status(409).json({ error: 'Username already taken' });
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
      username,
      passwordHash,
      publicKey,
      keyType
    });

    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    logger.info('New user registered', { userId: user._id, username });
    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: { id: user._id, username: user.username, twoFactorEnabled: false }
    });

  } catch (error) {
    logger.error('Registration error', { error: error.message, stack: error.stack });
    res.status(500).json({ error: 'Server error' });
  }
};

export const login = async (req, res) => {
  try {
    const { username, password, totpCode } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      logger.warn('Login failed: user not found', { username, ip: req.ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      logger.warn('Login failed: wrong password', { username, ip: req.ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if 2FA is enabled
    if (user.twoFactorEnabled) {
      if (!totpCode) {
        // Return indicator that 2FA is required
        logger.info('2FA required for login', { username });
        return res.status(200).json({ 
          requires2FA: true, 
          message: 'Please provide 2FA code' 
        });
      }

      // Verify TOTP code
      const isValidTOTP = verifyTOTP(totpCode, user.twoFactorSecret);
      
      // Also check backup codes if TOTP fails
      if (!isValidTOTP) {
        const backupIndex = user.twoFactorBackupCodes.indexOf(totpCode.toUpperCase());
        if (backupIndex === -1) {
          logger.warn('Login failed: invalid 2FA code', { username, ip: req.ip });
          return res.status(401).json({ error: 'Invalid 2FA code' });
        }
        // Remove used backup code
        user.twoFactorBackupCodes.splice(backupIndex, 1);
        await user.save();
        logger.info('Backup code used for login', { username });
      }
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    logger.info('User logged in', { userId: user._id, username, with2FA: user.twoFactorEnabled });
    res.json({
      message: 'Login successful',
      token,
      user: { id: user._id, username: user.username, twoFactorEnabled: user.twoFactorEnabled }
    });

  } catch (error) {
    logger.error('Login error', { error: error.message });
    res.status(500).json({ error: 'Server error' });
  }
};

// Enable 2FA - Step 1: Generate secret
export const setup2FA = async (req, res) => {
  try {
    const userId = req.userId;
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is already enabled' });
    }

    // Generate new secret
    const secret = generateSecret();
    const otpauthUri = generateOTPAuthURI(secret, user.username);
    
    // Temporarily store secret (not enabled yet)
    user.twoFactorSecret = secret;
    await user.save();

    logger.info('2FA setup initiated', { userId, username: user.username });
    
    res.json({
      secret,
      otpauthUri,
      message: 'Scan the QR code with your authenticator app, then verify with a code'
    });
  } catch (error) {
    logger.error('2FA setup error', { error: error.message });
    res.status(500).json({ error: 'Server error' });
  }
};

// Enable 2FA - Step 2: Verify and enable
export const verify2FA = async (req, res) => {
  try {
    const userId = req.userId;
    const { totpCode } = req.body;

    const user = await User.findById(userId);
    
    if (!user || !user.twoFactorSecret) {
      return res.status(400).json({ error: 'Please setup 2FA first' });
    }

    if (user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is already enabled' });
    }

    // Verify the TOTP code
    const isValid = verifyTOTP(totpCode, user.twoFactorSecret);
    
    if (!isValid) {
      logger.warn('2FA verification failed', { userId });
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    // Generate backup codes
    const backupCodes = generateBackupCodes();
    
    // Enable 2FA
    user.twoFactorEnabled = true;
    user.twoFactorBackupCodes = backupCodes;
    await user.save();

    logger.info('2FA enabled successfully', { userId, username: user.username });
    
    res.json({
      message: '2FA enabled successfully',
      backupCodes,
      warning: 'Save these backup codes securely. They can only be used once.'
    });
  } catch (error) {
    logger.error('2FA verification error', { error: error.message });
    res.status(500).json({ error: 'Server error' });
  }
};

// Disable 2FA
export const disable2FA = async (req, res) => {
  try {
    const userId = req.userId;
    const { totpCode, password } = req.body;

    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is not enabled' });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      logger.warn('2FA disable failed: wrong password', { userId });
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Verify TOTP code
    const isValidTOTP = verifyTOTP(totpCode, user.twoFactorSecret);
    if (!isValidTOTP) {
      logger.warn('2FA disable failed: invalid code', { userId });
      return res.status(401).json({ error: 'Invalid 2FA code' });
    }

    // Disable 2FA
    user.twoFactorEnabled = false;
    user.twoFactorSecret = null;
    user.twoFactorBackupCodes = [];
    await user.save();

    logger.info('2FA disabled', { userId, username: user.username });
    
    res.json({ message: '2FA disabled successfully' });
  } catch (error) {
    logger.error('2FA disable error', { error: error.message });
    res.status(500).json({ error: 'Server error' });
  }
};

// Get 2FA status
export const get2FAStatus = async (req, res) => {
  try {
    const userId = req.userId;
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ 
      twoFactorEnabled: user.twoFactorEnabled,
      backupCodesRemaining: user.twoFactorBackupCodes?.length || 0
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
};