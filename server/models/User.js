import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  publicKey: { type: String, required: true },
  keyType: { type: String, enum: ['RSA', 'ECC'], required: true },
  // Two-Factor Authentication
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: { type: String, default: null },
  twoFactorBackupCodes: [{ type: String }],
  createdAt: { type: Date, default: Date.now }
});

export default mongoose.model('User', userSchema);