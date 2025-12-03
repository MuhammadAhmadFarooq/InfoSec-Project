// models/Message.js
import mongoose from 'mongoose';

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  encryptedMessage: { type: String, required: true },
  iv: { type: String, required: true },
  tag: { type: String, required: true },
  timestamp: { type: Number, required: true },
  sequenceNumber: { type: Number, required: true },
  fileId: { type: String, default: null }
}, { timestamps: true });

// Critical: Prevent duplicates & enable fast lookup
messageSchema.index({ sender: 1, receiver: 1, sequenceNumber: 1 }, { unique: true });
messageSchema.index({ sender: 1, receiver: 1, timestamp: 1 });

export default mongoose.model('Message', messageSchema);