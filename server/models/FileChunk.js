import mongoose from 'mongoose';

const fileChunkSchema = new mongoose.Schema({
  fileId: { type: String, required: true },
  chunkIndex: { type: Number, required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  encryptedChunk: { type: String, required: true },  // Store as base64 string directly
  iv: { type: String, required: true },
  tag: { type: String, required: true },
  totalChunks: { type: Number, required: true },
  filename: { type: String, required: true },
  mimeType: { type: String },
  timestamp: { type: Number, default: Date.now }
});

export default mongoose.model('FileChunk', fileChunkSchema);