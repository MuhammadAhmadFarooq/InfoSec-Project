// models/KeyExchange.js
import mongoose from 'mongoose';

const keyExchangeSchema = new mongoose.Schema({
  initiator: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  initiatorEphemeralKey: { type: String, required: true },     // Base64 PEM
  responderEphemeralKey: { type: String },
  signature: { type: String, required: true },                 // Initiator's signature
  responderSignature: { type: String },                        // Responder's signature
  initiatorConfirmation: { type: String },                     // Key confirmation token
  responderConfirmation: { type: String },                     // Key confirmation token
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'confirmed', 'failed'], 
    default: 'pending' 
  },
  createdAt: { type: Date, default: Date.now, expires: 3600 }  // auto-delete after 1h
});

// Index for efficient queries
keyExchangeSchema.index({ initiator: 1, receiver: 1 });
keyExchangeSchema.index({ status: 1 });

export default mongoose.model('KeyExchange', keyExchangeSchema);