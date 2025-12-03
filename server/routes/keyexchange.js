// routes/keyexchange.js
import express from 'express';
import jwtMiddleware from '../middleware/auth.js';
import KeyExchange from '../models/KeyExchange.js';
import { logger } from '../utils/logger.js';

const router = express.Router();
router.use(jwtMiddleware);

// Step 1: Alice initiates exchange with Bob
router.post('/initiate', async (req, res) => {
  try {
    const { receiverId, ephemeralPublicKey, signature } = req.body;
    const initiatorId = req.userId;

    if (!receiverId || !ephemeralPublicKey || !signature) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const exchange = new KeyExchange({
      initiator: initiatorId,
      receiver: receiverId,
      initiatorEphemeralKey: ephemeralPublicKey,
      signature,
      status: 'pending'
    });

    await exchange.save();

    logger.info('Key exchange initiated', { initiatorId, receiverId, exchangeId: exchange._id });

    res.json({ exchangeId: exchange._id });
  } catch (err) {
    logger.error('Key exchange initiate failed', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Step 2: Bob responds
router.post('/respond', async (req, res) => {
  try {
    const { exchangeId, ephemeralPublicKey, signature } = req.body;
    const responderId = req.userId;

    const exchange = await KeyExchange.findById(exchangeId);
    if (!exchange || exchange.receiver.toString() !== responderId || exchange.status !== 'pending') {
      return res.status(400).json({ error: 'Invalid or expired exchange' });
    }

    exchange.responderEphemeralKey = ephemeralPublicKey;
    exchange.responderSignature = signature;
    exchange.status = 'completed';
    await exchange.save();

    logger.info('Key exchange completed', { exchangeId, responderId });

    res.json({ success: true, exchangeId });
  } catch (err) {
    logger.error('Key exchange respond failed', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get pending exchanges where user is receiver
router.get('/pending', async (req, res) => {
  const userId = req.userId;
  const pending = await KeyExchange.find({
    receiver: userId,
    status: 'pending'
  }).populate('initiator', 'username');

  res.json(pending);
});

// Get exchanges initiated by user (to check for completion)
router.get('/initiated', async (req, res) => {
  const userId = req.userId;
  const initiated = await KeyExchange.find({
    initiator: userId
  }).populate('receiver', 'username');

  res.json(initiated);
});

// Step 3: Key Confirmation - prove both parties derived the same key
router.post('/confirm', async (req, res) => {
  try {
    const { exchangeId, confirmationToken } = req.body;
    const userId = req.userId;

    const exchange = await KeyExchange.findById(exchangeId);
    if (!exchange || exchange.status !== 'completed') {
      return res.status(400).json({ error: 'Invalid or incomplete exchange' });
    }

    // Store confirmation based on who is sending it
    if (exchange.initiator.toString() === userId) {
      exchange.initiatorConfirmation = confirmationToken;
    } else if (exchange.receiver.toString() === userId) {
      exchange.responderConfirmation = confirmationToken;
    } else {
      return res.status(403).json({ error: 'Not a party to this exchange' });
    }

    // Check if both confirmations are present
    if (exchange.initiatorConfirmation && exchange.responderConfirmation) {
      exchange.status = 'confirmed';
      logger.info('Key exchange fully confirmed', { exchangeId, initiator: exchange.initiator, receiver: exchange.receiver });
    }

    await exchange.save();
    res.json({ success: true, status: exchange.status });
  } catch (err) {
    logger.error('Key confirmation failed', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get exchange status for confirmation
router.get('/status/:exchangeId', async (req, res) => {
  try {
    const exchange = await KeyExchange.findById(req.params.exchangeId);
    if (!exchange) {
      return res.status(404).json({ error: 'Exchange not found' });
    }
    
    res.json({
      status: exchange.status,
      hasInitiatorConfirmation: !!exchange.initiatorConfirmation,
      hasResponderConfirmation: !!exchange.responderConfirmation
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

export default router;