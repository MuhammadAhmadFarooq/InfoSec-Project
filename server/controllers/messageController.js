import Message from '../models/Message.js';
import { logger } from '../utils/logger.js';

export const sendMessage = async (req, res) => {
  try {
    const { receiverId, encryptedMessage, iv, tag, timestamp, sequenceNumber } = req.body;
    const senderId = req.userId;

    if (!receiverId || !encryptedMessage || !iv || !tag || !timestamp || sequenceNumber === undefined) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const message = new Message({
      sender: senderId,
      receiver: receiverId,
      encryptedMessage,
      iv,
      tag,
      timestamp,
      sequenceNumber
    });

    await message.save();

    res.status(201).json({
      success: true,
      messageId: message._id,
      timestamp: message.timestamp
    });
  } catch (error) {
    logger.error('Failed to store message', { error: error.message });
    res.status(500).json({ error: 'Failed to send message' });
  }
};

export const getConversation = async (req, res) => {
  try {
    const partnerId = req.params.partnerId;
    const userId = req.userId;

    const messages = await Message.find({
      $or: [
        { sender: userId, receiver: partnerId },
        { sender: partnerId, receiver: userId }
      ]
    })
    .sort({ timestamp: 1 })
    .select('sender receiver encryptedMessage iv tag timestamp sequenceNumber fileId');

    res.json(messages);
  } catch (error) {
    logger.error('Error fetching conversation', error);
    res.status(500).json({ error: 'Failed to load messages' });
  }
};