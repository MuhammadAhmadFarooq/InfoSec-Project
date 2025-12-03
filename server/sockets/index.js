// sockets/index.js
import Message from '../models/Message.js';
import { logger } from '../utils/logger.js';

export default function setupSocketHandlers(io) {
  const onlineUsers = new Map(); // socket.id → userId

  io.on('connection', (socket) => {
    const userId = socket.user.userId;
    onlineUsers.set(socket.id, userId);
    logger.info('Socket connection established', { 
      userId, 
      socketId: socket.id,
      event: 'SOCKET_CONNECT',
      ip: socket.handshake.address 
    });

    socket.on('send-message', async (data) => {
      try {
        const { receiverId, encryptedMessage, iv, tag, timestamp, sequenceNumber, fileId } = data;

        // Log message attempt (metadata only - no plaintext)
        logger.info('Message send attempt', { 
          event: 'MESSAGE_ATTEMPT',
          from: userId, 
          to: receiverId,
          hasFile: !!fileId,
          timestamp 
        });

        // === REPLAY PROTECTION ===
        const now = Date.now();
        if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
          socket.emit('message-error', { error: 'Timestamp out of sync' });
          logger.warn('SECURITY: Replay attack detected - timestamp out of sync', { 
            event: 'REPLAY_ATTACK_TIMESTAMP',
            userId, 
            receiverId,
            messageTimestamp: timestamp,
            serverTimestamp: now,
            drift: Math.abs(now - timestamp)
          });
          return;
        }

        const lastMsg = await Message.findOne(
          { sender: userId, receiver: receiverId },
          'sequenceNumber'
        ).sort({ sequenceNumber: -1 });

        if (lastMsg && sequenceNumber <= lastMsg.sequenceNumber) {
          logger.warn('SECURITY: Replay attack detected - duplicate sequence', { 
            event: 'REPLAY_ATTACK_SEQUENCE',
            userId, 
            receiverId, 
            attemptedSeq: sequenceNumber,
            lastSeq: lastMsg.sequenceNumber
          });
          socket.emit('message-error', { error: 'Duplicate sequence number' });
          return;
        }

        // Save message (encrypted - server cannot read content)
        const message = new Message({
          sender: userId,
          receiver: receiverId,
          encryptedMessage,
          iv,
          tag,
          timestamp,
          sequenceNumber,
          fileId: fileId || null
        });

        await message.save();

        const payload = {
          _id: message._id,
          sender: userId,
          encryptedMessage,
          iv,
          tag,
          timestamp,
          sequenceNumber,
          fileId: fileId || null
        };

        // Deliver to receiver if online
        let delivered = false;
        for (const [sid, uid] of onlineUsers.entries()) {
          if (uid.toString() === receiverId.toString()) {
            io.to(sid).emit('new-message', payload);
            delivered = true;
          }
        }

        socket.emit('message-delivered', { messageId: message._id });
        logger.info('Message stored and delivered', { 
          event: 'MESSAGE_DELIVERED',
          messageId: message._id, 
          from: userId, 
          to: receiverId,
          deliveredRealtime: delivered,
          hasFile: !!fileId
        });

      } catch (err) {
        logger.error('Message send failed', { 
          event: 'MESSAGE_ERROR',
          error: err.message, 
          userId,
          stack: err.stack 
        });
        socket.emit('message-error', { error: 'Failed to send' });
      }
    });

    socket.on('disconnect', () => {
      onlineUsers.delete(socket.id);
      logger.info('Socket disconnected', { 
        event: 'SOCKET_DISCONNECT',
        userId, 
        socketId: socket.id 
      });
    });
  });
}