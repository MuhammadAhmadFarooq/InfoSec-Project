import jwt from 'jsonwebtoken';
import { logger } from '../utils/logger.js';

export const authenticateSocket = (socket, next) => {
  const token = socket.handshake.auth.token || socket.handshake.headers['authorization']?.split(' ')[1];

  if (!token) {
    logger.warn('Socket connection rejected: no token', { ip: socket.handshake.address });
    return next(new Error('Authentication error: No token'));
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    socket.user = { userId: payload.userId };
    logger.info('Socket authenticated', { userId: payload.userId, socketId: socket.id });
    next();
  } catch (err) {
    logger.warn('Socket auth failed: invalid token', { ip: socket.handshake.address });
    next(new Error('Authentication error: Invalid token'));
  }
};