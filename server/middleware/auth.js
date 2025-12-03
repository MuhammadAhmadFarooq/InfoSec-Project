import jwt from 'jsonwebtoken';
import { logger } from '../utils/logger.js';

export default function jwtMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (err) {
    logger.warn('Invalid JWT', { ip: req.ip });
    res.status(401).json({ error: 'Invalid token' });
  }
}