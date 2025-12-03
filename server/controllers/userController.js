import User from '../models/User.js';
import { logger } from '../utils/logger.js';

export const getAllUsers = async (req, res) => {
  try {
    const users = await User.find({}, 'username publicKey keyType _id createdAt');
    res.json(users);
  } catch (error) {
    logger.error('Error fetching users', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
};

export const getUserPublicKey = async (req, res) => {
  try {
    const user = await User.findById(req.params.id, 'publicKey keyType username');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      userId: user._id,
      username: user.username,
      publicKey: user.publicKey,
      keyType: user.keyType
    });
  } catch (error) {
    logger.error('Error fetching public key', error);
    res.status(500).json({ error: 'Server error' });
  }
};