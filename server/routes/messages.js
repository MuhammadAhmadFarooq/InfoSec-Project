import express from 'express';
import { sendMessage, getConversation } from '../controllers/messageController.js';
import jwtMiddleware from '../middleware/auth.js';

const router = express.Router();
router.use(jwtMiddleware);

router.post('/', sendMessage);
router.get('/:partnerId', getConversation);

export default router;