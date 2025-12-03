import express from 'express';
import { getAllUsers, getUserPublicKey } from '../controllers/userController.js';
import jwtMiddleware from '../middleware/auth.js';

const router = express.Router();
router.use(jwtMiddleware);

router.get('/', getAllUsers);
router.get('/:id/publickey', getUserPublicKey);

export default router;