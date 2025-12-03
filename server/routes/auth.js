import express from 'express';
import { register, login, setup2FA, verify2FA, disable2FA, get2FAStatus } from '../controllers/authController.js';
import jwtMiddleware from '../middleware/auth.js';

const router = express.Router();

// Public routes
router.post('/register', register);
router.post('/login', login);

// Protected 2FA routes
router.get('/2fa/status', jwtMiddleware, get2FAStatus);
router.post('/2fa/setup', jwtMiddleware, setup2FA);
router.post('/2fa/verify', jwtMiddleware, verify2FA);
router.post('/2fa/disable', jwtMiddleware, disable2FA);

export default router;