import express from 'express';
import { uploadEncryptedChunk, getFileChunks } from '../controllers/fileController.js';
import jwtMiddleware from '../middleware/auth.js';

const router = express.Router();
router.use(jwtMiddleware);

router.post('/upload-chunk', uploadEncryptedChunk);
router.get('/download/:fileId', getFileChunks);

export default router;