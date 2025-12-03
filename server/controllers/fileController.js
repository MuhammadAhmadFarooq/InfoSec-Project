import FileChunk from '../models/FileChunk.js';
import { logger } from '../utils/logger.js';

export const uploadEncryptedChunk = async (req, res) => {
  try {
    const chunkData = {
      ...req.body,
      sender: req.userId
    };

    const chunk = new FileChunk(chunkData);
    await chunk.save();

    logger.info('Encrypted file chunk uploaded', {
      fileId: chunk.fileId,
      chunkIndex: chunk.chunkIndex,
      sender: req.userId
    });

    res.status(201).json({ success: true, chunkIndex: chunk.chunkIndex });
  } catch (error) {
    logger.error('File chunk upload failed', error);
    res.status(500).json({ error: 'Failed to upload chunk' });
  }
};

export const getFileChunks = async (req, res) => {
  try {
    const { fileId } = req.params;
    const chunks = await FileChunk.find({ fileId })
      .sort({ chunkIndex: 1 })
      .select('chunkIndex encryptedChunk iv tag totalChunks filename mimeType');

    if (chunks.length === 0) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.json({
      fileId,
      totalChunks: chunks[0].totalChunks,
      filename: chunks[0].filename,
      mimeType: chunks[0].mimeType || 'application/octet-stream',
      chunks: chunks.map(c => ({
        chunkIndex: c.chunkIndex,
        encryptedChunk: c.encryptedChunk,  // Already a base64 string
        iv: c.iv,
        tag: c.tag
      }))
    });
  } catch (error) {
    logger.error('Error downloading file', error);
    res.status(500).json({ error: 'Failed to retrieve file' });
  }
};