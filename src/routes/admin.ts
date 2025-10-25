import express from 'express';
import { authenticateToken, requireRole } from '../middleware/auth.js';
import { getSessionStats, cleanupExpiredSessions } from '../utils/session-cleanup.js';

const router = express.Router();

/**
 * Get session statistics (Admin only)
 */
router.get('/stats', authenticateToken, requireRole(['Admin']), async (req, res, next) => {
  try {
    const stats = await getSessionStats();
    res.json(stats);
  } catch (error) {
    next(error);
  }
});

/**
 * Manually trigger session cleanup (Admin only)
 */
router.post('/cleanup', authenticateToken, requireRole(['Admin']), async (req, res, next) => {
  try {
    await cleanupExpiredSessions();
    res.json({ message: 'Session cleanup completed successfully' });
  } catch (error) {
    next(error);
  }
});

export default router;