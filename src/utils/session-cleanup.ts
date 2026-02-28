import cron from 'node-cron';
import User from '../models/user.js';
import Session from '../models/session.js';
import logger from './logger.js';

/**
 * Clean up expired sessions from all users
 */
export const cleanupExpiredSessions = async (): Promise<void> => {
  try {
    logger.info('Starting session cleanup...');
    const now = new Date();

    const result = await Session.deleteMany({
      $or: [{ expiresAt: { $lte: now } }, { isActive: false }],
    });

    logger.info(`Session cleanup completed. Deleted ${result.deletedCount ?? 0} sessions.`);
  } catch (error) {
    logger.error('Session cleanup failed:', error);
  }
};

/**
 * Start automated session cleanup
 * Runs every hour
 */
export const startSessionCleanup = (): void => {
  // Run every hour
  cron.schedule('0 * * * *', async () => {
    await cleanupExpiredSessions();
  });
  
  logger.info('Session cleanup scheduler started (runs every hour)');
};

/**
 * Clean up sessions for a specific user
 */
export const cleanupUserSessions = async (userId: string): Promise<void> => {
  try {
    const now = new Date();
    await Session.deleteMany({
      userId,
      $or: [{ expiresAt: { $lte: now } }, { isActive: false }],
    });

    logger.debug(`Cleaned up sessions for user ${userId}`);
  } catch (error) {
    logger.error(`Failed to cleanup sessions for user ${userId}:`, error);
  }
};

/**
 * Get session statistics
 */
export const getSessionStats = async (): Promise<{
  totalUsers: number;
  usersWithActiveSessions: number;
  totalActiveSessions: number;
  expiredSessions: number;
}> => {
  try {
    const now = new Date();
    const totalUsers = await User.countDocuments();

    const totalActiveSessions = await Session.countDocuments({
      isActive: true,
      expiresAt: { $gt: now },
    });

    const userIdsWithActive = await Session.distinct('userId', {
      isActive: true,
      expiresAt: { $gt: now },
    });

    const expiredSessions = await Session.countDocuments({
      $or: [{ isActive: false }, { expiresAt: { $lte: now } }],
    });

    return {
      totalUsers,
      usersWithActiveSessions: userIdsWithActive.length,
      totalActiveSessions,
      expiredSessions,
    };
  } catch (error) {
    logger.error('Failed to get session stats:', error);
    return {
      totalUsers: 0,
      usersWithActiveSessions: 0,
      totalActiveSessions: 0,
      expiredSessions: 0
    };
  }
};