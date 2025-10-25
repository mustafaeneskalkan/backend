import cron from 'node-cron';
import User from '../models/user.js';
import logger from './logger.js';

/**
 * Clean up expired sessions from all users
 */
export const cleanupExpiredSessions = async (): Promise<void> => {
  try {
    logger.info('Starting session cleanup...');
    
    const result = await User.updateMany(
      {},
      {
        $pull: {
          sessions: {
            $or: [
              { expiresAt: { $lt: new Date() } },
              { isActive: false }
            ]
          }
        }
      }
    );

    logger.info(`Session cleanup completed. Modified ${result.modifiedCount} users.`);
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
    const user = await User.findById(userId);
    if (!user) {
      return;
    }

    user.sessions = user.sessions?.filter((session: any) => 
      session.expiresAt > new Date() && session.isActive
    ) || [];
    
    await user.save();
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
    const totalUsers = await User.countDocuments();
    
    const pipeline = [
      {
        $project: {
          activeSessions: {
            $filter: {
              input: '$sessions',
              cond: {
                $and: [
                  { $eq: ['$$this.isActive', true] },
                  { $gt: ['$$this.expiresAt', new Date()] }
                ]
              }
            }
          },
          expiredSessions: {
            $filter: {
              input: '$sessions',
              cond: {
                $or: [
                  { $eq: ['$$this.isActive', false] },
                  { $lt: ['$$this.expiresAt', new Date()] }
                ]
              }
            }
          }
        }
      },
      {
        $group: {
          _id: null,
          usersWithActiveSessions: {
            $sum: {
              $cond: [{ $gt: [{ $size: '$activeSessions' }, 0] }, 1, 0]
            }
          },
          totalActiveSessions: { $sum: { $size: '$activeSessions' } },
          expiredSessions: { $sum: { $size: '$expiredSessions' } }
        }
      }
    ];

    const result = await User.aggregate(pipeline);
    const stats = result[0] || {
      usersWithActiveSessions: 0,
      totalActiveSessions: 0,
      expiredSessions: 0
    };

    return {
      totalUsers,
      ...stats
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