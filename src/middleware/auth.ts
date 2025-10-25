import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User, { IUser } from '../models/user.js';
import { JWTPayload } from '../types/custom.js';
import logger from '../utils/logger.js';

/**
 * Middleware to authenticate JWT tokens and validate sessions
 */
export const authenticateToken = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const startTime = Date.now();
  const requestId = req.headers['x-request-id'] || 'unknown';
  
  logger.debug('[AUTH] Starting token authentication', {
    requestId,
    method: req.method,
    path: req.path,
    userAgent: req.headers['user-agent'],
    ip: req.ip
  });

  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      logger.debug('[AUTH] No token provided', { requestId, path: req.path });
      res.status(401).json({ 
        error: 'Access token required',
        code: 'NO_TOKEN'
      });
      return;
    }

    if (!process.env.JWT_SECRET) {
      logger.error('[AUTH] JWT_SECRET not configured', { requestId });
      throw new Error('JWT_SECRET not configured');
    }

    // Verify access token
    logger.debug('[AUTH] Verifying JWT token', { requestId, tokenLength: token.length });
    const payload = jwt.verify(token, process.env.JWT_SECRET) as JWTPayload;
    
    logger.debug('[AUTH] JWT verified successfully', { 
      requestId, 
      userId: payload.userId, 
      sessionId: payload.sessionId,
      tokenIssuedAt: new Date(payload.iat * 1000).toISOString()
    });
    
    // Find user and validate session
    const user = await User.findById(payload.userId);
    if (!user) {
      logger.warn('[AUTH] User not found for token', { 
        requestId, 
        userId: payload.userId,
        sessionId: payload.sessionId
      });
      res.status(401).json({ 
        error: 'Invalid token - user not found',
        code: 'USER_NOT_FOUND'
      });
      return;
    }

    logger.debug('[AUTH] User found', { 
      requestId, 
      userId: user._id, 
      username: user.username,
      activeSessionsCount: user.sessions?.length || 0
    });

    // Check if session exists and is active
    const session = user.sessions?.find((s: any) => 
      s.sessionId === payload.sessionId && 
      s.isActive && 
      s.expiresAt > new Date()
    );

    if (!session) {
      logger.warn('[AUTH] Session not found or invalid', { 
        requestId, 
        userId: user._id,
        sessionId: payload.sessionId,
        availableSessions: user.sessions?.map((s: any) => ({
          sessionId: s.sessionId,
          isActive: s.isActive,
          expiresAt: s.expiresAt,
          expired: s.expiresAt <= new Date()
        })) || []
      });
      res.status(401).json({ 
        error: 'Invalid session',
        code: 'SESSION_INVALID'
      });
      return;
    }

    logger.debug('[AUTH] Session found and validated', { 
      requestId, 
      userId: user._id,
      sessionId: payload.sessionId,
      sessionLastActivity: session.lastActivity,
      sessionExpiresAt: session.expiresAt
    });

    // Check if password was changed after token was issued
    if (user.passwordChangedAt && new Date(payload.iat * 1000) < user.passwordChangedAt) {
      logger.warn('[AUTH] Password changed after token issued', { 
        requestId, 
        userId: user._id,
        sessionId: payload.sessionId,
        tokenIssuedAt: new Date(payload.iat * 1000).toISOString(),
        passwordChangedAt: user.passwordChangedAt.toISOString()
      });
      res.status(401).json({ 
        error: 'Password recently changed. Please login again.',
        code: 'PASSWORD_CHANGED'
      });
      return;
    }

    // Update last activity
    logger.debug('[AUTH] Updating session last activity', { 
      requestId, 
      userId: user._id,
      sessionId: payload.sessionId
    });
    
    user.sessions = user.sessions?.map((s: any) => 
      s.sessionId === payload.sessionId 
        ? { ...s, lastActivity: new Date() }
        : s
    ) || [];
    await user.save();

    // Attach user and session info to request
    req.user = user;
    req.sessionId = payload.sessionId;
    
    const duration = Date.now() - startTime;
    logger.debug('[AUTH] Authentication successful', { 
      requestId, 
      userId: user._id,
      username: user.username,
      sessionId: payload.sessionId,
      duration: `${duration}ms`
    });
    
    next();
  } catch (error) {
    const duration = Date.now() - startTime;
    
    if (error instanceof jwt.JsonWebTokenError) {
      logger.warn('[AUTH] Invalid JWT token', { 
        requestId, 
        error: error.message,
        duration: `${duration}ms`,
        path: req.path
      });
      res.status(401).json({ 
        error: 'Invalid token',
        code: 'TOKEN_INVALID'
      });
      return;
    }
    
    if (error instanceof jwt.TokenExpiredError) {
      logger.warn('[AUTH] JWT token expired', { 
        requestId, 
        error: error.message,
        duration: `${duration}ms`,
        path: req.path
      });
      res.status(401).json({ 
        error: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
      return;
    }

    logger.error('[AUTH] Authentication error', { 
      requestId, 
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      duration: `${duration}ms`,
      path: req.path
    });
    res.status(500).json({ 
      error: 'Authentication failed',
      code: 'AUTH_ERROR'
    });
  }
};

/**
 * Middleware to authenticate refresh tokens
 */
export const authenticateRefreshToken = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const startTime = Date.now();
  const requestId = req.headers['x-request-id'] || 'unknown';
  
  logger.debug('[REFRESH] Starting refresh token authentication', {
    requestId,
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  try {
    const { refreshToken, sessionId } = req.body;

    if (!refreshToken || !sessionId) {
      logger.debug('[REFRESH] Missing refresh data', { 
        requestId, 
        hasRefreshToken: !!refreshToken,
        hasSessionId: !!sessionId
      });
      res.status(401).json({ 
        error: 'Refresh token and session ID required',
        code: 'MISSING_REFRESH_DATA'
      });
      return;
    }

    if (!process.env.JWT_REFRESH_SECRET) {
      logger.error('[REFRESH] JWT_REFRESH_SECRET not configured', { requestId });
      throw new Error('JWT_REFRESH_SECRET not configured');
    }

    // Verify refresh token
    logger.debug('[REFRESH] Verifying refresh token', { 
      requestId, 
      sessionId,
      refreshTokenLength: refreshToken.length
    });
    const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET) as JWTPayload;
    
    logger.debug('[REFRESH] Refresh token verified', { 
      requestId, 
      userId: payload.userId,
      sessionId: payload.sessionId,
      requestedSessionId: sessionId
    });
    
    // Find user
    const user = await User.findById(payload.userId);
    if (!user) {
      logger.warn('[REFRESH] User not found for refresh token', { 
        requestId, 
        userId: payload.userId,
        sessionId
      });
      res.status(401).json({ 
        error: 'Invalid refresh token - user not found',
        code: 'USER_NOT_FOUND'
      });
      return;
    }

    logger.debug('[REFRESH] User found for refresh', { 
      requestId, 
      userId: user._id,
      username: user.username,
      activeSessionsCount: user.sessions?.length || 0
    });

    // Validate session and refresh token
    const session = user.sessions?.find((s: any) => 
      s.sessionId === sessionId && 
      s.refreshToken === refreshToken &&
      s.isActive && 
      s.expiresAt > new Date()
    );

    if (!session) {
      logger.warn('[REFRESH] Invalid refresh session', { 
        requestId, 
        userId: user._id,
        sessionId,
        availableSessions: user.sessions?.map((s: any) => ({
          sessionId: s.sessionId,
          isActive: s.isActive,
          expiresAt: s.expiresAt,
          tokenMatches: s.refreshToken === refreshToken
        })) || []
      });
      res.status(401).json({ 
        error: 'Invalid refresh session',
        code: 'REFRESH_SESSION_INVALID'
      });
      return;
    }

    logger.debug('[REFRESH] Refresh session validated', { 
      requestId, 
      userId: user._id,
      sessionId,
      sessionLastActivity: session.lastActivity
    });

    // Attach user and session info to request
    req.user = user;
    req.sessionId = sessionId;
    
    const duration = Date.now() - startTime;
    logger.debug('[REFRESH] Refresh token authentication successful', { 
      requestId, 
      userId: user._id,
      sessionId,
      duration: `${duration}ms`
    });
    
    next();
  } catch (error) {
    const duration = Date.now() - startTime;
    
    if (error instanceof jwt.JsonWebTokenError) {
      logger.warn('[REFRESH] Invalid refresh token', { 
        requestId, 
        error: error.message,
        duration: `${duration}ms`
      });
      res.status(401).json({ 
        error: 'Invalid refresh token',
        code: 'REFRESH_TOKEN_INVALID'
      });
      return;
    }
    
    if (error instanceof jwt.TokenExpiredError) {
      logger.warn('[REFRESH] Refresh token expired', { 
        requestId, 
        error: error.message,
        duration: `${duration}ms`
      });
      res.status(401).json({ 
        error: 'Refresh token expired',
        code: 'REFRESH_TOKEN_EXPIRED'
      });
      return;
    }

    logger.error('[REFRESH] Refresh authentication error', { 
      requestId, 
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      duration: `${duration}ms`
    });
    res.status(500).json({ 
      error: 'Refresh authentication failed',
      code: 'REFRESH_AUTH_ERROR'
    });
  }
};

/**
 * Middleware to check if user's email is verified
 */
export const requireEmailVerification = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const requestId = req.headers['x-request-id'] || 'unknown';
  const userId = req.user?._id;
  const emailVerified = req.user?.emailVerification?.emailVerified;
  
  logger.debug('[EMAIL_VERIFICATION] Checking email verification status', {
    requestId,
    userId,
    emailVerified,
    hasUser: !!req.user
  });

  if (!req.user?.emailVerification?.emailVerified) {
    logger.warn('[EMAIL_VERIFICATION] Email verification required', {
      requestId,
      userId,
      email: req.user?.email
    });
    res.status(403).json({
      error: 'Email verification required',
      code: 'EMAIL_NOT_VERIFIED'
    });
    return;
  }
  
  logger.debug('[EMAIL_VERIFICATION] Email verification passed', {
    requestId,
    userId
  });
  next();
};

/**
 * Middleware to check user roles
 */
export const requireRole = (roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const requestId = req.headers['x-request-id'] || 'unknown';
    const userId = req.user?._id;
    const userRole = req.user?.role;
    
    logger.debug('[ROLE_CHECK] Checking user role permissions', {
      requestId,
      userId,
      userRole,
      requiredRoles: roles,
      hasUser: !!req.user
    });

    if (!req.user) {
      logger.warn('[ROLE_CHECK] No authenticated user for role check', {
        requestId,
        requiredRoles: roles
      });
      res.status(401).json({
        error: 'Authentication required',
        code: 'NOT_AUTHENTICATED'
      });
      return;
    }

    if (!req.user.role || !roles.includes(req.user.role)) {
      logger.warn('[ROLE_CHECK] Insufficient permissions', {
        requestId,
        userId,
        userRole: req.user.role,
        requiredRoles: roles
      });
      res.status(403).json({
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS',
        requiredRoles: roles,
        userRole: req.user.role
      });
      return;
    }

    logger.debug('[ROLE_CHECK] Role check passed', {
      requestId,
      userId,
      userRole: req.user.role,
      requiredRoles: roles
    });
    next();
  };
};

/**
 * Optional authentication - doesn't fail if no token provided
 */
export const optionalAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const requestId = req.headers['x-request-id'] || 'unknown';
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  logger.debug('[OPTIONAL_AUTH] Starting optional authentication', {
    requestId,
    hasToken: !!token,
    path: req.path
  });

  if (!token) {
    logger.debug('[OPTIONAL_AUTH] No token provided, continuing without auth', { requestId });
    next();
    return;
  }

  try {
    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET not configured');
    }

    const payload = jwt.verify(token, process.env.JWT_SECRET) as JWTPayload;
    const user = await User.findById(payload.userId);
    
    if (user) {
      const session = user.sessions?.find((s: any) => 
        s.sessionId === payload.sessionId && 
        s.isActive && 
        s.expiresAt > new Date()
      );

      if (session && (!user.passwordChangedAt || new Date(payload.iat * 1000) >= user.passwordChangedAt)) {
        req.user = user;
        req.sessionId = payload.sessionId;
        logger.debug('[OPTIONAL_AUTH] User authenticated successfully', {
          requestId,
          userId: user._id,
          username: user.username,
          sessionId: payload.sessionId
        });
      } else {
        logger.debug('[OPTIONAL_AUTH] Session invalid or password changed', {
          requestId,
          userId: user._id,
          sessionFound: !!session,
          passwordChanged: user.passwordChangedAt ? new Date(payload.iat * 1000) < user.passwordChangedAt : false
        });
      }
    } else {
      logger.debug('[OPTIONAL_AUTH] User not found', {
        requestId,
        userId: payload.userId
      });
    }
  } catch (error) {
    logger.debug('[OPTIONAL_AUTH] Authentication failed (ignored)', {
      requestId,
      error: error instanceof Error ? error.message : String(error)
    });
  }

  next();
};