import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User, { IUser } from '../models/user.js';
import Session from '../models/session.js';
import { JWTPayload } from '../types/custom.js';
import logger from '../utils/logger.js';
import { hashRefreshToken, safeEqualHex } from '../utils/token-hash.js';
import { ACCESS_TOKEN_COOKIE_NAME, REFRESH_TOKEN_COOKIE_NAME, SESSION_ID_COOKIE_NAME } from '../utils/cookies.js';

/**
 * Middleware to authenticate JWT tokens and validate sessions
 */
export const authenticateToken = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const startTime = Date.now();
  const requestId = req.requestId || req.headers['x-request-id'] || 'unknown';
  
  logger.debug('[AUTH] Starting token authentication', {
    requestId,
    method: req.method,
    path: req.path,
    userAgent: req.headers['user-agent'],
    ip: req.ip
  });

  try {
    const cookieToken = (req as any).cookies?.[ACCESS_TOKEN_COOKIE_NAME] as string | undefined;
    const token = cookieToken;

    if (!token) {
      logger.debug('[AUTH] No token provided', { requestId, path: req.path });
      res.status(401).json({ 
        error: 'Access token required',
        code: 'NO_TOKEN'
      });
      return;
    }

    if (!process.env.JWT_ACCESS_SECRET) {
      logger.error('[AUTH] JWT_ACCESS_SECRET not configured', { requestId });
      throw new Error('JWT_ACCESS_SECRET not configured');
    }

    // Verify access token
    logger.debug('[AUTH] Verifying JWT token', { requestId, tokenLength: token.length });
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET) as JWTPayload;
    
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

    const now = new Date();

    // Check if session exists and is active
    const session = await Session.findOne({
      userId: user._id,
      sessionId: payload.sessionId,
      isActive: true,
      expiresAt: { $gt: now }
    });

    if (!session) {
      logger.warn('[AUTH] Session not found or invalid', { 
        requestId, 
        userId: user._id,
        sessionId: payload.sessionId
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

    // Update last activity (throttled + targeted write)
    const throttleSecondsRaw = process.env.SESSION_ACTIVITY_THROTTLE_SECONDS;
    const throttleSeconds = throttleSecondsRaw ? Number(throttleSecondsRaw) : 300;
    const throttleMs = Number.isFinite(throttleSeconds) && throttleSeconds > 0 ? throttleSeconds * 1000 : 300_000;

    const lastActivityDate = session.lastActivity ? new Date(session.lastActivity) : undefined;
    const shouldUpdateLastActivity =
      !lastActivityDate || Number.isNaN(lastActivityDate.getTime()) || (Date.now() - lastActivityDate.getTime() > throttleMs);

    if (shouldUpdateLastActivity) {
      logger.debug('[AUTH] Updating session last activity (throttled)', {
        requestId,
        userId: user._id,
        sessionId: payload.sessionId,
        throttleMs
      });

      void Session.updateOne(
        { userId: user._id, sessionId: payload.sessionId },
        { $set: { lastActivity: new Date() } }
      ).catch((err: unknown) => {
        logger.warn('[AUTH] Failed to update session last activity', {
          requestId,
          userId: user._id,
          sessionId: payload.sessionId,
          error: err instanceof Error ? err.message : String(err)
        });
      });
    }

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
  const requestId = req.requestId || req.headers['x-request-id'] || 'unknown';
  
  logger.debug('[REFRESH] Starting refresh token authentication', {
    requestId,
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });

  try {
    const refreshToken = (req as any).cookies?.[REFRESH_TOKEN_COOKIE_NAME] as string | undefined;
    const sessionId = (req as any).cookies?.[SESSION_ID_COOKIE_NAME] as string | undefined;

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

    if (payload.sessionId !== sessionId) {
      logger.warn('[REFRESH] SessionId mismatch for refresh token', {
        requestId,
        userId: payload.userId,
        tokenSessionId: payload.sessionId,
        requestedSessionId: sessionId
      });
      res.status(401).json({
        error: 'Invalid refresh session',
        code: 'REFRESH_SESSION_MISMATCH'
      });
      return;
    }
    
    const presentedHash = hashRefreshToken(refreshToken);

    const now = new Date();
    const session = await Session.findOne({
      userId: payload.userId,
      sessionId,
      isActive: true,
      expiresAt: { $gt: now }
    });

    const tokenMatches = !!session && safeEqualHex(session.refreshTokenHash, presentedHash);

    if (!session || !tokenMatches) {
      logger.warn('[REFRESH] Invalid refresh session', { 
        requestId, 
        userId: payload.userId,
        sessionId,
        tokenMatches
      });
      res.status(401).json({ 
        error: 'Invalid refresh session',
        code: 'REFRESH_SESSION_INVALID'
      });
      return;
    }

    // Find user (after session check to avoid leaking user existence)
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

    // Check if password was changed after token was issued
    if (user.passwordChangedAt && new Date(payload.iat * 1000) < user.passwordChangedAt) {
      logger.warn('[REFRESH] Password changed after refresh token issued', {
        requestId,
        userId: user._id,
        sessionId
      });
      await Session.deleteOne({ _id: session._id }).catch(() => undefined);
      res.status(401).json({
        error: 'Password recently changed. Please login again.',
        code: 'PASSWORD_CHANGED'
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
  const requestId = req.requestId || req.headers['x-request-id'] || 'unknown';
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
    const requestId = req.requestId || req.headers['x-request-id'] || 'unknown';
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
  const requestId = req.requestId || req.headers['x-request-id'] || 'unknown';
  const token = (req as any).cookies?.[ACCESS_TOKEN_COOKIE_NAME] as string | undefined;

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
    if (!process.env.JWT_ACCESS_SECRET) {
      throw new Error('JWT_ACCESS_SECRET not configured');
    }

    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET) as JWTPayload;
    const user = await User.findById(payload.userId);
    
    if (user) {
      const session = await Session.findOne({
        userId: user._id,
        sessionId: payload.sessionId,
        isActive: true,
        expiresAt: { $gt: new Date() }
      });

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