import { IUser } from '../models/user.js';

declare global {
  namespace Express {
    interface Request {
      user?: IUser;
      sessionId?: string;
      requestId?: string;
    }
  }
}

export interface SessionData {
  sessionId: string;
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface LoginResponse {
  message: string;
  user: {
    id: string;
    username: string;
    email: string;
    name?: string;
    role?: string;
    emailVerified: boolean;
    lastLoginAt?: Date;
  };
  session: SessionData;
}

export interface SessionInfo {
  sessionId: string;
  lastActivity: Date;
  userAgent?: string;
  ipAddress?: string;
  isCurrent?: boolean;
}

export interface JWTPayload {
  userId: string;
  sessionId: string;
  iat: number;
  exp: number;
}

export interface AuthError {
  error: string;
  code: string;
  details?: string;
}