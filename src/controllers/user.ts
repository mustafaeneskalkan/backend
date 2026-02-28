import { Request, Response, NextFunction } from "express";
import User, { IUser } from "../models/user.js";
import Session from "../models/session.js";
import sendMail from "../utils/nodemailer.js";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import crypto from "crypto";
import { hashRefreshToken } from "../utils/token-hash.js";
import {
  ACCESS_TOKEN_COOKIE_NAME,
  REFRESH_TOKEN_COOKIE_NAME,
  SESSION_ID_COOKIE_NAME,
  getAuthCookieOptions,
  clearAuthCookies,
} from "../utils/cookies.js";

export class UserController {
  private getPasswordResetSecret(): string {
    const secret =
      process.env.JWT_PASSWORD_RESET_SECRET ||
      process.env.JWT_EMAIL_VERIFY_SECRET ||
      process.env.JWT_ACCESS_SECRET;

    if (!secret) {
      throw new Error(
        "JWT_PASSWORD_RESET_SECRET (or JWT_EMAIL_VERIFY_SECRET / JWT_ACCESS_SECRET fallback) is not configured"
      );
    }
    return secret;
  }

  private async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    if (!process.env.FRONTEND_URL) {
      throw new Error("FRONTEND_URL environment variable is not configured");
    }

    const subject = "Password reset request";
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

    const text = `We received a request to reset your password.\n\nReset your password here: ${resetUrl}\n\nThis link will expire in 2 hours. If you didn't request this, you can ignore this email.`;

    const html = `
      <p>We received a request to reset your password.</p>
      <p><a href="${resetUrl}">Reset your password</a></p>
      <p>This link will expire in 2 hours. If you didn't request this, you can ignore this email.</p>
    `;

    await sendMail(email, subject, text, html);
  }

  private async issueSessionForUser(
    user: IUser,
    req: Request,
    res: Response
  ): Promise<{ sessionId: string; expiresIn: number }> {
    const userAgent = req.headers["user-agent"];
    const ipAddress = req.ip || req.connection.remoteAddress;

    const accessSecret = process.env.JWT_ACCESS_SECRET;
    const refreshSecret = process.env.JWT_REFRESH_SECRET;
    if (!accessSecret || !refreshSecret) {
      throw new Error(
        "JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be configured"
      );
    }

    const now = new Date();
    const sessionId = crypto.randomUUID();

    const accessToken = jwt.sign(
      { userId: user._id, sessionId },
      accessSecret,
      { expiresIn: "15m" }
    );
    const refreshToken = jwt.sign(
      { userId: user._id, sessionId },
      refreshSecret,
      { expiresIn: "7d" }
    );

    const refreshTokenHash = hashRefreshToken(refreshToken);
    const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

    // Best-effort cleanup of stale sessions for this user
    await Session.deleteMany({
      userId: user._id,
      $or: [{ expiresAt: { $lte: now } }, { isActive: false }],
    });

    // Enforce a cap on active sessions per user (default: 5)
    const maxRaw = process.env.MAX_ACTIVE_SESSIONS_PER_USER;
    const maxActiveSessions = maxRaw ? Number(maxRaw) : 5;
    if (Number.isFinite(maxActiveSessions) && maxActiveSessions > 0) {
      const active = await Session.find({
        userId: user._id,
        isActive: true,
        expiresAt: { $gt: now },
      })
        .sort({ createdAt: 1 })
        .select({ _id: 1 })
        .lean();

      const overflow = active.length - (maxActiveSessions - 1);
      if (overflow > 0) {
        const toDelete = active.slice(0, overflow).map((s) => s._id);
        await Session.deleteMany({ _id: { $in: toDelete } });
      }
    }

    await Session.create({
      userId: user._id,
      sessionId,
      refreshTokenHash,
      expiresAt,
      isActive: true,
      userAgent,
      ipAddress,
      lastActivity: now,
    });

    user.lastLoginAt = now;
    await user.save();

    // Cookie-based auth: store tokens in httpOnly cookies
    res.cookie(
      ACCESS_TOKEN_COOKIE_NAME,
      accessToken,
      getAuthCookieOptions(15 * 60 * 1000, "/")
    );
    res.cookie(
      REFRESH_TOKEN_COOKIE_NAME,
      refreshToken,
      getAuthCookieOptions(7 * 24 * 60 * 60 * 1000, "/api/users")
    );
    res.cookie(
      SESSION_ID_COOKIE_NAME,
      sessionId,
      getAuthCookieOptions(7 * 24 * 60 * 60 * 1000, "/api/users")
    );

    return { sessionId, expiresIn: 900 };
  }

  private async issueSessionForAdmin(
    user: IUser,
    req: Request,
    res: Response
  ): Promise<{ sessionId: string; expiresIn: number }> {
    const userAgent = req.headers["user-agent"];
    const ipAddress = req.ip || req.connection.remoteAddress;

    const accessSecret = process.env.JWT_ACCESS_SECRET;
    const refreshSecret = process.env.JWT_REFRESH_SECRET;
    if (!accessSecret || !refreshSecret) {
      throw new Error(
        "JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be configured"
      );
    }

    const now = new Date();
    const sessionId = crypto.randomUUID();

    const accessToken = jwt.sign(
      { userId: user._id, sessionId },
      accessSecret,
      { expiresIn: "15m" }
    );
    const refreshToken = jwt.sign(
      { userId: user._id, sessionId },
      refreshSecret,
      { expiresIn: "7d" }
    );

    const refreshTokenHash = hashRefreshToken(refreshToken);
    const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

    // Best-effort cleanup of stale sessions for this user
    await Session.deleteMany({
      userId: user._id,
      $or: [{ expiresAt: { $lte: now } }, { isActive: false }],
    });

    // Enforce a cap on active sessions per user (default: 5)
    const maxRaw = process.env.MAX_ACTIVE_SESSIONS_PER_USER;
    const maxActiveSessions = maxRaw ? Number(maxRaw) : 5;
    if (Number.isFinite(maxActiveSessions) && maxActiveSessions > 0) {
      const active = await Session.find({
        userId: user._id,
        isActive: true,
        expiresAt: { $gt: now },
      })
        .sort({ createdAt: 1 })
        .select({ _id: 1 })
        .lean();

      const overflow = active.length - (maxActiveSessions - 1);
      if (overflow > 0) {
        const toDelete = active.slice(0, overflow).map((s) => s._id);
        await Session.deleteMany({ _id: { $in: toDelete } });
      }
    }

    await Session.create({
      userId: user._id,
      sessionId,
      refreshTokenHash,
      expiresAt,
      isActive: true,
      userAgent,
      ipAddress,
      lastActivity: now,
    });

    user.lastLoginAt = now;
    await user.save();

    // Cookie-based auth: store tokens in httpOnly cookies
    res.cookie(
      ACCESS_TOKEN_COOKIE_NAME,
      accessToken,
      getAuthCookieOptions(15 * 60 * 1000, "/")
    );
    res.cookie(
      REFRESH_TOKEN_COOKIE_NAME,
      refreshToken,
      getAuthCookieOptions(7 * 24 * 60 * 60 * 1000, "/api/backend/api/admin/auth/login")
    );
    res.cookie(
      SESSION_ID_COOKIE_NAME,
      sessionId,
      getAuthCookieOptions(7 * 24 * 60 * 60 * 1000, "/api/backend/api/admin/auth/login")
    );

    return { sessionId, expiresIn: 900 };
  }

  /**
   * Validate the email string.
   * @param email - Email string to validate
   * @returns True if the email is valid, false otherwise
   */
  private validateEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
  /**
   * Validate the password string.
   * @param password - Password string to validate
   * @returns An object containing the validation result and an optional error message
   */
  private validatePassword(password: string): {
    isValid: boolean;
    message?: string;
  } {
    if (password.length < 8) {
      return {
        isValid: false,
        message: "Password must be at least 8 characters long",
      };
    }
    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
      return {
        isValid: false,
        message:
          "Password must contain at least one uppercase letter, one lowercase letter, and one number",
      };
    }
    return { isValid: true };
  }

  /**
   * Validate the username string.
   * @param username - Username string to validate
   * @returns An object containing the validation result and an optional error message
   */
  private validateUsername(username: string): {
    isValid: boolean;
    message?: string;
  } {
    if (username.length < 3) {
      return {
        isValid: false,
        message: "Username must be at least 3 characters long",
      };
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return {
        isValid: false,
        message: "Username can only contain letters, numbers, and underscores",
      };
    }
    return { isValid: true };
  }

  /**
   * User registration with comprehensive validation
   * @param req - Express request object
   * @param res - Express response object
   * @param next - Express next middleware function
   * @returns
   */
  async register(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { username, email, password } = req.body as {
        username: string;
        email: string;
        password: string;
      };

      // Input validation
      if (!username || !email || !password) {
        res.status(400).json({
          error: "Missing required fields",
          details: "Username, email, and password are required",
        });
        return;
      }

      // Validate email format
      if (!this.validateEmail(email)) {
        res.status(400).json({
          error: "Invalid email format",
        });
        return;
      }

      // Validate username
      const usernameValidation = this.validateUsername(username);
      if (!usernameValidation.isValid) {
        res.status(400).json({
          error: "Invalid username",
          details: usernameValidation.message,
        });
        return;
      }

      // Validate password
      const passwordValidation = this.validatePassword(password);
      if (!passwordValidation.isValid) {
        res.status(400).json({
          error: "Invalid password",
          details: passwordValidation.message,
        });
        return;
      }

      // Check if user already exists
      const existingUser = await User.findOne({
        $or: [{ email: email.toLowerCase() }, { username }],
      });

      if (existingUser) {
        const field =
          existingUser.email === email.toLowerCase() ? "email" : "username";
        res.status(409).json({
          error: `User with this ${field} already exists`,
        });
        return;
      }

      // Create user
      const user = await User.create({
        username,
        email: email.toLowerCase(),
        password,
      });

      // Generate and send verification email
      const token = await this.createEmailVerificationToken(user);
      await this.sendVerificationEmail(email, token);

      const session = await this.issueSessionForUser(user, req, res);

      res.status(201).json({
        message:
          "User registered successfully. Please check your email for verification.",
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          emailVerified: user.emailVerification?.emailVerified || false,
        },
        session,
      });
    } catch (error) {
      // Handle mongoose validation errors
      if (error instanceof mongoose.Error.ValidationError) {
        const validationErrors = Object.values(error.errors).map(
          (err) => err.message
        );
        res.status(400).json({
          error: "Validation failed",
          details: validationErrors,
        });
        return;
      }

      // Handle duplicate key errors
      if ((error as any).code === 11000) {
        const field = Object.keys((error as any).keyPattern)[0];
        res.status(409).json({
          error: `User with this ${field} already exists`,
        });
        return;
      }

      next(error as Error);
    }
  }

  /**
   * Change password (authenticated)
   * Invalidates all sessions (handled in User pre-save hook) and clears auth cookies.
   */
  async changePassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { currentPassword, newPassword } = req.body as {
        currentPassword: string;
        newPassword: string;
      };

      if (!currentPassword || !newPassword) {
        res.status(400).json({
          error: "Missing required fields",
          details: "currentPassword and newPassword are required",
        });
        return;
      }

      const user = req.user!;
      const isMatch = await user.comparePassword(currentPassword);
      if (!isMatch) {
        res.status(401).json({ error: "Invalid current password" });
        return;
      }

      const passwordValidation = this.validatePassword(newPassword);
      if (!passwordValidation.isValid) {
        res.status(400).json({
          error: "Invalid password",
          details: passwordValidation.message,
        });
        return;
      }

      // Clear any outstanding reset token and update password
      (user as any).passwordChange = {};
      user.password = newPassword;
      await user.save();

      clearAuthCookies(res);
      res.status(200).json({
        message: "Password changed successfully. Please login again.",
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Request a password reset (public)
   * Always responds 200 for valid-looking requests to avoid user enumeration.
   */
  async requestPasswordReset(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { email } = req.body as { email: string };

      if (!email) {
        res.status(400).json({
          error: "Missing required fields",
          details: "email is required",
        });
        return;
      }

      if (!this.validateEmail(email)) {
        res.status(400).json({
          error: "Invalid email format",
        });
        return;
      }

      const user = await User.findOne({ email: email.toLowerCase() });
      if (user) {
        const secret = this.getPasswordResetSecret();
        const token = jwt.sign(
          { userId: user._id, purpose: "password-reset" },
          secret,
          { expiresIn: "2h" }
        );

        const expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000);
        await (user as any).setPasswordChangeToken(token, expiresAt);
        await this.sendPasswordResetEmail(user.email, token);
      }

      res.status(200).json({
        message: "If an account exists for this email, a reset link has been sent.",
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Reset password using email-delivered token (public)
   */
  async resetPassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { token, newPassword } = req.body as { token: string; newPassword: string };

      if (!token || !newPassword) {
        res.status(400).json({
          error: "Missing required fields",
          details: "token and newPassword are required",
        });
        return;
      }

      const passwordValidation = this.validatePassword(newPassword);
      if (!passwordValidation.isValid) {
        res.status(400).json({
          error: "Invalid password",
          details: passwordValidation.message,
        });
        return;
      }

      const secret = this.getPasswordResetSecret();
      let payload: any;
      try {
        payload = jwt.verify(token, secret);
      } catch {
        res.status(400).json({ error: "Invalid or expired token" });
        return;
      }

      if (!payload?.userId || payload?.purpose !== "password-reset") {
        res.status(400).json({ error: "Invalid or expired token" });
        return;
      }

      const user = await User.findById(payload.userId);
      if (!user) {
        res.status(400).json({ error: "Invalid or expired token" });
        return;
      }

      const storedToken = (user as any).passwordChange?.token as string | undefined;
      const storedExpires = (user as any).passwordChange?.tokenExpires as Date | undefined;
      if (!storedToken || storedToken !== token) {
        res.status(400).json({ error: "Invalid or expired token" });
        return;
      }

      if (storedExpires && new Date(storedExpires).getTime() <= Date.now()) {
        res.status(400).json({ error: "Invalid or expired token" });
        return;
      }

      (user as any).passwordChange = {};
      user.password = newPassword;
      await user.save();

      res.status(200).json({ message: "Password reset successful" });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Send verification email to user
   * @param {string} email - Recipient email
   * @param {string} token - Verification token
   */
  async sendVerificationEmail(email: string, token: string): Promise<void> {
    try {
      // Validate inputs
      if (!email || !token) {
        throw new Error("Email and token are required");
      }

      if (!this.validateEmail(email)) {
        throw new Error("Invalid email format");
      }

      if (!process.env.FRONTEND_URL) {
        throw new Error("FRONTEND_URL environment variable is not configured");
      }

      const subject = "Welcome! Please verify your email address";
      const text = `Welcome to our platform! To complete your registration and secure your account, please verify your email address by visiting: ${process.env.FRONTEND_URL}/verify-email?token=${token}

This link will expire in 2 hours for your security. If you didn't create an account, please ignore this email.

Thank you for joining us!`;

      const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Verification</title>
        <style>
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
          }
          .container {
            max-width: 600px;
            margin: 20px auto;
            background: #ffffff;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            overflow: hidden;
          }
          .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
          }
          .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 300;
          }
          .content {
            padding: 40px 30px;
          }
          .welcome-text {
            font-size: 18px;
            color: #555;
            margin-bottom: 25px;
            text-align: center;
          }
          .message {
            font-size: 16px;
            color: #666;
            margin-bottom: 30px;
            line-height: 1.8;
          }
          .verify-button {
            display: block;
            width: 250px;
            margin: 30px auto;
            padding: 15px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 50px;
            text-align: center;
            font-weight: 600;
            font-size: 16px;
            transition: transform 0.2s ease;
          }
          .verify-button:hover {
            transform: translateY(-2px);
          }
          .security-note {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 15px 20px;
            margin: 25px 0;
            font-size: 14px;
            color: #666;
          }
          .footer {
            background: #f8f9fa;
            padding: 20px 30px;
            text-align: center;
            font-size: 14px;
            color: #888;
            border-top: 1px solid #eee;
          }
          .link-fallback {
            word-break: break-all;
            font-size: 12px;
            color: #999;
            margin-top: 20px;
          }

          /* Dark mode styles */
          @media (prefers-color-scheme: dark) {
            body {
              color: #e1e1e1;
              background-color: #1a1a1a;
            }
            .container {
              background: #2d2d2d;
              box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            }
            .header {
              background: linear-gradient(135deg, #5a6fd8 0%, #6b4e93 100%);
            }
            .welcome-text {
              color: #c1c1c1;
            }
            .message {
              color: #b1b1b1;
            }
            .verify-button {
              background: linear-gradient(135deg, #5a6fd8 0%, #6b4e93 100%);
            }
            .verify-button:hover {
              background: linear-gradient(135deg, #4a5fc8 0%, #5b3e83 100%);
            }
            .security-note {
              background: #3a3a3a;
              border-left: 4px solid #5a6fd8;
              color: #b1b1b1;
            }
            .footer {
              background: #3a3a3a;
              color: #999;
              border-top: 1px solid #444;
            }
            .link-fallback {
              color: #888;
            }
            p[style*="color: #666"] {
              color: #b1b1b1 !important;
            }
            p[style*="color: #888"] {
              color: #999 !important;
            }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Welcome to Our Platform!</h1>
          </div>
          <div class="content">
            <p class="welcome-text">🎉 Thank you for joining us!</p>
            <p class="message">
              To complete your registration and secure your account, please verify your email address by clicking the button below.
            </p>
            <a href="${process.env.FRONTEND_URL}/verify-email?token=${token}" class="verify-button">
              Verify My Email Address
            </a>
            <div class="security-note">
              <strong>Security Notice:</strong> This verification link will expire in 2 hours for your protection. If you didn't create an account with us, please ignore this email.
            </div>
            <p style="text-align: center; color: #666; font-size: 14px;">
              If the button doesn't work, copy and paste this link into your browser:
            </p>
            <p class="link-fallback">
              ${process.env.FRONTEND_URL}/verify-email?token=${token}
            </p>
          </div>
          <div class="footer">
            <p>Thank you for choosing our platform. We're excited to have you on board!</p>
            <p style="margin-top: 10px; font-size: 12px;">
              This is an automated message, please do not reply to this email.
            </p>
          </div>
        </div>
      </body>
      </html>
    `;

      await sendMail(email, subject, text, html);
    } catch (error) {
      throw new Error(
        `Failed to send verification email: ${
          error instanceof Error ? error.message : "Unknown error"
        }`
      );
    }
  }

  /**
   * Send email change verification email to user
   * @param {string} email - Recipient email
   * @param {string} token - Verification token
   */
  async sendEmailChangeVerification(email: string, token: string): Promise<void> {
    try {
      // Validate inputs
      if (!email || !token) {
        throw new Error("Email and token are required");
      }

      if (!this.validateEmail(email)) {
        throw new Error("Invalid email format");
      }

      if (!process.env.FRONTEND_URL) {
        throw new Error("FRONTEND_URL environment variable is not configured");
      }

      const subject = "Please verify your new email address";
      const text = `We received a request to change the email on your account to this address. To confirm and complete the change, please visit: ${process.env.FRONTEND_URL}/verify-email-change?token=${token}

This verification link will expire in 2 hours for your security. If you didn't request this email change, please contact our support team immediately.

Verifying your email ensures you can receive important account notifications and security alerts.`;

      const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Change Verification</title>
        <style>
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
          }
          .container {
            max-width: 600px;
            margin: 20px auto;
            background: #ffffff;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            overflow: hidden;
          }
          .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
          }
          .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 300;
          }
          .content {
            padding: 40px 30px;
          }
          .welcome-text {
            font-size: 18px;
            color: #555;
            margin-bottom: 25px;
            text-align: center;
          }
          .message {
            font-size: 16px;
            color: #666;
            margin-bottom: 30px;
            line-height: 1.8;
          }
          .verify-button {
            display: block;
            width: 250px;
            margin: 30px auto;
            padding: 15px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 50px;
            text-align: center;
            font-weight: 600;
            font-size: 16px;
            transition: transform 0.2s ease;
          }
          .verify-button:hover {
            transform: translateY(-2px);
          }
          .security-note {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 15px 20px;
            margin: 25px 0;
            font-size: 14px;
            color: #666;
          }
          .footer {
            background: #f8f9fa;
            padding: 20px 30px;
            text-align: center;
            font-size: 14px;
            color: #888;
            border-top: 1px solid #eee;
          }
          .link-fallback {
            word-break: break-all;
            font-size: 12px;
            color: #999;
            margin-top: 20px;
          }

          /* Dark mode styles */
          @media (prefers-color-scheme: dark) {
            body {
              color: #e1e1e1;
              background-color: #1a1a1a;
            }
            .container {
              background: #2d2d2d;
              box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            }
            .header {
              background: linear-gradient(135deg, #5a6fd8 0%, #6b4e93 100%);
            }
            .welcome-text {
              color: #c1c1c1;
            }
            .message {
              color: #b1b1b1;
            }
            .verify-button {
              background: linear-gradient(135deg, #5a6fd8 0%, #6b4e93 100%);
            }
            .verify-button:hover {
              background: linear-gradient(135deg, #4a5fc8 0%, #5b3e83 100%);
            }
            .security-note {
              background: #3a3a3a;
              border-left: 4px solid #5a6fd8;
              color: #b1b1b1;
            }
            .footer {
              background: #3a3a3a;
              color: #999;
              border-top: 1px solid #444;
            }
            .link-fallback {
              color: #888;
            }
            p[style*="color: #666"] {
              color: #b1b1b1 !important;
            }
            p[style*="color: #888"] {
              color: #999 !important;
            }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Email Change Verification</h1>
          </div>
          <div class="content">
            <p class="welcome-text">Confirm your new email</p>
            <p class="message">
              We received a request to change the email on your account to this address. To confirm and complete the change, please click the button below.
            </p>
            <a href="${process.env.FRONTEND_URL}/verify-email-change?token=${token}" class="verify-button">
              Verify New Email Address
            </a>
            <div class="security-note">
              <strong>Security Notice:</strong> This verification link will expire in 2 hours for your protection. If you didn't request this email change, please contact our support team immediately as your account security may be compromised.
            </div>
            <p style="text-align: center; color: #666; font-size: 14px;">
              If the button doesn't work, copy and paste this link into your browser:
            </p>
            <p class="link-fallback">
              ${process.env.FRONTEND_URL}/verify-email-change?token=${token}
            </p>
          </div>
          <div class="footer">
            <p>Verifying your email ensures you can receive important account notifications and security alerts.</p>
            <p style="margin-top: 10px; font-size: 12px;">
              This is an automated message, please do not reply to this email.
            </p>
          </div>
        </div>
      </body>
      </html>
    `;

      await sendMail(email, subject, text, html);
    } catch (error) {
      throw new Error(
        `Failed to send email change verification email: ${
          error instanceof Error ? error.message : "Unknown error"
        }`
      );
    }
  }

  /**
   * Create token for email verification and store it in database
   * @param {IUser} user - User instance
   * @returns {Promise<string>} Verification token
   */
  async createEmailVerificationToken(user: IUser): Promise<string> {
    try {
      const emailSecret = process.env.JWT_EMAIL_VERIFY_SECRET;
      if (!emailSecret) {
        throw new Error("JWT_EMAIL_VERIFY_SECRET is not configured");
      }

      const token = jwt.sign({ userId: user._id }, emailSecret, {
        expiresIn: "2h",
      });

      // Set expiration time to 2 hours from now
      const expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000);
      await user.setVerificationToken(token, expiresAt);

      return token;
    } catch (error) {
      throw new Error(
        `Failed to create email verification token: ${
          error instanceof Error ? error.message : "Unknown error"
        }`
      );
    }
  }
  /**
   * Check if a string is a valid email address
   * @param str - string to check
   * @returns true if the string is a valid email address, false otherwise
   */
  private isEmail(str: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(str);
  }

  private generateToken(user: IUser): string {
    const emailSecret = process.env.JWT_EMAIL_VERIFY_SECRET;
    if (!emailSecret) {
      throw new Error("JWT_EMAIL_VERIFY_SECRET is not configured");
    }

    const token = jwt.sign({ userId: user._id }, emailSecret, {
      expiresIn: "2h",
    });

    return token;
  }

  /**
   * User login with session management
   * @param req Request
   * @param res Response
   * @param next NextFunction
   * @returns
   */
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { usernameOrEmail, password } = req.body as {
        usernameOrEmail: string;
        password: string;
      };

      // Input validation
      if (!usernameOrEmail || !password) {
        res.status(400).json({
          error: "Missing required fields",
          details: "Username/email and password are required",
        });
        return;
      }

      let user;

      if (this.isEmail(usernameOrEmail)) {
        // Login with email
        user = await User.findOne({ email: usernameOrEmail.toLowerCase() });
        if (!user) {
          res.status(401).json({ error: "Invalid email or password" });
          return;
        }
      } else {
        // Login with username
        user = await User.findOne({ username: usernameOrEmail });
        if (!user) {
          res.status(401).json({ error: "Invalid username or password" });
          return;
        }
      }

      // Check password
      const isMatch = await user.comparePassword(password);
      if (!isMatch) {
        res.status(401).json({ error: "Invalid credentials" });
        return;
      }

      // Create new session
      const session = await this.issueSessionForUser(user, req, res);

      res.status(200).json({
        message: "Login successful",
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          name: user.name,
          role: user.role,
          emailVerified: user.emailVerification?.emailVerified || false,
          lastLoginAt: user.lastLoginAt,
        },
        session,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Admin login (intended for CMS access only).
   * Requires an existing user with role "Admin".
   */
  async loginAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { usernameOrEmail, password } = req.body as {
        usernameOrEmail: string;
        password: string;
      };

      if (!usernameOrEmail || !password) {
        res.status(400).json({
          error: "Missing required fields",
          details: "Username/email and password are required",
        });
        return;
      }

      const query = this.isEmail(usernameOrEmail)
        ? { email: usernameOrEmail.toLowerCase() }
        : { username: usernameOrEmail };

      const user = await User.findOne(query);
      if (!user) {
        res.status(401).json({ error: "Invalid credentials" });
        return;
      }

      const isMatch = await user.comparePassword(password);
      if (!isMatch) {
        res.status(401).json({ error: "Invalid credentials" });
        return;
      }

      if (user.role !== "Admin") {
        res.status(403).json({
          error: "Insufficient permissions",
          code: "INSUFFICIENT_PERMISSIONS",
          requiredRoles: ["Admin"],
          userRole: user.role,
        });
        return;
      }

      // Optional extra safety: require the admin account email to be verified.
      if (!user.emailVerification?.emailVerified) {
        res.status(403).json({
          error: "Email verification required",
          code: "EMAIL_NOT_VERIFIED",
        });
        return;
      }

      const session = await this.issueSessionForAdmin(user, req, res);

      res.status(200).json({
        message: "Login successful",
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          name: user.name,
          role: user.role,
          emailVerified: user.emailVerification?.emailVerified || false,
          lastLoginAt: user.lastLoginAt,
        },
        session,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Refresh access token using refresh token
   * @param req Request
   * @param res Response
   * @param next NextFunction
   */
  async refreshToken(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const refreshToken = (req as any).cookies?.[REFRESH_TOKEN_COOKIE_NAME] as string | undefined;
      const sessionId = (req as any).cookies?.[SESSION_ID_COOKIE_NAME] as string | undefined;

      if (!refreshToken || !sessionId) {
        res.status(401).json({
          error: "Refresh token and session ID are required",
          code: "MISSING_REFRESH_DATA",
        });
        return;
      }

      // Find user by refresh token (done in middleware)
      const user = req.user!;

      const now = new Date();
      const session = await Session.findOne({
        userId: user._id,
        sessionId,
        isActive: true,
        expiresAt: { $gt: now },
      });

      if (!session) {
        res.status(401).json({
          error: "Invalid refresh token or session",
          code: "REFRESH_FAILED",
        });
        return;
      }

      const accessSecret = process.env.JWT_ACCESS_SECRET;
      const refreshSecret = process.env.JWT_REFRESH_SECRET;
      if (!accessSecret || !refreshSecret) {
        throw new Error("JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be configured");
      }

      const newAccessToken = jwt.sign({ userId: user._id, sessionId }, accessSecret, {
        expiresIn: "15m",
      });
      const newRefreshToken = jwt.sign({ userId: user._id, sessionId }, refreshSecret, {
        expiresIn: "7d",
      });
      const newRefreshTokenHash = hashRefreshToken(newRefreshToken);

      await Session.updateOne(
        { _id: session._id },
        { $set: { refreshTokenHash: newRefreshTokenHash, lastActivity: now } }
      );

      // Rotate cookies
      res.cookie(
        ACCESS_TOKEN_COOKIE_NAME,
        newAccessToken,
        getAuthCookieOptions(15 * 60 * 1000, "/")
      );
      res.cookie(
        REFRESH_TOKEN_COOKIE_NAME,
        newRefreshToken,
        getAuthCookieOptions(7 * 24 * 60 * 60 * 1000, "/api/users")
      );

      res.status(200).json({
        message: "Token refreshed successfully",
        session: {
          sessionId: sessionId,
          expiresIn: 900, // 15 minutes in seconds
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * User logout - invalidate specific session
   * @param req Request
   * @param res Response
   * @param next NextFunction
   */
  async logout(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const user = req.user!;
      const sessionId = req.sessionId!;

      await Session.deleteOne({ userId: user._id, sessionId });

      clearAuthCookies(res);

      res.status(200).json({
        message: "Logout successful",
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Logout from all sessions
   * @param req Request
   * @param res Response
   * @param next NextFunction
   */
  async logoutAll(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const user = req.user!;

      await Session.deleteMany({ userId: user._id });

      clearAuthCookies(res);

      res.status(200).json({
        message: "Logged out from all sessions successfully",
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get current user session info
   * @param req Request
   * @param res Response
   * @param next NextFunction
   */
  async getSession(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const user = req.user!;
      const sessionId = req.sessionId!;

      // Get current session info
      const currentSession = await Session.findOne({
        userId: user._id,
        sessionId,
        isActive: true,
        expiresAt: { $gt: new Date() },
      });

      res.status(200).json({
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          name: user.name,
          role: user.role,
          emailVerified: user.emailVerification?.emailVerified || false,
          lastLoginAt: user.lastLoginAt,
          createdAt: user.createdAt,
        },
        session: {
          sessionId: sessionId,
          lastActivity: currentSession?.lastActivity,
          userAgent: currentSession?.userAgent,
          ipAddress: currentSession?.ipAddress,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get all active sessions for the user
   * @param req Request
   * @param res Response
   * @param next NextFunction
   */
  async getSessions(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const user = req.user!;
      const currentSessionId = req.sessionId!;

      const now = new Date();
      const sessions = await Session.find({
        userId: user._id,
        isActive: true,
        expiresAt: { $gt: now },
      })
        .sort({ lastActivity: -1 })
        .lean();

      const activeSessions = sessions.map((s) => ({
        sessionId: s.sessionId,
        lastActivity: s.lastActivity,
        userAgent: s.userAgent,
        ipAddress: s.ipAddress,
        isCurrent: s.sessionId === currentSessionId,
      }));

      res.status(200).json({
        sessions: activeSessions,
        total: activeSessions.length,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Terminate a specific session
   * @param req Request
   * @param res Response
   * @param next NextFunction
   */
  async terminateSession(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const user = req.user!;
      const { sessionId } = req.params;

      if (!sessionId) {
        res.status(400).json({
          error: "Session ID is required",
        });
        return;
      }

      await Session.deleteOne({ userId: user._id, sessionId });

      res.status(200).json({
        message: "Session terminated successfully",
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Verify email address
   * @param req Request
   * @param res Response
   * @param next NextFunction
   */
  async verifyEmail(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { token } = req.body;

      if (!token) {
        res.status(400).json({
          error: "Verification token is required",
        });
        return;
      }

      const emailSecret = process.env.JWT_EMAIL_VERIFY_SECRET;
      if (!emailSecret) {
        throw new Error("JWT_EMAIL_VERIFY_SECRET is not configured");
      }

      // Verify the token
      let decoded;
      try {
        decoded = jwt.verify(token, emailSecret) as {
          userId: string;
        };
      } catch (error) {
        res.status(400).json({
          error: "Invalid or expired verification token",
        });
        return;
      }

      // Find user and check verification token
      const user = await User.findById(decoded.userId);
      if (!user) {
        res.status(404).json({
          error: "User not found",
        });
        return;
      }

      // Check if token matches and hasn't expired
      if (
        user.emailVerification?.verificationToken !== token ||
        !user.emailVerification?.verificationTokenExpires ||
        user.emailVerification.verificationTokenExpires < new Date()
      ) {
        res.status(400).json({
          error: "Invalid or expired verification token",
        });
        return;
      }

      // Check if email is already verified
      if (user.emailVerification?.emailVerified) {
        res.status(400).json({
          error: "Email is already verified",
        });
        return;
      }

      // Mark email as verified and clear verification token
      user.emailVerification = {
        emailVerified: true,
      };

      await user.save();

      res.status(200).json({
        message: "Email verified successfully",
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          emailVerified: true,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Verify and finalize email change
   * @param req Request
   * @param res Response
   * @param next NextFunction
   */
  async verifyEmailChange(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { token } = req.body;

      if (!token) {
        res.status(400).json({
          error: "Verification token is required",
        });
        return;
      }

      const emailSecret = process.env.JWT_EMAIL_VERIFY_SECRET;
      if (!emailSecret) {
        throw new Error("JWT_EMAIL_VERIFY_SECRET is not configured");
      }

      let decoded;
      try {
        decoded = jwt.verify(token, emailSecret) as { userId: string };
      } catch {
        res.status(400).json({
          error: "Invalid or expired verification token",
        });
        return;
      }

      const user = await User.findById(decoded.userId);
      if (!user) {
        res.status(404).json({
          error: "User not found",
        });
        return;
      }

      const pendingEmail = user.emailChange?.pendingEmail;
      const storedToken = user.emailChange?.token;
      const tokenExpires = user.emailChange?.tokenExpires;

      if (!pendingEmail || !storedToken || !tokenExpires || tokenExpires < new Date() || storedToken !== token) {
        res.status(400).json({
          error: "Invalid or expired verification token",
        });
        return;
      }

      // Ensure the pending email is still available (race-condition safety)
      const existingUser = await User.findOne({
        email: pendingEmail.toLowerCase(),
        _id: { $ne: user._id },
      });
      if (existingUser) {
        res.status(400).json({
          error: "Email is already in use",
        });
        return;
      }

      user.email = pendingEmail.toLowerCase();
      user.emailVerification = {
        emailVerified: true,
      };
      user.emailChange = {};

      await user.save();

      res.status(200).json({
        message: "Email changed and verified successfully",
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          emailVerified: true,
        },
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Resend email verification
   * @param req Request
   * @param res Response
   * @param next NextFunction
   */
  async resendVerification(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const { email } = req.body;

      if (!email) {
        res.status(400).json({
          error: "Email is required",
        });
        return;
      }

      if (!this.validateEmail(email)) {
        res.status(400).json({
          error: "Invalid email format",
        });
        return;
      }

      const user = await User.findOne({ email: email.toLowerCase() });
      if (!user) {
        res.status(404).json({
          error: "User not found",
        });
        return;
      }

      if (user.emailVerification?.emailVerified) {
        res.status(400).json({
          error: "Email is already verified",
        });
        return;
      }

      // Generate new verification token
      const token = await this.createEmailVerificationToken(user);
      await this.sendVerificationEmail(email, token);

      res.status(200).json({
        message: "Verification email sent successfully",
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Change email address and send verification
   * @param req Request
   * @param res Response
   * @param next NextFunction
   */
  async changeEmail(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const user = req.user!;
      const { newEmail } = req.body;

      if (!newEmail) {
        res.status(400).json({
          error: "New email is required",
        });
        return;
      }

      if (!this.validateEmail(newEmail)) {
        res.status(400).json({
          error: "Invalid email format",
        });
        return;
      }

      // Check if email is already in use
      const existingUser = await User.findOne({
        email: newEmail.toLowerCase(),
      });
      if (existingUser) {
        res.status(400).json({
          error: "Email is already in use",
        });
        return;
      }

      // No-op if same as current
      if (user.email.toLowerCase() === newEmail.toLowerCase()) {
        res.status(400).json({
          error: "New email must be different from current email",
        });
        return;
      }

      // Generate verification token
      const token = this.generateToken(user);
      const expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 hours from now

      // Store as pending until verified
      await user.changeEmail(newEmail.toLowerCase(), token, expiresAt);
      await this.sendEmailChangeVerification(newEmail, token);

      res.status(200).json({
        message: "Email change verification sent",
      });
    } catch (error) {
      next(error);
    }
  }
}

export default new UserController();
