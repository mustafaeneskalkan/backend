import mongoose, { Document, Model, Schema } from "mongoose";
import bcrypt from "bcryptjs";
import jwt from 'jsonwebtoken';

// Interface that represents a User document in MongoDB
export interface IUser extends Document {
  username: string;
  email: string;
  password: string;
  name?: string;
  role?: string;
  accessIds?: string[];
  emailVerification?: {
    emailVerified: boolean;
    verificationToken?: string;
    verificationTokenExpires?: Date;
  };
  passwordChange?: {
    token?: string;
    tokenExpires?: Date;
  };
  sessions?: {
    sessionId: string;
    refreshToken: string;
    accessToken: string;
    expiresAt: Date;
    isActive: boolean;
    userAgent?: string;
    ipAddress?: string;
    lastActivity: Date;
  }[];
  lastLoginAt?: Date;
  passwordChangedAt?: Date;
  createdAt?: Date;
  comparePassword(candidate: string): Promise<boolean>;
  setVerificationToken(token: string, expiresAt: Date): Promise<void>;
  changeEmail(newEmail: string, token: string, expiresAt: Date): Promise<void>;
  changePassword(newPassword: string): Promise<void>;
  createSession(userAgent?: string, ipAddress?: string): Promise<{ sessionId: string; accessToken: string; refreshToken: string }>;
  invalidateSession(sessionId: string): Promise<void>;
  invalidateAllSessions(): Promise<void>;
  refreshSession(sessionId: string, refreshToken: string): Promise<{ accessToken: string; refreshToken: string } | null>;
  getActiveSessions(): { sessionId: string; lastActivity: Date; userAgent?: string; ipAddress?: string }[];
}

// Schema definition
const UserSchema = new Schema<IUser>(
  {
    username: { type: String, required: true, unique: true, trim: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: { type: String, required: true },
    name: { type: String },
    role: { type: String, default: "Writer" },
    accessIds: { type: [String], default: [] },
    emailVerification: {
      emailVerified: { type: Boolean, default: false },
      verificationToken: { type: String },
      verificationTokenExpires: { type: Date },
    },
    passwordChange: {
      token: { type: String },
      tokenExpires: { type: Date },
    },
    sessions: [{
      sessionId: { type: String, required: true },
      refreshToken: { type: String, required: true },
      accessToken: { type: String, required: true },
      expiresAt: { type: Date, required: true },
      isActive: { type: Boolean, default: true },
      userAgent: { type: String },
      ipAddress: { type: String },
      lastActivity: { type: Date, default: Date.now }
    }],
    lastLoginAt: { type: Date },
    passwordChangedAt: { type: Date, default: Date.now },
  },
  {
    timestamps: { createdAt: true, updatedAt: true },
    toJSON: {
      transform(doc, ret) {
        delete ret.password;
        delete ret.sessions;
        return ret;
      },
    },
  }
);

// Hash password before save if modified
UserSchema.pre<IUser>("save", async function (next) {
  // Handle password hashing
  if (this.isModified("password")) {
    try {
      const salt = await bcrypt.genSalt(12);
      const hash = await bcrypt.hash(this.password, salt);
      this.password = hash;
      
      // Update password change timestamp and invalidate sessions if not new user
      if (!this.isNew) {
        this.passwordChangedAt = new Date();
        // Invalidate all sessions when password changes
        this.sessions = this.sessions?.map((session: any) => ({
          ...session,
          isActive: false
        })) || [];
      }
    } catch (err) {
      return next(err as any);
    }
  }
  return next();
});

// Instance method to compare password
UserSchema.methods.comparePassword = function (candidate: string) {
  return bcrypt.compare(candidate, this.password);
};

// Instance method to set verification token
UserSchema.methods.setVerificationToken = function (token: string, expiresAt: Date) {
  this.emailVerification = {
    ...this.emailVerification,
    verificationToken: token,
    verificationTokenExpires: expiresAt,
  };
  return this.save();
};


UserSchema.methods.changeEmail = async function (newEmail: string, token: string, expiresAt: Date) {
  this.email = newEmail;
  this.emailVerification = {
    emailVerified: false,
    verificationToken: token,
    verificationTokenExpires: expiresAt,
  };
  return this.save();
};

UserSchema.methods.changePassword = function (newPassword: string) {
  this.password = newPassword;
  this.passwordChangedAt = new Date();
  return this.save();
};

UserSchema.methods.setPasswordChangeToken = function (token: string, expiresAt: Date) {
  this.passwordChange = {
    token,
    tokenExpires: expiresAt,
  };
  return this.save();
};

// Session management methods
UserSchema.methods.createSession = async function (userAgent?: string, ipAddress?: string) {
  
  if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
    throw new Error('JWT secrets not configured');
  }

  const sessionId = crypto.randomUUID();
  const accessToken = jwt.sign(
    { userId: this._id, sessionId },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );
  const refreshToken = jwt.sign(
    { userId: this._id, sessionId },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  // Clean up expired sessions before adding new one
  this.sessions = this.sessions?.filter((session: any) => 
    session.expiresAt > new Date() && session.isActive
  ) || [];

  // Limit to 5 active sessions per user
  if (this.sessions.length >= 5) {
    this.sessions.shift(); // Remove oldest session
  }

  const newSession = {
    sessionId,
    refreshToken,
    accessToken,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    isActive: true,
    userAgent,
    ipAddress,
    lastActivity: new Date()
  };

  this.sessions.push(newSession);
  this.lastLoginAt = new Date();
  await this.save();

  return { sessionId, accessToken, refreshToken };
};

UserSchema.methods.invalidateSession = async function (sessionId: string) {
  this.sessions = this.sessions?.map((session: any) => 
    session.sessionId === sessionId 
      ? { ...session, isActive: false }
      : session
  ) || [];
  await this.save();
};

UserSchema.methods.invalidateAllSessions = async function () {
  this.sessions = this.sessions?.map((session: any) => ({
    ...session,
    isActive: false
  })) || [];
  await this.save();
};

UserSchema.methods.refreshSession = async function (sessionId: string, refreshToken: string) {
  
  if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
    throw new Error('JWT secrets not configured');
  }

  const session = this.sessions?.find((s: any) => 
    s.sessionId === sessionId && s.isActive && s.expiresAt > new Date()
  );

  if (!session || session.refreshToken !== refreshToken) {
    return null;
  }

  // Verify refresh token
  try {
    jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
  } catch (error) {
    // Invalidate session if refresh token is invalid
    await this.invalidateSession(sessionId);
    return null;
  }

  // Generate new tokens
  const newAccessToken = jwt.sign(
    { userId: this._id, sessionId },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );
  const newRefreshToken = jwt.sign(
    { userId: this._id, sessionId },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  // Update session
  this.sessions = this.sessions?.map((s: any) => 
    s.sessionId === sessionId 
      ? { 
          ...s, 
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
          lastActivity: new Date()
        }
      : s
  ) || [];

  await this.save();
  return { accessToken: newAccessToken, refreshToken: newRefreshToken };
};

UserSchema.methods.getActiveSessions = function () {
  return this.sessions?.filter((session: any) => 
    session.isActive && session.expiresAt > new Date()
  ).map((session: any) => ({
    sessionId: session.sessionId,
    lastActivity: session.lastActivity,
    userAgent: session.userAgent,
    ipAddress: session.ipAddress
  })) || [];
};

// Export the model
const User: Model<IUser> =
  mongoose.models.User || mongoose.model<IUser>("User", UserSchema);

export default User;
