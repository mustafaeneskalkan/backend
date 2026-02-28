import mongoose, { Document, Model, Schema, Types } from 'mongoose';

export interface ISession extends Document {
  userId: Types.ObjectId;
  sessionId: string;
  refreshTokenHash: string;
  expiresAt: Date;
  isActive: boolean;
  userAgent?: string;
  ipAddress?: string;
  lastActivity: Date;
  createdAt?: Date;
  updatedAt?: Date;
}

const SessionSchema = new Schema<ISession>(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    sessionId: { type: String, required: true },
    refreshTokenHash: { type: String, required: true },
    expiresAt: { type: Date, required: true, index: true },
    isActive: { type: Boolean, default: true, index: true },
    userAgent: { type: String },
    ipAddress: { type: String },
    lastActivity: { type: Date, default: Date.now, index: true },
  },
  {
    timestamps: true,
  }
);

// Ensure one session per (userId, sessionId)
SessionSchema.index({ userId: 1, sessionId: 1 }, { unique: true });

// TTL index: document will be removed when expiresAt is in the past
SessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const Session: Model<ISession> =
  mongoose.models.Session || mongoose.model<ISession>('Session', SessionSchema);

export default Session;
