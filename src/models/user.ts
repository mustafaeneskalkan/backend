import mongoose, { Document, Model, Schema } from "mongoose";
import bcrypt from "bcryptjs";
import Session from './session.js';

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
  emailChange?: {
    pendingEmail?: string;
    token?: string;
    tokenExpires?: Date;
  };
  passwordChange?: {
    token?: string;
    tokenExpires?: Date;
  };
  preferences: {
    theme: "light" | "dark";
    email:{
      newsletter: boolean;
      productUpdates: boolean;
      securityAlerts: boolean;
      motivational: boolean;
    }
  };
  lastLoginAt?: Date;
  passwordChangedAt?: Date;
  createdAt?: Date;
  comparePassword(candidate: string): Promise<boolean>;
  setVerificationToken(token: string, expiresAt: Date): Promise<void>;
  changeEmail(newEmail: string, token: string, expiresAt: Date): Promise<void>;
  changePassword(newPassword: string): Promise<void>;
  setPasswordChangeToken(token: string, expiresAt: Date): Promise<void>;
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
    role: { type: String, default: "Student" },
    accessIds: { type: [String], default: [] },
    emailVerification: {
      emailVerified: { type: Boolean, default: false },
      verificationToken: { type: String },
      verificationTokenExpires: { type: Date },
    },
    emailChange: {
      pendingEmail: { type: String, lowercase: true, trim: true },
      token: { type: String },
      tokenExpires: { type: Date },
    },
    passwordChange: {
      token: { type: String },
      tokenExpires: { type: Date },
    },
    preferences: {
      theme: { type: String, enum: ["light", "dark"], default: "light" },
      email: {
        newsletter: { type: Boolean, default: false },
        productUpdates: { type: Boolean, default: false },
        securityAlerts: { type: Boolean, default: false },
        motivational: { type: Boolean, default: false },
      },
    },
    lastLoginAt: { type: Date },
    passwordChangedAt: { type: Date, default: Date.now },
  },
  {
    timestamps: { createdAt: true, updatedAt: true },
    toJSON: {
      transform(doc, ret) {
        delete ret.password;
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
        await Session.deleteMany({ userId: this._id });
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
  // Do not change the primary email until the new address is verified.
  this.emailChange = {
    pendingEmail: newEmail,
    token,
    tokenExpires: expiresAt,
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

// Export the model
const User: Model<IUser> =
  mongoose.models.User || mongoose.model<IUser>("User", UserSchema);

export default User;
