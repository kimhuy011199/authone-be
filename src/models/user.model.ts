import mongoose, { Schema, Document } from 'mongoose';

export interface UserModel {
  email: string;
  name: string;
  password: string;
  isEnabledMfa: boolean;
  isVerifiedEmail: boolean;
  mfaOtpSecret: string;
  emailOtp: string;
  emailOtpExpiredTime: number;
  avatar: string;
}

export interface UserDocument extends Document, UserModel {}

const userSchema: Schema<UserDocument> = new Schema<UserDocument>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },
    name: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    isEnabledMfa: {
      type: Boolean,
      required: true,
    },
    isVerifiedEmail: {
      type: Boolean,
      required: true,
    },
    mfaOtpSecret: {
      type: String,
      required: true,
    },
    emailOtp: {
      type: String,
    },
    emailOtpExpiredTime: {
      type: Number,
      required: true,
    },
    avatar: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

export default mongoose.model<UserDocument>('User', userSchema);
