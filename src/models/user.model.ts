import mongoose, { Schema, Document } from 'mongoose';
import LoginType from '../shared/enums/loginType';

export interface UserModel {
  // Basic information
  email: string;
  firstName: string;
  lastName: string;
  avatar: string;
  password: string;
  loginType: LoginType;
  // Email verification
  emailVerification: {
    isVerified: boolean;
    code: string;
    expiredTime: number;
  };
  // Multifactor authentication (two-step verification)
  mfa: {
    isEnabled: boolean;
    otpSecret: string;
  };
}

export interface UserDocument extends Document, UserModel {}

const userSchema: Schema<UserDocument> = new Schema<UserDocument>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },
    firstName: {
      type: String,
    },
    lastName: {
      type: String,
    },
    password: {
      type: String,
      required: true,
    },
    avatar: {
      type: String,
    },
    loginType: {
      type: String,
    },
    emailVerification: {
      isVerified: {
        type: Boolean,
        required: true,
      },
      code: {
        type: String,
      },
      expiredTime: {
        type: Number,
        required: true,
      },
    },
    mfa: {
      isEnabled: {
        type: Boolean,
        required: true,
      },
      otpSecret: {
        type: String,
        required: true,
      },
    },
  },
  {
    timestamps: true,
  }
);

export default mongoose.model<UserDocument>('User', userSchema);
