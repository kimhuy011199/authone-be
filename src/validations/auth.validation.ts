import Joi from 'joi';

const PASSWORD_AT_LEAST_1_NUMBER = /^(?=.*?[0-9])/;
const OTP_LENGTH = 6;

interface Auth {
  email: string;
  password: string;
}

export interface RegisterUser extends Auth {
  name: string;
}

export interface LoginUser extends Auth {}

export interface UpdateUser {
  name: string;
}

const authSchema = {
  email: Joi.string().email().required(),
  password: Joi.string().min(8).regex(PASSWORD_AT_LEAST_1_NUMBER).required(),
};

export const registerSchema = Joi.object({
  ...authSchema,
  name: Joi.string().required(),
});

export const loginSchema = Joi.object({
  ...authSchema,
});

export const otpSchema = Joi.object({
  otp: Joi.string().length(OTP_LENGTH).required(),
});

export const verifyMfaSchema = Joi.object({
  otp: Joi.string().length(OTP_LENGTH).required(),
  mfaToken: Joi.string().required(),
});

export const updateUserSchema = Joi.object({
  name: Joi.string().required(),
});

export const updateAvatarSchema = Joi.object({
  base64Img: Joi.string().required(),
});

export const updatePasswordSchema = Joi.object({
  oldPassword: Joi.string().min(8).regex(PASSWORD_AT_LEAST_1_NUMBER).required(),
  password: Joi.string().min(8).regex(PASSWORD_AT_LEAST_1_NUMBER).required(),
});

export const emailSchema = Joi.object({
  email: Joi.string().email().required(),
});

export const verifyResetPasswordSchema = Joi.object({
  password: Joi.string().min(8).regex(PASSWORD_AT_LEAST_1_NUMBER).required(),
  passwordToken: Joi.string().email().required(),
});
