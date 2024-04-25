import Joi from 'joi';

const PASSWORD_AT_LEAST_1_NUMBER = /^(?=.*?[0-9])/;
const OTP_LENGTH = 6;

export interface LoginUser {
  email: string;
  password: string;
}

export interface RegisterUser {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}

export interface UpdateUser {
  firstName: string;
  lastName: string;
}

const nameSchema = {
  firstName: Joi.string().required(),
  lastName: Joi.string().required(),
};

const emailSchema = {
  email: Joi.string().email().required(),
};

const passwordSchema = {
  password: Joi.string()
    .min(8)
    .max(32)
    .regex(PASSWORD_AT_LEAST_1_NUMBER)
    .required(),
};

const otpSchema = {
  otp: Joi.string().length(OTP_LENGTH).required(),
};

export const registerSchema = Joi.object({
  ...nameSchema,
  ...emailSchema,
  ...passwordSchema,
});

export const loginSchema = Joi.object({
  ...emailSchema,
  ...passwordSchema,
});

export const verifyOtpSchema = Joi.object({
  ...otpSchema,
});

export const verifyMfaSchema = Joi.object({
  ...otpSchema,
  mfaToken: Joi.string().required(),
});

export const updateUserSchema = Joi.object({
  ...nameSchema,
});

export const updateAvatarSchema = Joi.object({
  base64Img: Joi.string().required(),
});

export const updatePasswordSchema = Joi.object({
  oldPassword: Joi.string().min(8).regex(PASSWORD_AT_LEAST_1_NUMBER).required(),
  ...passwordSchema,
});

export const requestPasswordSchema = Joi.object({
  ...emailSchema,
});

export const verifyResetPasswordSchema = Joi.object({
  ...passwordSchema,
  passwordToken: Joi.string().required(),
});
