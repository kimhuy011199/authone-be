import express, { Router } from 'express';
import authController from '../controllers/auth.controller';
import {
  emailSchema,
  loginSchema,
  otpSchema,
  passwordTokenSchema,
  registerSchema,
  updateAvatarSchema,
  updatePasswordSchema,
  updateUserSchema,
  verifyMfaSchema,
} from '../validations/auth.validation';
import validate from '../middlewares/validation.middleware';
import authenticateMiddleware from '../middlewares/auth.middleware';

const authRoute: Router = express.Router();

authRoute.post('/register', validate(registerSchema), authController.register);
authRoute.post('/login', validate(loginSchema), authController.login);
authRoute.get('/me', authenticateMiddleware, authController.getMe);
authRoute.get('/qrcode', authenticateMiddleware, authController.getQRCode);
authRoute.put(
  '/toggle-mfa',
  authenticateMiddleware,
  validate(otpSchema),
  authController.toggleMfa
);
authRoute.post(
  '/verify-mfa',
  validate(verifyMfaSchema),
  authController.verifyMfa
);
authRoute.post(
  '/send-verify-email',
  authenticateMiddleware,
  authController.sendVerifyEmail
);
authRoute.post(
  '/verify-email',
  authenticateMiddleware,
  validate(otpSchema),
  authController.verifyEmail
);
authRoute.put(
  '/update-user',
  authenticateMiddleware,
  validate(updateUserSchema),
  authController.updateUser
);
authRoute.put(
  '/update-avatar',
  authenticateMiddleware,
  validate(updateAvatarSchema),
  authController.updateAvatar
);
authRoute.put(
  '/update-password',
  authenticateMiddleware,
  validate(updatePasswordSchema),
  authController.updatePassword
);
authRoute.post(
  '/request-reset-password',
  validate(emailSchema),
  authController.requestResetPassword
);
authRoute.post(
  '/verify-reset-password',
  validate(passwordTokenSchema),
  authController.verifyResetPassword
);

export default authRoute;
