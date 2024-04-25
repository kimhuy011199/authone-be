import express, { Router } from 'express';
import authController from '../controllers/auth.controller';
import {
  loginSchema,
  registerSchema,
  verifyOtpSchema,
  updateAvatarSchema,
  updatePasswordSchema,
  updateUserSchema,
  verifyMfaSchema,
  verifyResetPasswordSchema,
  requestPasswordSchema,
} from '../validations/auth.validation';
import validate from '../middlewares/validation.middleware';
import authenticateMiddleware from '../middlewares/auth.middleware';

const authRoute: Router = express.Router();

authRoute.post('/register', validate(registerSchema), authController.register);
authRoute.post('/login', validate(loginSchema), authController.login);

authRoute.get('/me', authenticateMiddleware, authController.getMe);
authRoute.put(
  '/me',
  authenticateMiddleware,
  validate(updateUserSchema),
  authController.updateUser
);
authRoute.put(
  '/me/password',
  authenticateMiddleware,
  validate(updatePasswordSchema),
  authController.updatePassword
);
authRoute.put(
  '/me/avatar',
  authenticateMiddleware,
  validate(updateAvatarSchema),
  authController.updateAvatar
);

authRoute.get('/mfa/qrcode', authenticateMiddleware, authController.getQRCode);
authRoute.put(
  '/mfa',
  authenticateMiddleware,
  validate(verifyOtpSchema),
  authController.toggleMfa
);
authRoute.post('/mfa', validate(verifyMfaSchema), authController.verifyMfa);

authRoute.post(
  '/account/send-otp',
  authenticateMiddleware,
  authController.sendVerifyEmail
);
authRoute.post(
  '/account/verify-otp',
  authenticateMiddleware,
  validate(verifyOtpSchema),
  authController.verifyEmail
);

authRoute.post(
  '/password/send-link',
  validate(requestPasswordSchema),
  authController.requestResetPassword
);
authRoute.post(
  '/password/verify',
  validate(verifyResetPasswordSchema),
  authController.verifyResetPassword
);

export default authRoute;
