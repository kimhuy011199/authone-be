import express, { Router } from 'express';
import authController from '../controllers/auth.controller';
import {
  loginSchema,
  otpSchema,
  registerSchema,
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

export default authRoute;
