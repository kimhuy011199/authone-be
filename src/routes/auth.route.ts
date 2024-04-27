import express, { Router } from 'express';
import authController from '../controllers/auth.controller';
import {
  loginSchema,
  registerSchema,
  verifyOtpSchema,
  updatePasswordSchema,
  updateUserSchema,
  verifyMfaSchema,
  verifyResetPasswordSchema,
  requestPasswordSchema,
} from '../validations/auth.validation';
import validate from '../middlewares/validation.middleware';
import authenticateMiddleware from '../middlewares/auth.middleware';

/**
 * Router for handling authentication-related routes.
 */
const authRoute: Router = express.Router();

/**
 * Route for user registration.
 * @route POST /register
 * @middleware validate(registerSchema)
 * @controller authController.register
 */
authRoute.post('/register', validate(registerSchema), authController.register);

/**
 * Route for user login.
 * @route POST /login
 * @middleware validate(loginSchema)
 * @controller authController.login
 */
authRoute.post('/login', validate(loginSchema), authController.login);

/**
 * Route for getting the current user's information.
 * @route GET /users/me
 * @middleware authenticateMiddleware
 * @controller authController.getMe
 */
authRoute.get('/users/me', authenticateMiddleware, authController.getMe);

/**
 * Route for updating the current user's information.
 * @route PUT /users/me
 * @middleware authenticateMiddleware
 * @middleware validate(updateUserSchema)
 * @controller authController.updateUser
 */
authRoute.put(
  'users/me',
  authenticateMiddleware,
  validate(updateUserSchema),
  authController.updateUser
);

/**
 * Route for updating the current user's password.
 * @route PUT /users/me/password
 * @middleware authenticateMiddleware
 * @middleware validate(updatePasswordSchema)
 * @controller authController.updatePassword
 */
authRoute.put(
  'users/me/password',
  authenticateMiddleware,
  validate(updatePasswordSchema),
  authController.updatePassword
);

/**
 * Route for getting the QR code for enabling MFA.
 * @route GET /mfa/qrcode
 * @middleware authenticateMiddleware
 * @controller authController.getQRCode
 */
authRoute.get('/mfa/qrcode', authenticateMiddleware, authController.getQRCode);

/**
 * Route for toggling MFA for the current user.
 * @route PUT /mfa
 * @middleware authenticateMiddleware
 * @middleware validate(verifyOtpSchema)
 * @controller authController.toggleMfa
 */
authRoute.put(
  '/mfa',
  authenticateMiddleware,
  validate(verifyOtpSchema),
  authController.toggleMfa
);

/**
 * Route for verifying MFA for the current user.
 * @route POST /mfa
 * @middleware validate(verifyMfaSchema)
 * @controller authController.verifyMfa
 */
authRoute.post('/mfa', validate(verifyMfaSchema), authController.verifyMfa);

/**
 * Route for sending the verification email for the current user's account.
 * @route POST /account/otp
 * @middleware authenticateMiddleware
 * @controller authController.sendVerifyEmail
 */
authRoute.post(
  '/account/otp',
  authenticateMiddleware,
  authController.sendVerifyEmail
);

/**
 * Route for verifying the email for the current user's account.
 * @route POST /account/otp/verify
 * @middleware authenticateMiddleware
 * @middleware validate(verifyOtpSchema)
 * @controller authController.verifyEmail
 */
authRoute.post(
  '/account/otp/verify',
  authenticateMiddleware,
  validate(verifyOtpSchema),
  authController.verifyEmail
);

/**
 * Route for requesting a password reset link.
 * @route POST /password/reset-link
 * @middleware validate(requestPasswordSchema)
 * @controller authController.requestResetPassword
 */
authRoute.post(
  '/password/reset-link',
  validate(requestPasswordSchema),
  authController.requestResetPassword
);

/**
 * Route for verifying the reset password request.
 * @route POST /password/reset
 * @middleware validate(verifyResetPasswordSchema)
 * @controller authController.verifyResetPassword
 */
authRoute.post(
  '/password/reset',
  validate(verifyResetPasswordSchema),
  authController.verifyResetPassword
);

export default authRoute;
