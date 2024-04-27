import bcrypt from 'bcryptjs';
import jwt, { JwtPayload } from 'jsonwebtoken';
import HttpStatusCode from '../shared/enums/httpStatus';
import HttpException from '../shared/helpers/exception.helper';
import User, { UserDocument, UserModel } from '../models/user.model';
import {
  LoginUser,
  RegisterUser,
  UpdateUser,
} from '../validations/auth.validation';
import otpHelper from '../shared/helpers/otp.helper';
import mailHelper from '../shared/helpers/mail.helper';
import LoginType from '../shared/enums/loginType';
import { ERROR_MSG } from '../shared/constants/errorMsg';
import {
  ACCESS_TOKEN_SECRET,
  MFA_SECRET,
  PASSWORD_SECRET,
} from '../config/env.config';

const SALT_ROUNDS = 10;
const ACCESS_TOKEN_EXPRIED_IN = '300000s';

/**
 * Registers a new user.
 * @param body - The user registration data.
 * @returns An object containing the sanitized user data and an access token.
 * @throws HttpException with status code 400 if the email already exists.
 */
const register = async (body: RegisterUser) => {
  const { email, password, firstName, lastName } = body;

  // Check if email is existed
  const existedUser = await User.findOne({ email });
  if (existedUser) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      ERROR_MSG.EMAIL_ALREADY_EXISTS
    );
  }

  // Create hashed password
  const hashedPassword = await generateHashedPassword(password);

  // Create MFA otp secret
  const mfaOtpSecret = otpHelper.generateSecret();

  // Create and save user to DB
  const user = await User.create({
    email,
    firstName,
    lastName,
    password: hashedPassword,
    loginType: LoginType.EMAIL_PASSWORD,
    emailVerification: {
      isVerified: false,
      code: '',
      expiredTime: 0,
    },
    mfa: {
      isEnabled: false,
      otpSecret: mfaOtpSecret,
    },
  });

  // Generate access token
  const accessToken = generateToken({ sub: user._id }, ACCESS_TOKEN_SECRET);

  return {
    ...sanitizeUser(user),
    accessToken,
  };
};

/**
 * Authenticates a user by checking their email and password.
 * If the email is found and the password is correct, it generates an access token.
 * If MFA is enabled for the user, it also generates an MFA token.
 * @param body - The login user object containing the email and password.
 * @returns An object containing the user information and access/MFA tokens.
 * @throws HttpException with appropriate error message if email is not found or password is incorrect.
 */
const login = async (body: LoginUser) => {
  const { email, password } = body;

  // Check if email is not existed
  const user = await User.findOne({ email });
  if (!user) {
    throw new HttpException(
      HttpStatusCode.NOT_FOUND,
      ERROR_MSG.EMAIL_NOT_FOUND
    );
  }

  // Compare input password with stored password
  const isCorrectPassword = await bcrypt.compare(password, user.password);

  if (!isCorrectPassword) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      ERROR_MSG.INCORRECT_PASSWORD
    );
  }

  // Generate MFA token if MFA is enabled
  if (user.mfa.isEnabled) {
    const mfaToken = generateToken({ sub: user._id }, MFA_SECRET);
    return { mfaToken };
  } else {
    // If not, generate access token and return customer infor
    const accessToken = generateToken({ sub: user._id }, ACCESS_TOKEN_SECRET);

    return {
      ...sanitizeUser(user),
      accessToken,
    };
  }
};

/**
 * Sanitizes the user object by removing sensitive information and extracting relevant fields.
 * @param user - The user object to be sanitized.
 * @returns The sanitized user object with only basic user information, email verification status, and MFA status.
 */
const sanitizeUser = (user: UserModel) => {
  const { password, emailVerification, mfa, __v, ...basicUserInfo } =
    JSON.parse(JSON.stringify(user));

  const isVerifiedEmail = emailVerification.isVerified;
  const isEnabledMfa = mfa.isEnabled;

  return {
    user: { ...basicUserInfo, isVerifiedEmail, isEnabledMfa },
  };
};

/**
 * Generates a QR code image URL for the given email and MFA OTP secret.
 * @param email - The email associated with the user.
 * @param mfaOtpSecret - The MFA OTP secret for the user.
 * @returns An object containing the generated QR code image URL.
 */
const getQRCode = async (email: string, mfaOtpSecret: string) => {
  const qrCodeImgUrl = await otpHelper.generateQRCode(email, mfaOtpSecret);

  return {
    qrCodeImgUrl,
  };
};

/**
 * Toggles the Multi-Factor Authentication (MFA) status for a user.
 * @param otp - The One-Time Password (OTP) provided by the user.
 * @param user - The user document to toggle MFA for.
 * @returns The updated user document with MFA status toggled.
 * @throws {HttpException} If the provided OTP is invalid.
 */
const toggleMfa = async (otp: string, user: UserDocument) => {
  const { mfa } = user;
  const isValid = otpHelper.verifyOtpToken(otp, mfa.otpSecret);

  if (!isValid) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, ERROR_MSG.INVALID_OTP);
  }

  // Toggle MFA
  user.mfa.isEnabled = !user.mfa.isEnabled;
  const updatedUser = await user.save();

  return sanitizeUser(updatedUser);
};

const verifyMfa = async (otp: string, mfaToken: string) => {
  // Verify MFA token
  const decoded = jwt.verify(mfaToken, MFA_SECRET) as JwtPayload;

  if (!decoded) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      ERROR_MSG.INVALID_MFA_TOKEN
    );
  }

  const user = await User.findById(decoded.sub);

  // Verify otp
  const isValid = otpHelper.verifyOtpToken(otp, user.mfa.otpSecret);
  if (!isValid) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, ERROR_MSG.INVALID_OTP);
  }

  // Generate access token
  const accessToken = generateToken({ sub: user._id }, ACCESS_TOKEN_SECRET);

  return {
    ...sanitizeUser(user),
    accessToken,
  };
};

/**
 * Sends a verification email to the specified user.
 *
 * @param user - The user document to send the verification email to.
 * @returns A promise that resolves to an object with a success message.
 * @throws {HttpException} If the account has already been verified or if the email verification code needs to be resent.
 */
const sendVerifyEmail = async (user: UserDocument) => {
  const { email, emailVerification } = user;

  // Check if account has been verified
  if (emailVerification.isVerified) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      ERROR_MSG.ACCOUNT_VERIFED
    );
  }

  // Check time remaining
  const timeRemaining = otpHelper.getRemaningTime(
    emailVerification.expiredTime
  );
  if (timeRemaining > 0) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      `Resend email verification code in ${timeRemaining} seconds`
    );
  }

  const { emailVerificationCode, expiredTime } =
    otpHelper.generateEmailVerificationCode();

  // Send mail
  const emailOptions = mailHelper.generateVerifyEmailOptions(
    email,
    emailVerificationCode
  );
  await mailHelper.sendMail(emailOptions);

  // Update email otp and email otp expired time of user
  user.emailVerification.code = emailVerificationCode;
  user.emailVerification.expiredTime = expiredTime;
  await user.save();

  return {
    message: `Send verification code to ${email} successfully!`,
  };
};

/**
 * Verifies the email of a user using the provided OTP.
 * Throws an exception if the email is already verified, OTP is expired, or OTP is invalid.
 *
 * @param inputOtp - The OTP (One-Time Password) provided by the user.
 * @param user - The user document containing the email verification details.
 * @returns The updated user document after email verification.
 * @throws {HttpException} If the email is already verified, OTP is expired, or OTP is invalid.
 */
const verifyEmail = async (inputOtp: string, user: UserDocument) => {
  const { emailVerification } = user;

  if (emailVerification.isVerified) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      ERROR_MSG.ACCOUNT_VERIFED
    );
  }

  // Check if otp has been expired
  const currentTime = new Date().getTime();
  if (emailVerification.expiredTime < currentTime) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, ERROR_MSG.OTP_EXPIRED);
  }

  // Verify otp
  if (inputOtp !== emailVerification.code) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, ERROR_MSG.INVALID_OTP);
  }

  // Verified email
  user.emailVerification.isVerified = true;
  const updatedUser = await user.save();

  return sanitizeUser(updatedUser);
};

const updateUser = async (body: UpdateUser, user: UserDocument) => {
  user.firstName = body.firstName;
  user.lastName = body.lastName;
  const updatedUser = await user.save();

  return sanitizeUser(updatedUser);
};

/**
 * Updates the password for a user.
 *
 * @param body - The request body containing the old and new passwords.
 * @param user - The user document to update the password for.
 * @returns The updated user document with the password updated.
 * @throws HttpException if the old password does not match the stored password.
 */
const updatePassword = async (body: any, user: UserDocument) => {
  // Compare input password with stored password
  const isCorrectPassword = await bcrypt.compare(
    body.oldPassword,
    user.password
  );

  if (!isCorrectPassword) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      ERROR_MSG.PASSWORD_NOT_MATCH
    );
  }

  // Generate salt
  const salt = await bcrypt.genSalt(SALT_ROUNDS);

  // Hash password with generated salt
  const hashedPassword = await bcrypt.hash(body.password, salt);

  user.password = hashedPassword;
  const updatedUser = await user.save();

  return sanitizeUser(updatedUser);
};

/**
 * Requests a password reset for the given email.
 *
 * @param email - The email of the user requesting the password reset.
 * @returns A promise that resolves to an object with a success message.
 * @throws HttpException if the email is not found.
 */
const requestResetPassword = async (email: string) => {
  const existedUser = await User.findOne({ email });
  if (!existedUser) {
    throw new HttpException(
      HttpStatusCode.NOT_FOUND,
      ERROR_MSG.EMAIL_NOT_FOUND
    );
  }

  const passwordToken = generateToken(
    { sub: existedUser._id },
    PASSWORD_SECRET
  );

  // Send mail url reset password
  const emailOptions = mailHelper.generateResetPasswordOptions(
    email,
    passwordToken
  );
  await mailHelper.sendMail(emailOptions);

  return {
    message: `Send verification code to ${email} successfully!`,
  };
};

/**
 * Verifies the reset password token and updates the user's password.
 * @param passwordToken - The reset password token.
 * @param password - The new password to set.
 * @returns The updated user object after password reset.
 * @throws HttpException if the token is invalid.
 */
const verifyResetPassword = async (passwordToken: string, password: string) => {
  // Verify password token
  const decoded = jwt.verify(passwordToken, PASSWORD_SECRET) as JwtPayload;

  if (!decoded) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      ERROR_MSG.INVALID_TOKEN
    );
  }

  const user = await User.findById(decoded.sub);
  const hashedPassword = await generateHashedPassword(password);
  user.password = hashedPassword;
  const updatedUser = await user.save();

  return sanitizeUser(updatedUser);
};

/**
 * Generates a JWT token with the given payload and secret.
 * @param payload - The data to be included in the token.
 * @param secret - The secret key used to sign the token.
 * @param expiresIn - The expiration time for the token in seconds. Defaults to ACCESS_TOKEN_EXPRIED_IN.
 * @returns The generated JWT token.
 */
const generateToken = (
  payload: any,
  secret: string,
  expiresIn = ACCESS_TOKEN_EXPRIED_IN
) => {
  return jwt.sign(payload, secret, { expiresIn });
};

/**
 * Generates a hashed password using bcrypt.
 *
 * @param password - The password to be hashed.
 * @returns A promise that resolves to the hashed password.
 */
const generateHashedPassword = async (password: string) => {
  // Generate salt
  const salt = await bcrypt.genSalt(SALT_ROUNDS);

  // Hash password with generated salt
  const hashedPassword = await bcrypt.hash(password, salt);

  return hashedPassword;
};

const authService = {
  register,
  login,
  sanitizeUser,
  getQRCode,
  toggleMfa,
  verifyMfa,
  sendVerifyEmail,
  verifyEmail,
  updateUser,
  updatePassword,
  requestResetPassword,
  verifyResetPassword,
};

export default authService;
