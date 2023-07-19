import bcrypt from 'bcryptjs';
import jwt, { JwtPayload } from 'jsonwebtoken';
import HttpStatusCode from '../shared/enums/httpStatus';
import HttpException from '../shared/helpers/exception.helper';
import User, { UserDocument, UserModel } from '../models/user.model';
import { LoginUser, RegisterUser } from '../validations/auth.validation';
import otpHelper from '../shared/helpers/otp.helper';
import mailHelper from '../shared/helpers/mail.helper';

const TOKEN_EXPRIED_IN = '3000s';

const register = async (body: RegisterUser) => {
  const { email, password, name } = body;

  // Check if email is existed
  const existedUser = await User.findOne({ email });
  if (existedUser) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      'Email address already exists'
    );
  }

  // Generate salt
  const salt = await bcrypt.genSalt(10);

  // Hash password with generated salt
  const hashedPassword = await bcrypt.hash(password, salt);

  // Create mfa otp secret
  const mfaOtpSecret = otpHelper.generateSecret();

  // Create and save user to DB
  const user = await User.create({
    email,
    name,
    password: hashedPassword,
    isEnabledMfa: false,
    isVerifiedEmail: false,
    mfaOtpSecret,
    emailOtp: '',
    emailOtpExpiredTime: 0,
  });

  // Generate access token
  const accessToken = generateToken({ sub: user._id }, process.env.JWT_SECRET);

  return {
    email: user.email,
    accessToken,
  };
};

const login = async (body: LoginUser) => {
  const { email, password } = body;

  // Check if email is not existed
  const user = await User.findOne({ email });
  if (!user) {
    throw new HttpException(HttpStatusCode.NOT_FOUND, 'User not found');
  }

  // Compare input password with stored password
  const isCorrectPassword = await bcrypt.compare(password, user.password);

  if (!isCorrectPassword) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      'Password does not match'
    );
  }

  if (user.isEnabledMfa) {
    // Generate MFA token
    const mfaToken = generateToken({ sub: user._id }, process.env.MFA_SECRET);

    return { mfaToken };
  }

  // Generate access token
  const accessToken = generateToken({ sub: user._id }, process.env.JWT_SECRET);

  return {
    email: user.email,
    accessToken,
  };
};

const sanitizeUser = (user: UserModel) => {
  const {
    password,
    emailOtp,
    emailOtpExpiredTime,
    mfaOtpSecret,
    __v,
    ...returnUser
  } = JSON.parse(JSON.stringify(user));

  return {
    user: returnUser,
  };
};

const getQRCode = async (email: string, mfaOtpSecret: string) => {
  const qrCodeImgUrl = await otpHelper.generateQRCode(email, mfaOtpSecret);

  return {
    qrCodeImgUrl,
  };
};

const toggleMfa = async (otpToken: string, user: UserDocument) => {
  const { mfaOtpSecret } = user;
  const isValid = otpHelper.verifyOTPToken(otpToken, mfaOtpSecret);

  if (!isValid) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, 'OTP does not match');
  }

  // Toggle MFA
  user.isEnabledMfa = !user.isEnabledMfa;
  const updatedUser = await user.save();

  return sanitizeUser(updatedUser);
};

const verifyMfa = async (otpToken: string, mfaToken: string) => {
  // Verify MFA token
  const decoded = jwt.verify(mfaToken, process.env.MFA_SECRET) as JwtPayload;

  if (!decoded) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, 'Invalid token');
  }

  const user = await User.findById(decoded.sub);

  // Verify otp token
  const isValid = otpHelper.verifyOTPToken(otpToken, user.mfaOtpSecret);
  if (!isValid) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, 'OTP does not match');
  }

  // Generate access token
  const accessToken = generateToken({ sub: user._id }, process.env.JWT_SECRET);

  return {
    email: user.email,
    accessToken,
  };
};

const sendVerifyEmail = async (user: UserDocument) => {
  const { email, emailOtpExpiredTime, isVerifiedEmail } = user;

  // Check if account has been verified
  if (isVerifiedEmail) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      'Your account has been verified'
    );
  }

  // Check time remaining
  const timeRemaining = otpHelper.getRemaningTime(emailOtpExpiredTime);
  if (timeRemaining > 0) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      `Resend email verification code in ${timeRemaining} seconds`
    );
  }

  const { emailOtp, expiredTime } = otpHelper.generateEmailOtp();

  // Send mail
  await mailHelper.sendMail(email, emailOtp);

  // Update email otp and email otp expired time of user
  user.emailOtp = emailOtp;
  user.emailOtpExpiredTime = expiredTime;
  await user.save();

  return {
    message: `Send verification code to ${email} successfully!`,
  };
};

const verifyEmail = async (inputOtp: string, user: UserDocument) => {
  const { emailOtp, emailOtpExpiredTime, isVerifiedEmail } = user;

  if (isVerifiedEmail) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      'Your account has been verified'
    );
  }

  // Check if otp has been expired
  const currentTime = new Date().getTime();
  if (emailOtpExpiredTime < currentTime) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, 'OTP has been expired');
  }

  // Verify otp
  if (inputOtp !== emailOtp) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, 'OTP does not match');
  }

  // Verified email
  user.isVerifiedEmail = true;
  const updatedUser = await user.save();

  return sanitizeUser(updatedUser);
};

const generateToken = (
  payload: any,
  secret: string,
  expiresIn = TOKEN_EXPRIED_IN
) => {
  return jwt.sign(payload, secret, { expiresIn });
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
};

export default authService;
