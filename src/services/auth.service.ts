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
import uploadHelper from '../shared/helpers/upload.helper';
import { ACCESS_TOKEN_EXPRIED_IN } from '../shared/constants';
import LoginType from '../shared/enums/loginType';

const register = async (body: RegisterUser) => {
  const { email, password, firstName, lastName } = body;

  // Check if email is existed
  const existedUser = await User.findOne({ email });
  if (existedUser) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      'Email address already exists'
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
    avatar: '',
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
  const accessToken = generateToken(
    { sub: user._id },
    process.env.ACCESS_TOKEN_SECRET
  );

  return {
    ...sanitizeUser(user),
    accessToken,
  };
};

const login = async (body: LoginUser) => {
  const { email, password } = body;

  // Check if email is not existed
  const user = await User.findOne({ email });
  if (!user) {
    throw new HttpException(HttpStatusCode.NOT_FOUND, 'Email is not existed');
  }

  // Compare input password with stored password
  const isCorrectPassword = await bcrypt.compare(password, user.password);

  if (!isCorrectPassword) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, 'Incorrect password');
  }

  // Generate MFA token if MFA is enabled
  if (user.mfa.isEnabled) {
    const mfaToken = generateToken({ sub: user._id }, process.env.MFA_SECRET);
    return { mfaToken };
  } else {
    // If not, generate access token and return customer infor
    const accessToken = generateToken(
      { sub: user._id },
      process.env.ACCESS_TOKEN_SECRET
    );

    return {
      ...sanitizeUser(user),
      accessToken,
    };
  }
};

const sanitizeUser = (user: UserModel) => {
  const { password, emailVerification, mfa, __v, ...basicUserInfo } =
    JSON.parse(JSON.stringify(user));
  const isVerifiedEmail = emailVerification.isVerified;
  const isEnabledMfa = mfa.isEnabled;

  return {
    user: { ...basicUserInfo, isVerifiedEmail, isEnabledMfa },
  };
};

const getQRCode = async (email: string, mfaOtpSecret: string) => {
  const qrCodeImgUrl = await otpHelper.generateQRCode(email, mfaOtpSecret);

  return {
    qrCodeImgUrl,
  };
};

const toggleMfa = async (otp: string, user: UserDocument) => {
  const { mfa } = user;
  const isValid = otpHelper.verifyOtpToken(otp, mfa.otpSecret);

  if (!isValid) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, 'Invalid OTP');
  }

  // Toggle MFA
  user.mfa.isEnabled = !user.mfa.isEnabled;
  const updatedUser = await user.save();

  return sanitizeUser(updatedUser);
};

const verifyMfa = async (otp: string, mfaToken: string) => {
  // Verify MFA token
  const decoded = jwt.verify(mfaToken, process.env.MFA_SECRET) as JwtPayload;

  if (!decoded) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, 'Invalid MFA token');
  }

  const user = await User.findById(decoded.sub);

  // Verify otp
  const isValid = otpHelper.verifyOtpToken(otp, user.mfa.otpSecret);
  if (!isValid) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, 'Invalid OTP');
  }

  // Generate access token
  const accessToken = generateToken(
    { sub: user._id },
    process.env.ACCESS_TOKEN_SECRET
  );

  return {
    ...sanitizeUser(user),
    accessToken,
  };
};

const sendVerifyEmail = async (user: UserDocument) => {
  const { email, emailVerification } = user;

  // Check if account has been verified
  if (emailVerification.isVerified) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      'Your account has been verified'
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

const verifyEmail = async (inputOtp: string, user: UserDocument) => {
  const { emailVerification } = user;

  if (emailVerification.isVerified) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      'Your account has been verified'
    );
  }

  // Check if otp has been expired
  const currentTime = new Date().getTime();
  if (emailVerification.expiredTime < currentTime) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, 'OTP has been expired');
  }

  // Verify otp
  if (inputOtp !== emailVerification.code) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, 'OTP does not match');
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

const updateAvatar = async (base64Img: string, user: UserDocument) => {
  const imgUrl = await uploadHelper.uploadImg(base64Img);

  user.avatar = imgUrl;
  const updatedUser = await user.save();

  return sanitizeUser(updatedUser);
};

const updatePassword = async (body: any, user: UserDocument) => {
  // Compare input password with stored password
  const isCorrectPassword = await bcrypt.compare(
    body.oldPassword,
    user.password
  );

  if (!isCorrectPassword) {
    throw new HttpException(
      HttpStatusCode.BAD_REQUEST,
      'Password does not match'
    );
  }

  // Generate salt
  const salt = await bcrypt.genSalt(10);

  // Hash password with generated salt
  const hashedPassword = await bcrypt.hash(body.password, salt);

  user.password = hashedPassword;
  const updatedUser = await user.save();

  return sanitizeUser(updatedUser);
};

const requestResetPassword = async (email: string) => {
  const existedUser = await User.findOne({ email });
  if (!existedUser) {
    throw new HttpException(
      HttpStatusCode.NOT_FOUND,
      'Email address not found'
    );
  }

  const passwordToken = generateToken(
    { sub: existedUser._id },
    process.env.PASSWORD_SECRET
  );

  // Send mail url reset password
  const emailOptions = mailHelper.generateResetPasswordOptions(
    email,
    passwordToken
  );
  await mailHelper.sendMail(emailOptions);

  return passwordToken;
};

const verifyResetPassword = async (passwordToken: string, password: string) => {
  // Verify password token
  const decoded = jwt.verify(
    passwordToken,
    process.env.PASSWORD_SECRET
  ) as JwtPayload;

  if (!decoded) {
    throw new HttpException(HttpStatusCode.BAD_REQUEST, 'Invalid token');
  }

  const user = await User.findById(decoded.sub);
  const hashedPassword = await generateHashedPassword(password);
  user.password = hashedPassword;
  const updatedUser = await user.save();

  return sanitizeUser(updatedUser);
};

const generateToken = (
  payload: any,
  secret: string,
  expiresIn = ACCESS_TOKEN_EXPRIED_IN
) => {
  return jwt.sign(payload, secret, { expiresIn });
};

const generateHashedPassword = async (password: string) => {
  // Generate salt
  const salt = await bcrypt.genSalt(10);

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
  updateAvatar,
  updatePassword,
  requestResetPassword,
  verifyResetPassword,
};

export default authService;
