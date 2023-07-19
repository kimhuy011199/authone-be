import qrcode from 'qrcode';
import { authenticator } from 'otplib';

const QR_CODE_SERVICE_NAME = 'AuthOne';
const OTP_LENGTH = 6;
const DEFAULT_EXPIRED_TIME = 2 * 60 * 1000;

const generateSecret = () => {
  return authenticator.generateSecret();
};

const generateOTPToken = (secret: string) => {
  return authenticator.generate(secret);
};

const verifyOTPToken = (token: string, secret: string) => {
  return authenticator.verify({ token, secret });
};

const generateQRCode = async (email: string, secret: string) => {
  const text = authenticator.keyuri(email, QR_CODE_SERVICE_NAME, secret);
  return await qrcode.toDataURL(text);
};

const generateEmailOtp = (
  length = OTP_LENGTH,
  expiredAfter = DEFAULT_EXPIRED_TIME
) => {
  // Generate email OTP
  const charset = '0123456789';
  let emailOtp = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length);
    emailOtp += charset[randomIndex];
  }

  // Generate expired time
  const currentTime = new Date().getTime();
  const expiredTime = currentTime + expiredAfter;

  return { emailOtp, expiredTime };
};

const getRemaningTime = (emailOtpExpiredTime: number) => {
  const currentTime = new Date().getTime();
  const timeRemaining = (emailOtpExpiredTime - currentTime) / 1000;

  return +timeRemaining.toString().split('.')[0];
};

const otpHelper = {
  generateSecret,
  generateOTPToken,
  verifyOTPToken,
  generateQRCode,
  generateEmailOtp,
  getRemaningTime,
};

export default otpHelper;
