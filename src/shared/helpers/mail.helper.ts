import nodemailer from 'nodemailer';
import { OAuth2Client } from 'google-auth-library';

const MAIL_HOST = 'smtp.gmail.com';
const MAIL_PORT = 465;
const CLIENT_URL = 'http://localhost:5173';

interface MailOptionsInterface {
  subject: string;
  to: string;
  html: string;
}

const sendMail = async (mailOptions: MailOptionsInterface) => {
  const transport = await createTransport();

  transport.sendMail(mailOptions);
};

const createTransport = async () => {
  const accessToken = await getAccessToken();

  const transport = nodemailer.createTransport({
    host: MAIL_HOST,
    port: MAIL_PORT,
    secure: true,
    auth: {
      type: 'OAuth2',
      user: process.env.ADMIN_EMAIL_ADDRESS,
      clientId: process.env.GOOGLE_MAILER_CLIENT_ID,
      clientSecret: process.env.GOOGLE_MAILER_CLIENT_SECRET,
      refreshToken: process.env.GOOGLE_MAILER_REFRESH_TOKEN,
      accessToken,
    },
  });

  return transport;
};

const getAccessToken = async () => {
  const myOAuth2Client = new OAuth2Client(
    process.env.GOOGLE_MAILER_CLIENT_ID,
    process.env.GOOGLE_MAILER_CLIENT_SECRET
  );

  myOAuth2Client.setCredentials({
    refresh_token: process.env.GOOGLE_MAILER_REFRESH_TOKEN,
  });
  const accessTokenObj = await myOAuth2Client.getAccessToken();
  return accessTokenObj.token;
};

const generateContentVerifyEmail = (email: string, emailOtp: string) => {
  const subject = '[AuthOne] Email Verification';
  const content = `Your verification code is: ${emailOtp}`;
  const mailOptions = {
    to: email,
    subject,
    html: content,
  };

  return mailOptions;
};

const generateContentResetPassword = (email: string, passwordToken: string) => {
  const url = `${CLIENT_URL}/new-password?pt=${passwordToken}`;
  const subject = '[AuthOne] Reset Password';
  const content = `Click on this link to create new password for your account: ${url}`;
  const mailOptions = {
    to: email,
    subject,
    html: content,
  };

  return mailOptions;
};

const mailHelper = {
  sendMail,
  generateContentVerifyEmail,
  generateContentResetPassword,
};

export default mailHelper;
