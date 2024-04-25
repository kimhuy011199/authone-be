import nodemailer from 'nodemailer';
import { OAuth2Client } from 'google-auth-library';
import { forgotPasswordMailTemplate } from '../constants/forgotPasswordMailTemplate';
import { accountVerificationTemplate } from '../constants/accountVerificationTemplate';
import { magicLinkMailTemplate } from '../constants/magicLinkMailTemplate';
import {
  ADMIN_EMAIL_ADDRESS,
  CLIENT_APP_URL,
  GOOGLE_MAILER_CLIENT_ID,
  GOOGLE_MAILER_CLIENT_SECRET,
  GOOGLE_MAILER_REFRESH_TOKEN,
  MAIL_HOST,
  MAIL_PORT,
} from '../../config/env.config';
import SMTPTransport from 'nodemailer/lib/smtp-transport';

const ACCOUNT_VERIFICATION_SUBJECT = '[AuthOne] Account Verification';
const RESET_PASSWORD_SUBJECT = '[AuthOne] Reset Password';
const MAGIC_LINK_SUBJECT = '[AuthOne] Login With Magic Link';

interface MailOptionsInterface {
  subject: string;
  to: string;
  html: string;
}

const sendMail = async (mailOptions: MailOptionsInterface) => {
  try {
    const transport = await createTransport();
    await transport.sendMail(mailOptions);
  } catch (error) {
    console.error(`Failed to send email: ${error}`);
  }
};

const createTransport = async () => {
  const accessToken = await getAccessToken();

  const transportOptions = {
    host: MAIL_HOST,
    port: +MAIL_PORT,
    secure: true,
    auth: {
      type: 'OAuth2',
      user: ADMIN_EMAIL_ADDRESS,
      clientId: GOOGLE_MAILER_CLIENT_ID,
      clientSecret: GOOGLE_MAILER_CLIENT_SECRET,
      refreshToken: GOOGLE_MAILER_REFRESH_TOKEN,
      accessToken,
    },
  } as SMTPTransport.Options;

  const transport = nodemailer.createTransport(transportOptions);
  return transport;
};

const getAccessToken = async () => {
  const myOAuth2Client = new OAuth2Client(
    GOOGLE_MAILER_CLIENT_ID,
    GOOGLE_MAILER_CLIENT_SECRET
  );

  myOAuth2Client.setCredentials({
    refresh_token: GOOGLE_MAILER_REFRESH_TOKEN,
  });
  const accessTokenObj = await myOAuth2Client.getAccessToken();
  return accessTokenObj.token;
};

const generateMagicLinkOptions = (email: string, loginToken: string) => {
  const url = `${CLIENT_APP_URL}/magic-link?token=${loginToken}`;

  const mailOptions = {
    to: email,
    subject: MAGIC_LINK_SUBJECT,
    html: magicLinkMailTemplate(url),
  };

  return mailOptions;
};

const generateVerifyEmailOptions = (email: string, emailOtp: string) => {
  const mailOptions = {
    to: email,
    subject: ACCOUNT_VERIFICATION_SUBJECT,
    html: accountVerificationTemplate(emailOtp),
  };

  return mailOptions;
};

const generateResetPasswordOptions = (email: string, passwordToken: string) => {
  const url = `${CLIENT_APP_URL}/new-password?token=${passwordToken}`;

  const mailOptions = {
    to: email,
    subject: RESET_PASSWORD_SUBJECT,
    html: forgotPasswordMailTemplate(url),
  };

  return mailOptions;
};

const mailHelper = {
  sendMail,
  generateVerifyEmailOptions,
  generateResetPasswordOptions,
  generateMagicLinkOptions,
};

export default mailHelper;
