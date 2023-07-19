import nodemailer from 'nodemailer';
import { OAuth2Client } from 'google-auth-library';

const MAIL_HOST = 'smtp.gmail.com';
const MAIL_PORT = 465;

const sendMail = async (email: string, emailOtp: string) => {
  const transport = await createTransport();

  const subject = '[AuthOne] Email Verification';
  const content = `Your verification code is: ${emailOtp}`;
  const mailOptions = {
    to: email,
    subject,
    html: content,
  };

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

const mailHelper = {
  sendMail,
};

export default mailHelper;
