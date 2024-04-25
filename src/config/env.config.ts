import dotenv from 'dotenv';

dotenv.config();

export const {
  PORT,
  ADMIN_EMAIL_ADDRESS,
  GOOGLE_MAILER_CLIENT_ID,
  GOOGLE_MAILER_CLIENT_SECRET,
  GOOGLE_MAILER_REFRESH_TOKEN,
  MAIL_HOST = 'smtp.gmail.com',
  MAIL_PORT = 465,
  CLIENT_APP_URL,
  MONGO_URI,
  ACCESS_TOKEN_SECRET,
  MFA_SECRET,
  PASSWORD_SECRET,
} = process.env;
