import dotenv from 'dotenv';

dotenv.config();

const {
  NODE_ENV = 'development',
  PORT = 5001,
  MONGO_URI,
  ACCESS_TOKEN_SECRET,
  MFA_SECRET,
  PASSWORD_SECRET,
  GOOGLE_MAILER_CLIENT_ID,
  GOOGLE_MAILER_CLIENT_SECRET,
  GOOGLE_MAILER_REFRESH_TOKEN,
  ADMIN_EMAIL_ADDRESS,
  MAIL_HOST = 'smtp.gmail.com',
  MAIL_PORT = 465,
  CLIENT_APP_URL,
} = process.env;

if (!MONGO_URI) {
  throw new Error('Please define the MONGO_URI environment variable');
}

if (!ACCESS_TOKEN_SECRET) {
  throw new Error('Please define the ACCESS_TOKEN_SECRET environment variable');
}

export {
  NODE_ENV,
  PORT,
  MONGO_URI,
  ACCESS_TOKEN_SECRET,
  MFA_SECRET,
  PASSWORD_SECRET,
  GOOGLE_MAILER_CLIENT_ID,
  GOOGLE_MAILER_CLIENT_SECRET,
  GOOGLE_MAILER_REFRESH_TOKEN,
  ADMIN_EMAIL_ADDRESS,
  MAIL_HOST,
  MAIL_PORT,
  CLIENT_APP_URL,
};
