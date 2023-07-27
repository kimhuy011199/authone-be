import { Request, Response } from 'express';
import { AuthenticatedRequest } from '../middlewares/auth.middleware';
import authService from '../services/auth.service';
import HttpStatusCode from '../shared/enums/httpStatus';

const register = async (req: Request, res: Response) => {
  const data = await authService.register(req.body);
  res.status(HttpStatusCode.CREATED).json(data);
};

const login = async (req: Request, res: Response) => {
  const data = await authService.login(req.body);
  res.status(HttpStatusCode.OK).json(data);
};

const getMe = (req: AuthenticatedRequest, res: Response) => {
  const data = authService.sanitizeUser(req.user);
  res.status(HttpStatusCode.OK).json(data);
};

const getQRCode = async (req: AuthenticatedRequest, res: Response) => {
  const { email, mfaOtpSecret } = req.user;
  const data = await authService.getQRCode(email, mfaOtpSecret);
  res.status(HttpStatusCode.OK).json(data);
};

const toggleMfa = async (req: AuthenticatedRequest, res: Response) => {
  const { otp } = req.body;
  const data = await authService.toggleMfa(otp, req.user);
  res.status(HttpStatusCode.OK).json(data);
};

const verifyMfa = async (req: Request, res: Response) => {
  const { otp, mfaToken } = req.body;
  const data = await authService.verifyMfa(otp, mfaToken);
  res.status(HttpStatusCode.OK).json(data);
};

const sendVerifyEmail = async (req: AuthenticatedRequest, res: Response) => {
  const data = await authService.sendVerifyEmail(req.user);
  res.status(HttpStatusCode.OK).json(data);
};

const verifyEmail = async (req: AuthenticatedRequest, res: Response) => {
  const { otp } = req.body;
  const data = await authService.verifyEmail(otp, req.user);
  res.status(HttpStatusCode.OK).json(data);
};

const updateUser = async (req: AuthenticatedRequest, res: Response) => {
  const data = await authService.updateUser(req.body, req.user);
  res.status(HttpStatusCode.OK).json(data);
};

const updateAvatar = async (req: AuthenticatedRequest, res: Response) => {
  const { base64Img } = req.body;
  const data = await authService.updateAvatar(base64Img, req.user);
  res.status(HttpStatusCode.OK).json(data);
};

const updatePassword = async (req: AuthenticatedRequest, res: Response) => {
  const data = await authService.updatePassword(req.body, req.user);
  res.status(HttpStatusCode.OK).json(data);
};

const requestResetPassword = async (req: Request, res: Response) => {
  const { email } = req.body;
  const data = await authService.requestResetPassword(email);
  res.status(HttpStatusCode.OK).json(data);
};

const verifyResetPassword = async (req: Request, res: Response) => {
  const { passwordToken, password } = req.body;
  const data = await authService.verifyResetPassword(passwordToken, password);
  res.status(HttpStatusCode.OK).json(data);
};

const authController = {
  register,
  login,
  getMe,
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

export default authController;
