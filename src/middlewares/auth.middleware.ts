import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import HttpException from '../shared/helpers/exception.helper';
import HttpStatusCode from '../shared/enums/httpStatus';
import User, { UserDocument } from '../models/user.model';
import { ACCESS_TOKEN_SECRET } from '../config/env.config';
import { ERROR_MSG } from '../shared/constants/errorMsg';

export type AuthenticatedRequest = Request & { user?: UserDocument };

/**
 * Middleware function to authenticate requests.
 *
 * @param req - The request object.
 * @param res - The response object.
 * @param next - The next function to call.
 * @throws {HttpException} If authentication token is not found, token is invalid, or user is not found.
 */
const authenticateMiddleware = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    throw new HttpException(
      HttpStatusCode.UNAUTHORIZED,
      ERROR_MSG.AUTHENTICATION_TOKEN_NOT_FOUND
    );
  }

  const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);

  if (!decoded) {
    throw new HttpException(HttpStatusCode.FORBIDDEN, ERROR_MSG.INVALID_TOKEN);
  }

  const user = await User.findById(decoded.sub);

  if (!user) {
    throw new HttpException(
      HttpStatusCode.UNAUTHORIZED,
      ERROR_MSG.USER_NOT_FOUND
    );
  }

  req.user = user;
  next();
};

export default authenticateMiddleware;
