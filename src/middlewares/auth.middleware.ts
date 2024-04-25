import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import HttpException from '../shared/helpers/exception.helper';
import HttpStatusCode from '../shared/enums/httpStatus';
import User, { UserDocument } from '../models/user.model';

export type AuthenticatedRequest = Request & { user?: UserDocument };

const authenticateMiddleware = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    throw new HttpException(
      HttpStatusCode.UNAUTHORIZED,
      'Authentication token not found'
    );
  }

  const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

  if (!decoded) {
    throw new HttpException(HttpStatusCode.FORBIDDEN, 'Invalid token');
  }

  const user = await User.findById(decoded.sub);
  req.user = user;
  next();
};

export default authenticateMiddleware;
