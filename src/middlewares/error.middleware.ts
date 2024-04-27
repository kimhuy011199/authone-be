import { NextFunction, Request, Response } from 'express';
import HttpStatusCode from '../shared/enums/httpStatus';
import { ERROR_MSG } from '../shared/constants/errorMsg';
import { NODE_ENV } from '../config/env.config';

declare global {
  interface Error {
    statusCode: number;
  }
}

/**
 * Express middleware for handling errors.
 *
 * @param {Error} err - The error object.
 * @param {Request} req - The Express request object.
 * @param {Response} res - The Express response object.
 * @param {NextFunction} next - The next middleware function.
 */
const errorMiddleware = (
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const statusCode = err.statusCode || HttpStatusCode.INTERNAL_SERVER_ERROR;
  const message = err.message || ERROR_MSG.INTERNAL_SERVER_ERROR;
  console.log(err.stack);

  const errorResponse = {
    message,
    error: {
      name: err.name,
      // Only include the stack trace in development
      stack: NODE_ENV === 'development' ? err.stack : undefined,
    },
    statusCode,
  };

  res.status(statusCode).json(errorResponse);
};

export default errorMiddleware;
