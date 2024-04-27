import { Request, Response, NextFunction } from 'express';
import { Schema } from 'joi';
import HttpException from '../shared/helpers/exception.helper';
import HttpStatusCode from '../shared/enums/httpStatus';

/**
 * Middleware function to validate request body against a given schema.
 * @param schema - The schema to validate against.
 * @returns A middleware function that validates the request body.
 */
const validateMiddleware = (schema: Schema) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error } = schema.validate(req.body);

    if (error) {
      const errorMessage = error.details
        .map((detail) => detail.message)
        .join(', ');
      throw new HttpException(HttpStatusCode.BAD_REQUEST, errorMessage);
    }

    next();
  };
};

export default validateMiddleware;
