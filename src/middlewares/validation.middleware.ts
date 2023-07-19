import { Request, Response, NextFunction } from 'express';
import Joi, { Schema } from 'joi';
import HttpException from '../shared/helpers/exception.helper';
import HttpStatusCode from '../shared/enums/httpStatus';

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
