import { Request, Response, NextFunction } from 'express';
import AppError from '../utils/appError';

export const rolePermission =
  (...allowedRoles: string[]) =>
  (req: Request, res: Response, next: NextFunction) => {
    const user = res.locals.user;
    if (!allowedRoles.includes(user.role)) {
      return next(
        new AppError('You are not allowed to perform this action', 403)
      );
    }

    next();
  };