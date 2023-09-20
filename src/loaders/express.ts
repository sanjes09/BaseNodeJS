import express, { Express, Request, Response, NextFunction } from 'express';
import morgan from 'morgan';
import config from 'config';
import cookieParser from 'cookie-parser';
import routes from '../api';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import path from 'path';
import helmet from 'helmet';
import cors from "cors";
import compression from 'compression';

export default ({ app } : { app: Express }) => {

  const limit = rateLimit({
    max: 1000,// max requests
    windowMs: 60 * 60 * 1000, // 1 Hour of 'ban' / lockout 
    message: 'Too many requests, you are locked for 1hr' // message to send
  });
  /**
   * Middlewares
   */

  app.use(express.urlencoded({extended: true ,limit: '1mb'}))
  app.use(express.static(path.join(__dirname,'public'), {
    dotfiles: 'allow',
    maxAge: 31557600000,
    setHeaders: function(res, path) {
      res.setHeader("Expires", new Date(Date.now() + 2592000000*30).toUTCString());
    }
  }));

  /// Body Parser
  app.use(express.json({ limit: '10kb' }));
  app.use(mongoSanitize());
  app.use(compression());
  app.use(helmet());
  
  /// Cookie Parser
  app.use(cookieParser());

  // Useful if you're behind a reverse proxy (Heroku, Bluemix, AWS ELB, Nginx, etc)
  // It shows the real origin IP in the heroku or Cloudwatch logs
  app.enable('trust proxy');

  /// Cors
  app.use( '*', limit);
  app.use(
    cors({
      origin: config.get<string>('origin'),
      credentials: true,
    })
  );
  app.options("*", cors());

  /// Load API routes
  app.use(config.get<string>('api.prefix'), routes());

  /// Handle Error
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    err.status = err.status || 'error';
    err.statusCode = err.statusCode || 500;

    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
  });

  /// Logger
  if (process.env.NODE_ENV === 'development') app.use(morgan('dev'));

  /**
   * Health Check endpoints
   */
  app.get('/status', (req, res) => {
    res.status(200).json({
      status: 'success',
      message: 'Welcome',
    });
  });
  app.head('/status', (req, res) => {
    res.status(200).end();
  });

  
  /// Catch 404 and forward to error handler
  app.all('*', (req: Request, res: Response, next: NextFunction) => {
    const err = new Error(`Route ${req.originalUrl} not found`) as any;
    err.statusCode = 404;
    next(err);
  });
  
  
  /**
   * Error Handler
   */
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    /**
     * Handle 401 thrown by express-jwt library
     */
    if (err.name === 'UnauthorizedError') {
      return res
        .status(err.status)
        .send({ message: err.message })
        .end();
    }
    return next(err);
  });

  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    err.status = err.status || 'error';
    err.statusCode = err.statusCode || 500;

    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
  });
};
