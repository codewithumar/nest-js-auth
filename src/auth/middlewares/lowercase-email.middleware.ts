import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class LowercaseEmailMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction): void {
    if (req.body && typeof req.body.email === 'string') {
      req.body.email = req.body.email.toLowerCase();
    }
    next();
  }
}
