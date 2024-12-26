
import {
    Injectable,
    NestInterceptor,
    ExecutionContext,
    CallHandler,
  } from '@nestjs/common';
  import { Observable } from 'rxjs';
  import { tap } from 'rxjs/operators';
  import { Logger } from '@nestjs/common';
  
  @Injectable()
  export class LoggerInterceptor implements NestInterceptor {
    private readonly logger = new Logger('HTTP');
  
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
      const request = context.switchToHttp().getRequest();
      const { method, url,body } = request;
  
      const startTime = Date.now();
      this.logger.log(`Incoming Request: ${method} ${url} - ${JSON.stringify(body)}`);
  
      return next.handle().pipe(
        tap(() => {
          const duration = Date.now() - startTime;
          this.logger.log(`Response Sent: ${method} ${url} - ${duration}ms`);
        }),
      );
    }
  }
  