import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { LoggerInterceptor } from './interceptors/logging.interceptor';
import { ResponseSerializerInterceptor } from './interceptors/response-serializer.interceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe(
    {
      whitelist: true,
      forbidNonWhitelisted: true,
    }
  ),);
  app.useGlobalInterceptors(new LoggerInterceptor(),new ResponseSerializerInterceptor());
  await app.listen(process.env.PORT);
}
bootstrap();
