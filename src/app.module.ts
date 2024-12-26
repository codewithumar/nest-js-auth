import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthController } from './auth/auth.controller';
import { AuthService } from './auth/auth.service';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [
    AuthModule,
    ConfigModule.forRoot({
      envFilePath: '.env', 
      isGlobal: true, 
    }),
    MongooseModule.forRoot(
      process.env.DB_URL,
    ), 
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
