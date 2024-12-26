import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthController } from './auth/auth.controller';
import { AuthService } from './auth/auth.service';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [MongooseModule.forRoot(
    "mongodb+srv://Cluster56258:92cF3_xzURvgnMy@cluster56258.d5lxj.mongodb.net/test"
  ), AuthModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
