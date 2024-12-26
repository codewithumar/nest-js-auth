import { MiddlewareConsumer, Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AppService } from 'src/app.service';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './schema/user.schema';
import { LowercaseEmailMiddleware } from './middlewares/lowercase-email.middleware';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt/jwt.strategy';

@Module({
  imports: [
    MongooseModule.forFeature([{
    name: User.name,
    schema:UserSchema
  }]),
  PassportModule,
  JwtModule.register({
    secret: 'your-secret-key',
    signOptions: { expiresIn: '1h' }, 
  }),
],
  controllers: [ AuthController ],
  providers: [ AuthService , JwtStrategy ],
})
export class AuthModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(LowercaseEmailMiddleware)
      .forRoutes('auth/signup');
  }

}
