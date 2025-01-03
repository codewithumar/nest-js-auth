import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schema/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { SignUpDTO } from './dtos/signup.dto';
import { LoginDTO } from './dtos/login.dto';
import { Token } from './schema/token.schema';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { RefreshTokenDTO } from './dtos/refresh-token.schema';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private UserModel: Model<User>,
    @InjectModel(Token.name) private TokenModel: Model<Token>,
    private readonly jwtService: JwtService,
  ) {}

  async currentUser(token: string | { token: string }) {
    const tokenString = typeof token === 'string' ? token : token.token;

    const Token = await this.TokenModel.findOne({ token: tokenString.split(' ')[1] });
    if (!Token || !Token.userId) {
      throw new BadRequestException('Invalid token');
    }

    const user = await this.UserModel.findById(Token.userId);
    if (!user) {
      throw new BadRequestException('Invalid token');
    }

    return {
      user,
    };
  }

  async refresh(refreshTokenDTO: RefreshTokenDTO) {
    const { refreshToken } = refreshTokenDTO;
    const token = await this.TokenModel.findOneAndDelete({
      refreshToken: refreshToken,
      expiresAt: { $gt: new Date() },
    });
    if (!token) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    return await this.generateTokens(token.userId);
  }

  async logIn(loginData: LoginDTO) {
    const { email, password } = loginData;

    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new BadRequestException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new BadRequestException('Invalid credentials');
    }

    return await this.generateTokens(user._id);
  }

  async signup(signupData: SignUpDTO) {
    const { name, email, password } = signupData;

    const emailInUse = await this.UserModel.findOne({ email: email });

    if (emailInUse) {
      throw new BadRequestException('Email already in use');
    }

    const hashPassword = await bcrypt.hash(password, 10);

    const UserCreated = await this.UserModel.create({
      name,
      email,
      password: hashPassword,
    });
    return await this.generateTokens(UserCreated._id);
  }

  async generateTokens(userId) {
    const token = this.jwtService.sign({ userId });
    const refreshToken = uuidv4();
    await this.TokenModel.findOneAndDelete({
      userId: userId,
    });
    await this.storeRefreshToken(userId, token, refreshToken);

    return {
      token: token,
      refreshToken: refreshToken,
    };
  }

  async storeRefreshToken(userId: string, token: string, refreshToken: string) {
    const expiresAt = new Date();
    expiresAt.setHours(
      expiresAt.getHours() + parseInt(process.env.JWT_EXPIRES_IN),
    );

    await this.TokenModel.create({
      userId: userId,
      token: token,
      refreshToken: refreshToken,
      expiresAt: expiresAt,
    });
  }
}
