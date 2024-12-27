import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schema/user.schema';
import { Model } from 'mongoose';
import * as  bcrypt from 'bcrypt';
import { SignUpDTO } from './dtos/signup.dto';
import { LoginDTO } from './dtos/login.dto';
import { Token } from './schema/token.schema';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { RefreshTokenDTO } from './dtos/refresh-token.schema';


@Injectable()
export class AuthService {
  constructor (
    @InjectModel(User.name) private UserModel:Model<User>,
    @InjectModel(Token.name) private TokenModel:Model<Token>,
    private readonly jwtService : JwtService,
  ) {}
  
  async currentUser(token: string) {
    const Token = await this.TokenModel.findOne({ token });
    if (!Token.userId) {
      throw new BadRequestException('Invalid token');
    }
    const user = await this.UserModel.findById(Token.userId);
    if (!user) {
      throw new BadRequestException('Invalid token');
    }
    return {
      user: user,
      Token,
    };
  }
  async refresh(refreshTokenDTO : RefreshTokenDTO) {
    
    const { refreshToken } = refreshTokenDTO;
    const token = await this.TokenModel.findOne({ 
      refreshToken:refreshToken,
      expiresAt: { $gt: new Date() },
    });
    if (!token) {
      throw new BadRequestException('Invalid refresh token');
    }
    const tokens = this.generateTokens(token.userId);
    
    await token.updateOne({
      token: tokens.token,
      expiresAt: tokens.expiresAt,
      refreshToken: tokens.refreshToken,
    });

    return {
      token: tokens.token ,
      refreshToken: tokens.refreshToken,
      expiresAt: tokens.expiresAt,
    };
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
  
      const tokens = this.generateTokens(user._id);
  
     await this.TokenModel.create({
        userId: user._id,
        ...tokens
      });
  
      const userResponse = user.toObject();
      delete userResponse.password;
  
      return {
        user: userResponse,
        ...tokens,
      };
    }
   generateTokens(userId) {
    
    const token = this.jwtService.sign({userId});
    const expiresIn = process.env.JWT_EXPIRES_IN;
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + parseInt(expiresIn));
    const refreshToken = uuidv4();

    return {
      token : token,
      refreshToken : refreshToken,
      expiresAt : expiresAt,
    };
  }
  async signup(signupData: SignUpDTO) {

    const {
      name,
      email,
      password
    } = signupData

    const emailInUse = await this.UserModel.findOne({ email : email });
    
    if (emailInUse) {
      throw new BadRequestException('Email already in use');
    }

    const hashPassword = await bcrypt.hash( password, 10);


    const UserCreated = await this.UserModel.create({
      name,
      email,
      password:hashPassword
    })

    return {
      id: UserCreated._id,
      name: UserCreated.name,
      email: UserCreated.email,
    }
  }
}
