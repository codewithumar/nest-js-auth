import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schema/user.schema';
import { Model } from 'mongoose';
import * as  bcrypt from 'bcrypt';
import { SignUpDTO } from './dtos/signup.dto';
import { LoginDTO } from './dtos/login.dto';
import { create } from 'domain';
import { Token } from './schema/token.schema';
import { JwtService } from '@nestjs/jwt';


@Injectable()
export class AuthService {
  constructor (
    @InjectModel(User.name) private UserModel:Model<User>,
    @InjectModel(Token.name) private TokenModel:Model<Token>,
    private readonly jwtService : JwtService,
  ) {}
  
  async currentUser(token: string) {
    const user = await this.UserModel.findOne({ email: token });
    if (!user) {
      throw new BadRequestException('Invalid token');
    }
    return user;
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
  
      const payload = {
        sub: user._id,
        email: user.email,
      };
      
      const token = this.jwtService.sign(payload);
  
      const expiresIn = process.env.JWT_EXPIRES_IN
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + parseInt(expiresIn));
  
     await this.TokenModel.create({
        userId: user._id,
        token,
        expiresAt,
      });
  
      const userResponse = user.toObject();
      delete userResponse.password;
  
      return {
        user: userResponse,
        token,
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
