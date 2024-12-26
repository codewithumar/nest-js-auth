import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schema/user.schema';
import { Model } from 'mongoose';
import * as  bcrypt from 'bcrypt';
import { SignUpDTO } from './dtos/signup.dto';
import { LoginDTO } from './dtos/login.dto';

@Injectable()
export class AuthService {
  constructor (@InjectModel(User.name) private UserModel:Model<User>) {}



  async logIn(loginData: LoginDTO) {
    const {
      email,
      password
    } = loginData;
    
    const user = await this.UserModel.findOne({
      email: email
    });

    if (!user) {
      throw new BadRequestException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new BadRequestException('Invalid credentials');
    }

    delete user.password;

    return user ;
    
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

    return UserCreated
  }
}
