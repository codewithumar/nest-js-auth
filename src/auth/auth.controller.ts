import { Body, Controller, Get, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDTO } from './dtos/signup.dto';
import { LoginDTO } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';


@Controller('auth')
export class AuthController {
  constructor (
    private readonly authService : AuthService,
    private readonly jwtService : JwtService,
  ){}
  
  @Post('signup')
  async signup(@Body() signupData: SignUpDTO) {
    return await this.authService.signup(signupData);
  }
  @Post('login')
  async login(@Body() loginDto: LoginDTO) {
    const response = await this.authService.logIn(loginDto);
    return response;
  }
  @Post('currentUser')
  async currentUser(@Body() token: string) {
    return await this.authService.currentUser(token);
  }

}
