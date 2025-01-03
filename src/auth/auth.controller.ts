import { Body, Controller, Get, Post, UseGuards,Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDTO } from './dtos/signup.dto';
import { LoginDTO } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshTokenDTO } from './dtos/refresh-token.schema';
import { JwtAuthGuard } from 'src/guards/auth.guard';


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
  @Post('refresh')
  async refresh(@Body() refreshTokenDTO: RefreshTokenDTO) {
    return await this.authService.refresh(refreshTokenDTO);
  }
  @Get('currentUser')
  @UseGuards(JwtAuthGuard)
  async currentUser(@Request() req: any) {
    return await this.authService.currentUser(req.headers.authorization);
  }

}
