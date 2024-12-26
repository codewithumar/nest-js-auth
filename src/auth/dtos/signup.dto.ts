import { IsEmail, IsString, Matches, MinLength } from "class-validator";

export class SignUpDTO{
    @IsString()
    name: string;

    @IsEmail()
    email: string;
    
    @IsString()
    @MinLength(8)
    // @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/, {message: 'Password too weak'})
    password: string;
} 