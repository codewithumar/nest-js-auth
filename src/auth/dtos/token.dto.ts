import { IsDate, IsString } from "class-validator";
export class TokenDTO{
    @IsString()
    userId: string;

    @IsString()
    token: string;
    @IsDate()
    createdAt: Date;
    
    @IsDate()
    expiresAt: Date;

  } 