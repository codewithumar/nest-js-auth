import { Prop,Schema,SchemaFactory } from '@nestjs/mongoose';
import { Document} from 'mongoose';

@Schema()
export class Token extends Document {
    
  @Prop({required: true})
  userId: string;

  @Prop({ required: true })
  token: string;

  @Prop({auto: true})
  createdAt: Date;
  
  @Prop({required: true,default: Date.now})
  expiresAt: Date;
}

export const TokenSchema = SchemaFactory.createForClass(Token);