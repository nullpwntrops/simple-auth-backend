import { Module } from '@nestjs/common';
import { UserModule } from '../user/user.module';
import { HashModule } from '../hash/hash.module';
import { MailModule } from '../mailer/mailer.module';
import { UserService } from '../user/user.service';
import { HashService } from '../hash/hash.service';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

@Module({
  imports: [UserModule, HashModule, MailModule],
  controllers: [AuthController],
  providers: [AuthService, UserService, HashService],
  exports: [AuthService],
})
export class AuthModule {}
