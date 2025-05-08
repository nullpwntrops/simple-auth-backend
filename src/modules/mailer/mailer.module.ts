import { Module } from '@nestjs/common';
import { MailService } from './mailer.service';

@Module({
  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}
