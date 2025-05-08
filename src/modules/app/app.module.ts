import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard } from '@nestjs/throttler';
import { AuthGuard } from '../../providers/guards/auth.guard';
import { DbModule } from '../global/db.module';
import { MyJwtModule } from '../global/jwt.module';
import { MyThrottlerModule } from '../global/throttler.module';
import { MyStaticWebModule } from '../global/static.web.module';
import { MyPinoLoggerModule as PinoConfigModule } from '../global/pino-logger.module';
import { AuthModule } from '../auth/auth.module';
import { UserModule } from '../user/user.module';
import { HashModule } from '../hash/hash.module';
import { MailModule } from '../mailer/mailer.module';
import { HealthModule } from '../health/health.module';
import { AppController } from './app.controller';
import { AppService } from './app.service';

@Module({
  imports: [
    AuthModule,
    DbModule,
    HashModule,
    HealthModule,
    MailModule,
    MyJwtModule,
    MyStaticWebModule,
    MyThrottlerModule,
    PinoConfigModule,
    UserModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    AppService,
  ],
})
export class AppModule {}
