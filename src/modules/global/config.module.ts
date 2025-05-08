import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { configSchema } from '../../common/config/config.validation';
import { getConfig } from '../../common/config/service-config';

/**
 * Configuration module to read and validate environment variables.
 * This is not used currently in the app.  But left here in case
 * someone wants to use it in the future.
 *
 * How to use:
 * 1. Inject the config service in the constructor:
 *
 *        constructor(private readonly configService: ConfigService) {}
 *
 * 2. Use the config service to get the values you need
 *
 *        this.configService.get('NODE_ENV');
 *
 * @export
 * @class MyConfigModule
 */
@Module({
  imports: [
    ConfigModule.forRoot({
      load: [getConfig],
      isGlobal: true,
      cache: true,
      expandVariables: true,
      envFilePath: [`.env.${process.env.NODE_ENV}`, `.env.${process.env.NODE_ENV}.local`],
      validationSchema: configSchema,
    }),
  ],
})
export class MyConfigModule {}
