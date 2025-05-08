import { Module } from '@nestjs/common';
import { LoggerModule, Params } from 'nestjs-pino';
import { Options } from 'pino-http';
import { v4 as uuid4 } from 'uuid';
import { getConfig } from '../../common/config/service-config';

@Module({
  imports: [
    LoggerModule.forRootAsync({
      useFactory: async (): Promise<Params> => {
        const config = getConfig();
        const pinoParams: Options = {
          level: <string>config.misc.pinoLogLevel,
          genReqId: (req) => {
            return req.headers['x-request-id'] || uuid4();
          },
        };
        if (!config.service.isProduction) {
          const extraParams: Options = {
            quietReqLogger: true,
            quietResLogger: true,
            autoLogging: false,
            transport: {
              target: 'pino-pretty',
              options: {
                colorize: true,
                translateTime: 'SYS:standard',
              },
            },
          };
          Object.assign(pinoParams, extraParams);
        }
        return { pinoHttp: pinoParams };
      },
    }),
  ],
  exports: [LoggerModule],
})
export class MyPinoLoggerModule {}
