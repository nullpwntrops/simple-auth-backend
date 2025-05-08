import { Module } from '@nestjs/common';
import { ThrottlerModule, ThrottlerModuleOptions } from '@nestjs/throttler';
import { getConfig } from '../../common/config/service-config';

@Module({
  imports: [
    ThrottlerModule.forRootAsync({
      useFactory: async (): Promise<ThrottlerModuleOptions> => {
        const { throttler } = getConfig();
        return [
          {
            ttl: throttler.ttl,
            limit: throttler.limit,
          },
        ];
      },
    }),
  ],
})
export class MyThrottlerModule {}
