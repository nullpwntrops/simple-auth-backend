import { Module } from '@nestjs/common';
import { TypeOrmModule, TypeOrmModuleOptions } from '@nestjs/typeorm';
import { Config } from '../../common/constants';
import { getConfig } from '../../common/config/service-config';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      useFactory: async (): Promise<TypeOrmModuleOptions> => {
        const { database } = getConfig();
        return {
          type: Config.DB_TYPE,
          host: database.host,
          port: database.port,
          database: database.database,
          username: database.username,
          password: database.password,
          synchronize: database.sync,
          logging: database.logging,
          autoLoadEntities: true,
          migrations: [__dirname + '/migrations/**/*{.ts,.js}'],
          migrationsRun: false,
        };
      },
    }),
  ],
})
export class DbModule {}
