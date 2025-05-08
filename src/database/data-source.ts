import { DataSource, DataSourceOptions } from 'typeorm';
import * as dotenv from 'dotenv';
import { Config } from '../common/constants';
import { getConfig } from '../common/config/service-config';

/*******************************************************
 * TypeORM data source options for CLI commands
 * Used for migrations and other TypeORM CLI operations
 *******************************************************/

// Load environment variables
dotenv.config({ path: '.env.development' });
const { database } = getConfig();

const dataSourceOptions: DataSourceOptions = {
  type: Config.DB_TYPE,
  host: database.host,
  port: database.port,
  username: database.username,
  database: database.database,
  password: database.password,
  synchronize: database.sync, // Should be false for production
  logging: database.logging,
  entities: ['dist/database/entities/*.entity.js'],
  migrations: ['dist/database/migrations/*.js'],
};

// Data source instance for TypeORM CLI
const dataSource = new DataSource(dataSourceOptions);
export default dataSource;
