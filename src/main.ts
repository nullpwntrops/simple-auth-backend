import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { Logger, ValidationPipe } from '@nestjs/common';
import { Logger as PinoLogger } from 'nestjs-pino';
import { Enums } from './common/constants';
import { TopRoute } from './common/constants/routes';
import { getConfig } from './common/config/service-config';
import { HttpExceptionFilter } from './providers/filters/http-exception.filter';
import { validationPipeOptions } from './providers/validators/validation-pipe-options';
import { ResponseInterceptor } from './providers/interceptors/response.interceptor';
import { AppModule } from './modules/app/app.module';

async function bootstrap() {
  const logger = new Logger('Bootstrap');

  // Instantiate the app
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
  });
  app.useLogger(app.get(PinoLogger));

  // Retrieve configuration settings
  const service = getConfig().service;

  switch (service.nodeEnv) {
    case Enums.NodeEnv.DEVELOPMENT:
      // Call seeder service to populate database with fake data
      break;

    case Enums.NodeEnv.PRODUCTION:
      // Set the global prefix
      app.setGlobalPrefix(TopRoute);

      // Start listening for shutdown hooks
      // app.enableShutdownHooks();

      // Install global HTTP Exception filter
      app.useGlobalFilters(new HttpExceptionFilter());

      // TODO: install CSRF protection

      // Enable CORS
      app.enableCors({
        origin: '*',
        methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
        preflightContinue: false,
        optionsSuccessStatus: 204,
      });
  }

  // Install global validation
  const validationOptions = validationPipeOptions();
  app.useGlobalPipes(new ValidationPipe(validationOptions));
  app.useGlobalInterceptors(new ResponseInterceptor(app.get(PinoLogger)));

  // Start listening
  await app.listen(service.port);

  // Log a few things to the console so we know it's alive
  logger.log('************************************************************');
  logger.log(`Application name is ${service.app_name}`);
  logger.log(`Service name is ${service.serviceName}`);
  logger.log(`Service URL on: http://localhost:${service.port}`);
  logger.log(`Docker URL  on: http://localhost:${service.dockerPort}`);
  logger.log('************************************************************');
}
void bootstrap();
