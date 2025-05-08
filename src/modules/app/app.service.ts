import { Injectable } from '@nestjs/common';
import { PinoLogger } from 'nestjs-pino';
import { DateTime } from 'luxon';
import { getConfig } from '../../common/config/service-config';
import { JwtPayloadDto } from '../../database/dto/jwt-payload.dto';
import { MessageResponseDto } from '../../database/dto/message-response.dto';

@Injectable()
export class AppService {
  //********************************
  //#region Constructors
  //********************************

  constructor(private readonly logger: PinoLogger) {
    this.logger.setContext(AppService.name);
  }

  //#endregion
  //********************************

  //********************************
  //#region Public Methods
  //********************************

  /**
   * Returns a 'Hello World' message for the public route
   * Returns a more detailed message for the restricted route
   *
   * @param {boolean} verbose Flag to indicate whether to return a simple or detailed message
   * @param {JwtPayloadDto} [user] User JWT payload
   * @return {*}  {MessageResponseDto}
   * @memberof AppService
   */
  public getHello(verbose: boolean, user?: JwtPayloadDto): MessageResponseDto {
    if (verbose) {
      const { service } = getConfig();
      const now = DateTime.local();
      const time = now.toLocaleString(DateTime.DATETIME_SHORT_WITH_SECONDS);
      const uptimeInSeconds = process.uptime();
      const uptimeInMinutes = Math.floor(uptimeInSeconds / 60);
      const userName = user?.userName ?? 'Guest';
      let retVal = `Hello ${userName} from the ${service.serviceName} application!\n`;
      retVal += `Currently running in ${service.nodeEnv} mode.\n`;
      retVal += `The system time is ${time}\n`;
      retVal += `App uptime is ${uptimeInMinutes} minutes.`;
      return new MessageResponseDto(retVal);
    } else {
      return new MessageResponseDto('Hello World!');
    }
  }

  //#endregion
  //********************************
}
