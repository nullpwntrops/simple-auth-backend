import { Body, Controller, Get, Ip, Post, Query, Res } from '@nestjs/common';
import { Response } from 'express';
import { PinoLogger } from 'nestjs-pino';
import { UserRoles } from '../../common/constants/enums';
import { AppRoutes, AuthRoutes } from '../../common/constants/routes';
import { AppConfig, getConfig } from '../../common/config/service-config';
import { JwtPayloadDto } from '../../database/dto/jwt-payload.dto';
import { MessageResponseDto } from '../../database/dto/message-response.dto';
import { Public } from '../../providers/decorators/public.decorator';
import { User } from '../../providers/decorators/user.decorator';
import { Roles } from '../../providers/decorators/roles.decorator';
import { SemiPublic } from '../../providers/decorators/semi-public.decorator';
import { RefreshTokensResponseDto } from '../auth/dto/refresh-tokens-response.dto';
import { Verify2FARequestDto } from '../auth/dto/verify-2fa-request.dto';
import { AuthService } from '../auth/auth.service';
import { AppService } from './app.service';

@Controller()
export class AppController {
  //*************************
  //#region Local Variables
  //*************************

  private readonly config: AppConfig;

  //#endregion
  //*************************

  //*************************
  //#region Constructors
  //*************************

  constructor(
    private readonly appService: AppService,
    private readonly authService: AuthService,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(AppController.name);
    this.config = getConfig();
  }

  //#endregion
  //*************************

  //*************************
  //#region Public Routes
  //*************************

  /**
   * Public route to return a 'Hello World' message
   *
   * @return {*}  {MessageResponseDto}
   * @memberof AppController
   */
  @Public()
  @Get(AppRoutes.HELLO)
  public sayHello(): MessageResponseDto {
    return this.appService.getHello(false);
  }

  /**
   * Public route to verify user's email address
   *
   * @param {string} ip IP address from where the user clicked link
   * @param {string} token Verification code found in the URL
   * @param {Response} res Response object
   * @return {*} Caller is redirected to a page that displays a message
   * @memberof AppController
   */
  @Public()
  @Get(AuthRoutes.VERIFY_EMAIL)
  public async verify(@Ip() ip: string, @Query('token') token: string, @Res() res: Response) {
    const reply = await this.authService.verifyEmail(ip, token);
    if (reply) {
      return res.redirect(`http://${this.config.service.serviceUrl}/email-verification-success.html`);
    }
    return res.redirect(`http://${this.config.service.serviceUrl}/email-verification-fail.html`);
  }

  //#endregion
  //*************************

  //*************************
  //#region Restricted Routes
  //*************************

  /**
   * Semi-Public Route endpoint to verify 2FA code.
   * This is used by the frontend to verify the 2FA code entered by the user
   * during the forget password or reset password workflow.
   *
   * @param {JwtPayloadDto} user User to verify 2FA code for
   * @param {Verify2FARequestDto} body 2FA code
   * @return {*}  {Promise<RefreshTokensResponseDto>}
   * @memberof AuthController
   */
  @SemiPublic()
  @Post(AuthRoutes.VERIFY_2FA)
  public async verify2FA(@Body() body: Verify2FARequestDto): Promise<RefreshTokensResponseDto | MessageResponseDto> {
    try {
      await this.authService.verify2FA(body);
      return new MessageResponseDto('2FA code verified successfully.', true);
    } catch (error) {
      this.logger.error(`Error trying to verify 2FA for ${body.userName} (${body.email}): ${error.message}`);
    }
    return new MessageResponseDto('2FA code verified successfully.', false);
  }

  /**
   * Restricted route to return a more detailed 'Hello World' message
   *
   * @param {JwtPayloadDto} user User's JWT payload
   * @return {*}  {MessageResponseDto} Response message
   * @memberof AppController
   */
  @Roles(UserRoles.USER)
  @Get(AppRoutes.HEARTBEAT)
  public getHeartbeat(@User() user: JwtPayloadDto): MessageResponseDto {
    return this.appService.getHello(true, user);
  }

  //#endregion
  //*************************
}
