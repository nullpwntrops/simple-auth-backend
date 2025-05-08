import { Controller, Post, Body, HttpCode, HttpStatus, BadRequestException, Ip } from '@nestjs/common';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';
import { PinoLogger } from 'nestjs-pino';
import { AuthRoutes } from '../../common/constants/routes';
import { SemiPublic } from '../../providers/decorators/semi-public.decorator';
import { User } from '../../providers/decorators/user.decorator';
import { Is2FA } from '../../providers/decorators/2fa.decorator';
import { JwtPayloadDto } from '../../database/dto/jwt-payload.dto';
import { MessageResponseDto } from '../../database/dto/message-response.dto';
import { CreateUserRequestDto } from './dto/create-user-request.dto';
import { CreateUserResponseDto } from './dto/create-user-response.dto';
import { LoginRequestDto } from './dto/login-request.dto';
import { RefreshTokensResponseDto } from './dto/refresh-tokens-response.dto';
import { ChangePwdRequestDto } from './dto/change-pwd-request.dto';
import { RefreshTokensPlusResponseDto } from './dto/refresh-tokens-plus-response.dto';
import { Verify2FARequestDto } from './dto/verify-2fa-request.dto';
import { Send2FARequestDto } from './dto/send-2fa-request.dto';
import { AuthService } from './auth.service';

@Controller(AuthRoutes.ROOT)
export class AuthController {
  //***********************************
  //#region Constructors
  //***********************************

  constructor(
    private readonly authService: AuthService,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(AuthController.name);
  }

  //#endregion
  //***********************************

  //***********************************
  //#region Semi-Public Routes
  //***********************************

  /**
   * Route endpoint to register new user.
   *
   * @param {CreateUserRequestDto} createUserDto The user data to register.
   * @return {*}  {Promise<CreateUserResponseDto>}
   * @memberof AuthController
   */
  @SemiPublic()
  @ApiOperation({ summary: 'Register new user' })
  @ApiResponse({
    status: 201,
    description: 'It will return a new user object.',
  })
  @Post(AuthRoutes.SIGNUP)
  public async signUp(@Body() createUserDto: CreateUserRequestDto): Promise<CreateUserResponseDto> {
    // New signups require both email and username
    return await this.authService.signUp(createUserDto);
  }

  /**
   * Route endpoint to login user.
   *
   * @param {string} ip  The user's IP address.
   * @param {LoginRequestDto} loginDto  The user's login data.
   * @return {*}  {(Promise<RefreshTokensResponseDto | RefreshTokensPlusResponseDto>)}
   * @memberof AuthController
   */
  @SemiPublic()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login user' })
  @ApiResponse({
    status: 200,
    description: 'It will return a new access and refresh tokens.',
  })
  @Post(AuthRoutes.LOGIN)
  public async login(
    @Ip() ip: string,
    @Body() loginDto: LoginRequestDto,
  ): Promise<RefreshTokensResponseDto | RefreshTokensPlusResponseDto> {
    if (!loginDto.email && !loginDto.userName) {
      throw new BadRequestException('Username or email must be specified.');
    }
    return await this.authService.login(loginDto, ip);
  }

  /**
   * Route endpoint to send 2FA code to user.  Used when user
   * wants to reset password or forgets password.
   *
   * @param {Send2FARequestDto} user The user to send 2FA code to.
   * @return {*}  {Promise<MessageResponseDto>}
   * @memberof AuthController
   */
  @SemiPublic()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Send 2FA code to user' })
  @ApiResponse({
    status: 200,
    description: 'It will return a success or fail message.',
  })
  @Post(AuthRoutes.SEND_2FA)
  public async send2FA(@Body() user: Send2FARequestDto): Promise<MessageResponseDto> {
    if (!user.email && !user.userName) {
      throw new BadRequestException('Username or email must be specified.');
    }
    return await this.authService.send2FA(user);
  }

  //#endregion
  //***********************************

  //***********************************
  //#region Protected Routes
  //***********************************

  /**
   * Route endpoint to logout user.
   *
   * @param {JwtPayloadDto} user User to log out
   * @return {*}  {Promise<MessageResponseDto>}
   * @memberof AuthController
   */
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Logout user' })
  @ApiResponse({
    status: 200,
    description: 'It will return a message.',
  })
  @Post(AuthRoutes.LOGOUT)
  public async logout(@User() user: JwtPayloadDto): Promise<MessageResponseDto> {
    return await this.authService.logout(user);
  }

  /**
   * Route endpoint to refresh user's access and refresh tokens.
   *
   * @param {JwtPayloadDto} user User to get refresh tokens for
   * @return {*}  {Promise<RefreshTokenResponseDto>}
   * @memberof AuthController
   */
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh token' })
  @ApiResponse({
    status: 200,
    description: 'It will return a new access token.',
  })
  @Post(AuthRoutes.REFRESH_TOKEN)
  public async refreshToken(@User() user: JwtPayloadDto): Promise<RefreshTokensResponseDto> {
    return await this.authService.refreshToken(user);
  }

  /**
   * Route endpoint to change user's password.
   *
   * @param {JwtPayloadDto} user User to change password for
   * @param {ChangePwdRequestDto} body Old and new passwords
   * @return {*}  {Promise<MessageResponseDto>}
   * @memberof AuthController
   */
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Change password' })
  @ApiResponse({
    status: 200,
    description: 'Change user password.',
  })
  @Post(AuthRoutes.CHANGE_PASSWORD)
  public async changePassword(
    @User() user: JwtPayloadDto,
    @Body() body: ChangePwdRequestDto,
  ): Promise<RefreshTokensPlusResponseDto> {
    return await this.authService.changePassword(user, body);
  }

  /**
   * Route endpoint to resend verification email.
   *
   * @param {JwtPayloadDto} user User to resend verification email for
   * @return {*}  {Promise<MessageResponseDto>}
   * @memberof AuthController
   */
  @Post(AuthRoutes.RESEND_VERIFICATION_EMAIL)
  public async resendVerificationEmail(@User() user: JwtPayloadDto): Promise<RefreshTokensPlusResponseDto> {
    return await this.authService.resendVerification(user);
  }

  /**
   * Route endpoint to enable 2FA.
   *
   * @param {JwtPayloadDto} user User to enable 2FA for
   * @return {*}  {Promise<MessageResponseDto>}
   * @memberof AuthController
   */
  @Post(AuthRoutes.ENABLE_2FA)
  public async enable2FA(@User() user: JwtPayloadDto): Promise<MessageResponseDto> {
    return await this.authService.enable2FA(user);
  }

  /**
   * Route endpoint to disable 2FA
   *
   * @param {JwtPayloadDto} user User to disable 2FA for
   * @return {*}  {Promise<RefreshTokensPlusResponseDto>}
   * @memberof AuthController
   */
  @Post(AuthRoutes.DISABLE_2FA)
  public async disable2FA(@User() user: JwtPayloadDto): Promise<RefreshTokensPlusResponseDto> {
    return await this.authService.disable2FA(user);
  }

  /**
   * Route endpoint to verify 2FA code.  This endpoint is used during login
   * or enable/disable 2FA when the user's credentials are known.
   *
   * @param {JwtPayloadDto} user User to verify 2FA code for
   * @param {Verify2FARequestDto} body 2FA code
   * @return {*}  {Promise<RefreshTokensResponseDto>}
   * @memberof AuthController
   */
  @Is2FA()
  @Post(AuthRoutes.VERIFY_2FA)
  public async verify2FA(
    @User() user: JwtPayloadDto,
    @Body() body: Verify2FARequestDto,
  ): Promise<RefreshTokensResponseDto | MessageResponseDto> {
    return await this.authService.verify2FA(body, user);
  }

  //#endregion
  //***********************************
}
