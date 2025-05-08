import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import * as bcrypt from 'bcrypt';
import { PinoLogger } from 'nestjs-pino';
import { Enums } from '../../common/constants';
import { getConfig } from '../../common/config/service-config';
import { IS_PUBLIC_ROUTE } from '../decorators/public.decorator';
import { IS_SEMI_PUBLIC_ROUTE } from '../decorators/semi-public.decorator';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { JwtPayloadDto } from '../../database/dto/jwt-payload.dto';
import { UserEntity } from '../../database/entities/user.entity';
import { IS_2FA_ROUTE } from '../../providers/decorators/2fa.decorator';
import { UserService } from '../../modules/user/user.service';

/**
 * AuthGuard - Protects all routes.
 *  - If a route is marked as public, no authentication will be performed.
 *  - If a route is marked as semi-public, requests will be checked for a valid API key.
 *  - Otherwise, full authentication will be performed.
 *  - The following steps are performed for full authentication:
 *      1) Check if request header contains auth token
 *      2) Validate auth token
 *      3) Check if route has an assigned role.  If so, check that user has the required role
 *      4) Find user in database
 *      5) Check if user has 2FA enabled.  If so, check if 2FA code was sent/verified
 *      6) Check if user is still logged in
 *      7) Validate user's token
 *      8) Validate user's API key
 *  - If all checks pass, attach the user payload to the request object
 */
@Injectable()
export class AuthGuard implements CanActivate {
  //******************************
  //#region Local variables
  //******************************

  private readonly apiKey: string;
  private readonly jwtMapping: Map<Enums.TokenType, string>;

  //#endregion
  //******************************

  //******************************
  //#region Constructors
  //******************************

  constructor(
    private readonly jwtService: JwtService,
    private readonly reflector: Reflector,
    private readonly userService: UserService,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(AuthGuard.name);
    const config = getConfig();
    this.apiKey = config.service.api_key;
    this.jwtMapping = new Map<Enums.TokenType, string>([
      [Enums.TokenType.ACCESS_TOKEN, config.jwt.accessSecret],
      [Enums.TokenType.REFRESH_TOKEN, config.jwt.refreshSecret],
    ]);
  }

  //#endregion
  //******************************

  //******************************
  //#region Public Methods
  //******************************

  /**
   * CanActivate - Check if route is protected or not.  If it is
   * protected, check if request is authorized and if necessary
   * check if authenticated.
   *
   * @param {ExecutionContext} context Execution context
   * @return {*}  {Promise<boolean>} Returns true if the request is authenticated
   * @throws {UnauthorizedException} If the request is not authenticated
   * @memberof AuthGuard
   */
  public async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check if route is marked public
    if (this.isMarked(context, IS_PUBLIC_ROUTE)) {
      return true;
    }

    // Route is not public.  Perform authorization checks
    // and if needed, authentication checks.
    try {
      const { isValid, request } = this.isValidApiKey(context);
      if (isValid) {
        if (this.isMarked(context, IS_SEMI_PUBLIC_ROUTE)) {
          return true;
        }
        return await this.performFullAuthentication(context, request);
      }
      throw new UnauthorizedException('Invalid API key.');
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException(`Invalid token: ${error.message}`);
    }
  }

  //#endregion
  //******************************

  //******************************
  //#region Private Methods
  //******************************

  /**
   * Generic function to retrieve metadata key
   *
   * @private
   * @param {ExecutionContext} context Execution context
   * @param {string} key Key to check
   * @return {*}  {boolean} Returns true if key is found
   * @memberof AuthGuard
   */
  private isMarked(context: ExecutionContext, key: string): boolean {
    return this.reflector.getAllAndOverride<boolean>(key, [context.getHandler(), context.getClass()]);
  }

  /**
   * Check if application API key is valid
   *
   * @private
   * @param {ExecutionContext} context Execution context
   * @return {*}  {boolean, request} Returns true if API key is valid as well as the request object
   * @throws {UnauthorizedException} If the API key is invalid or missing
   * @memberof AuthGuard
   */
  private isValidApiKey(context: ExecutionContext): {
    isValid: boolean;
    request: Request;
  } {
    try {
      const request = <Request>context.switchToHttp().getRequest();
      const apiKey = <string>request.headers['x-api-key'];
      if (!apiKey) {
        throw new UnauthorizedException('Missing API key');
      } else if (apiKey !== this.apiKey) {
        throw new UnauthorizedException('Invalid API key');
      }
      return { isValid: true, request: request };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException(`Invalid API key: ${error.message}`);
    }
  }

  /**
   * Step 1: Extract the token from the request header.
   *
   * @private
   * @param {Request} request Request object
   * @return {*}  {(string | undefined)} Returns the token if found, otherwise undefined
   * @memberof AuthGuard
   */
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

  /**
   * Step 2: Validate the token and extract the payload.
   *
   * @private
   * @param {string} token Token to validate
   * @return {*}  {(Promise<{
   *     payload: JwtPayloadDto | null;
   *     tokenType: Enums.TokenType;
   *   }>)} Returns the payload and token type if valid
   * @throws {UnauthorizedException} If the token is invalid
   * @memberof AuthGuard
   */
  private async validateTokenAndExtractPayload(token: string): Promise<{
    payload: Partial<JwtPayloadDto> | null;
    tokenType: Enums.TokenType;
  }> {
    for (const [tokenType, secret] of this.jwtMapping.entries()) {
      try {
        const payload = await this.jwtService.verifyAsync(token, { secret });
        if (payload) {
          return { payload, tokenType };
        }
      } catch {
        // Ignore errors and continue to the next token type
        continue;
      }
    }
    throw new UnauthorizedException('Invalid token');
  }

  /**
   * Step 3: Check if route is protected by roles.
   * If so, check if user has the required role.
   *
   * @private
   * @param {ExecutionContext} context Execution context
   * @param {Enums.UserRoles} userRole User's role to check
   * @return {*}  {boolean} Returns true if user has the required role
   * @memberof AuthGuard
   */
  private checkRoles(context: ExecutionContext, userRole: Enums.UserRoles): boolean {
    const roles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [context.getHandler(), context.getClass()]);
    if (roles && roles.length > 0) {
      return userRole && roles.includes(userRole);
    }
    return true;
  }

  private check2FA(context: ExecutionContext, user: UserEntity): boolean {
    // enable2FA | twoFASecret |
    //  false    |  null       | User did not enable 2FA --> let valid token through
    //  false    |  token      | User in the process of enabling 2FA --> only 2FA routes allowed
    //  true     |  token      | User enabled 2FA, in the process of logging in --> only 2FA routes allowed
    //  true     |  null       | User enabled 2FA and passed --> all routes allowed
    if (user.twoFASecret) {
      const is2FA = this.isMarked(context, IS_2FA_ROUTE);
      if (is2FA) {
        // User is in the process of enabling 2FA or in the process of logging in
        return true;
      }
      throw new UnauthorizedException('Invalid use of token');
    }
    return false;
  }

  /**
   * Perform full authentication for protected routes.
   *
   * @private
   * @param {ExecutionContext} context Execution context
   * @param {Request} request Request object
   * @return {*}  {Promise<boolean>} Returns true if authentication is successful
   * @memberof AuthGuard
   */
  private async performFullAuthentication(context: ExecutionContext, request: Request): Promise<boolean> {
    try {
      // Step 1: Extract bearer token from request header
      const token = this.extractTokenFromHeader(request);
      if (!token) {
        throw new UnauthorizedException('Missing token');
      }

      // Step 2: Validate token and extract payload
      const { payload, tokenType } = await this.validateTokenAndExtractPayload(token);

      // Step 3: Check if route has an assigned role
      if (!this.checkRoles(context, payload.role)) {
        throw new UnauthorizedException('User does not have permission to access this route');
      }

      // Step 4: Find user
      const user = await this.userService.findOne({
        id: payload.sub,
        email: payload.email,
        userName: payload.userName,
      });
      if (!user) {
        throw new UnauthorizedException('Invalid user');
      }

      // Step 5: Check if user has 2FA enabled.  If so, check if passed
      const skipChecks = this.check2FA(context, user);
      // If 2FA in progress, skip the other checks
      if (!skipChecks) {
        // Step 6: Check if user is still logged in
        if (!user.refreshToken) {
          throw new UnauthorizedException('User logged out');
        }

        // Step 7: Compare Token against user's saved copy
        // Make sure it's the latest token and not an old one
        const tokenToMatch = tokenType === Enums.TokenType.ACCESS_TOKEN ? user.accessToken : user.refreshToken;
        const validToken = await bcrypt.compare(token, tokenToMatch);
        if (!validToken) {
          throw new UnauthorizedException('Invalid token');
        }

        // Step 8: Compare user's API key
        if (payload.apiKey !== user.apiKey) {
          throw new UnauthorizedException('Invalid API key');
        }
      }

      // ***************************
      // *  All checks passed!!!!  *
      // ***************************
      // Replace a few things in the payload from the user object in case things changed since
      // token was created as well as the IP address
      payload.isVerified = user.isVerified;
      payload.role = user.role;
      payload.ip = request.ip;
      payload.reqId = <string>request['id'];

      // Attach the payload to the request object
      request['user'] = payload;
      return true;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException(`Invalid token: ${error.message}`);
    }
  }

  //#endregion
  //******************************
}
