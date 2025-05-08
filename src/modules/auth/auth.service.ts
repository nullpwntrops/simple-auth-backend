import { Injectable, UnauthorizedException, NotFoundException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PinoLogger } from 'nestjs-pino';
import { instanceToPlain } from 'class-transformer';
import { v4 as uuid4 } from 'uuid';
import { Constants, Enums } from '../../common/constants';
import { AppConfig } from '../../common/config/service-config';
import { addInterval, currentTimeStamp, isExpired } from '../../common/utilities/date-time';
import { getConfig } from '../../common/config/service-config';
import { Tokens } from '../../common/types/global-types';
import { find2FAUserResponse } from '../../common/classes/find2FAResponse.class';
import { UserEntity } from '../../database/entities/user.entity';
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
import { HashService } from '../hash/hash.service';
import { MailService } from '../mailer/mailer.service';
import { UserService } from '../user/user.service';

@Injectable()
export class AuthService {
  //**********************************
  //#region Local variables
  //**********************************

  private readonly config: AppConfig;
  private readonly jwtDetails: Map<Enums.TokenType, { secret: string; expiresIn: string }>;

  //#endregion
  //**********************************

  //**********************************
  //#region Constructor
  //**********************************

  constructor(
    private readonly logger: PinoLogger,
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
    private readonly hashService: HashService,
    private readonly mailService: MailService,
  ) {
    this.logger.setContext(AuthService.name);
    this.config = getConfig();
    this.jwtDetails = new Map<Enums.TokenType, { secret: string; expiresIn: string }>([
      [
        Enums.TokenType.ACCESS_TOKEN,
        {
          secret: this.config.jwt.accessSecret,
          expiresIn: this.config.jwt.accessExpiration,
        },
      ],
      [
        Enums.TokenType.REFRESH_TOKEN,
        {
          secret: this.config.jwt.refreshSecret,
          expiresIn: this.config.jwt.refreshExpiration,
        },
      ],
    ]);
  }

  //#endregion
  //**********************************

  //**********************************
  //#region Public Methods
  //**********************************

  /**
   * Function to sign up users.
   *
   * @param {CreateUserRequestDto} userDto - Object that contains user's credentials.
   * @return {*}  {Promise<CreateUserResponseDto>}
   * @memberof AuthService
   */
  public async signUp(userDto: CreateUserRequestDto): Promise<CreateUserResponseDto> {
    try {
      // Step 1: Convert to a UserEntity object
      const userObj = Object.assign(new UserEntity(), userDto);

      // Step 2: Check if user already exists by email and/or username
      const userExists = await this.userService.checkUserAlreadyExists(userObj);
      if (userExists) {
        throw new BadRequestException('A user with this email and/or username already exists!');
      }

      // Step 3: Validate password
      const passwordError = this.validatePassword(userObj.password);
      if (passwordError) {
        throw new BadRequestException(passwordError);
      }

      // Step 4: New user!  Create new record in DB
      const newUser = await this.userService.createUser(userObj);

      // Step 5: Send verification email using the hashed verification token
      await this.mailService.sendVerificationEmail(newUser.email, newUser.verificationToken);

      // Step 6: Convert user object to the proper response object and return it
      return new CreateUserResponseDto(newUser);
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new BadRequestException('Failed to create user: ' + error.message);
    }
  }

  /**
   * Function to login users.
   *
   * @param {LoginRequestDto} loginDTO - Object that contains user's credentials.
   * @param {string} ip - User's IP address.
   * @return {*}  {(Promise<RefreshTokenResponseDto | { validate2FA: string; message: string }>)}
   * @memberof AuthService
   */
  public async login(
    loginDTO: LoginRequestDto,
    ip: string,
  ): Promise<RefreshTokensResponseDto | RefreshTokensPlusResponseDto> {
    try {
      // Step 1: Find and validate user
      const user = await this.findAndValidateUser(loginDTO, ip, false, true);

      // Step 2: Found user, check if user account is locked
      if (user.isLocked && !isExpired(user.isLockedExpiresAt)) {
        // User account is locked and timeout hasn't expired yet - throw an error
        throw new UnauthorizedException('Account is locked.  Try again later.');
      }

      // Step 3: Check if user enabled 2FA
      if (user.enable2FA) {
        const success = await this.send2FAemail(user);
        if (success) {
          const tokens = await this.generateTokens(user, true);
          return new RefreshTokensPlusResponseDto({ message: '2FA email sent successfully', tokens: tokens });
        }
        // TODO: Reply with failure?  Or throw error?
        //return new Login2FAResponseDto('Failed to send 2FA email.  Try again later.');
        throw new BadRequestException('Failed to send 2FA email.  Try again later.');
      }

      // Step 4: Found user, log in user, generate tokens, and return them
      this.updateLastLoginSuccess(user, ip);
      const tokens = await this.generateTokens(user, true);
      return new RefreshTokensResponseDto(tokens);
    } catch (error) {
      if (error instanceof UnauthorizedException || error instanceof BadRequestException) {
        throw error;
      }
      throw new BadRequestException(`Login failed: ${error.message}`);
    }
  }

  /**
   * Function to log out user.
   *
   * @param {JwtPayloadDto} logoutUser User to log out
   * @return {*}  {Promise<MessageResponseDto>}
   * @memberof AuthService
   */
  public async logout(logoutUser: JwtPayloadDto): Promise<MessageResponseDto> {
    try {
      // Step 1: Find user
      const updateUser = this.payload2UserEntity(logoutUser);
      const user = await this.findAndValidateUser(updateUser, logoutUser.ip, true);

      // Step 2: Found user, timestamp last logout and clear out tokens from DB
      user.lastLogout = currentTimeStamp();
      user.lastLogoutIp = logoutUser.ip;
      user.apiKey = null;
      user.accessToken = null;
      user.refreshToken = null;
      await this.userService.updateUser(user);

      // Step 3: Return success message
      return new MessageResponseDto('Logout successful');
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof UnauthorizedException ||
        error instanceof NotFoundException
      ) {
        throw error;
      }
      throw new BadRequestException(`Logout failed: ${error.message}`);
    }
  }

  /**
   * Function to refresh user's tokens.
   *
   * @param {JwtPayloadDto} user User's JWT payload
   * @return {*}  {Promise<RefreshTokensResponseDto>}
   * @memberof AuthService
   */
  public async refreshToken(user: JwtPayloadDto): Promise<RefreshTokensResponseDto> {
    // User already passed validation guard, just generate new tokens
    const userObj = this.payload2UserEntity(user);
    const tokens = await this.generateTokens(userObj, true);
    return new RefreshTokensResponseDto(tokens);
  }

  /**
   * Function to change user's password.
   *
   * @param {JwtPayloadDto} changeUser User's JWT payload
   * @param {ChangePwdRequestDto} body User's new password
   * @return {*}  {Promise<RefreshTokensPlusResponseDto>}
   * @memberof AuthService
   */
  public async changePassword(
    changeUser: JwtPayloadDto,
    body: ChangePwdRequestDto,
  ): Promise<RefreshTokensPlusResponseDto> {
    try {
      // Step 1: Validate the old and new passwords
      const { newPassword, oldPassword } = body;
      const passwordError = this.validatePassword(newPassword, oldPassword);
      if (passwordError) {
        throw new BadRequestException(passwordError);
      }

      // Step 2: Find user and verify old password
      const updateUser = this.payload2UserEntity(changeUser);
      updateUser.password = oldPassword;
      const user = await this.findAndValidateUser(updateUser, changeUser.ip, true, true);

      // Step 3: Save new password
      user.password = newPassword;

      // Step 4: Generate new tokens
      const tokens = await this.generateTokens(user);
      user.apiKey = tokens.apiKey;
      user.accessToken = tokens.accessToken;
      user.refreshToken = tokens.refreshToken;

      // Step 5: Update user's record in DB
      await this.userService.updateUser(user, true, true);

      // Step 4: Everything passed!  Return success message!
      return new RefreshTokensPlusResponseDto({ message: 'Password changed successfully', tokens: tokens });
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof UnauthorizedException ||
        error instanceof NotFoundException
      ) {
        throw error;
      }
      throw new BadRequestException(`Change password failed: ${error.message}`);
    }
  }

  /**
   * Function to verify user's email.
   *
   * @param {string} ip User's IP address
   * @param {string} token User's verification token
   * @return {*}  {Promise<boolean>}
   * @memberof AuthService
   */
  public async verifyEmail(ip: string, token: string): Promise<boolean> {
    try {
      // Step 1: Find user
      const foundUser = await this.userService.findOne({ verificationToken: token });
      if (!foundUser) {
        throw new NotFoundException('User not found!');
      }

      // Step 2: Check if token is expired
      if (isExpired(foundUser.verificationTokenExpiresAt)) {
        throw new BadRequestException('Verification token expired');
      }

      // Step 3: Mark user as verified
      foundUser.isVerified = true;
      foundUser.verifiedAt = currentTimeStamp();
      foundUser.verifiedFromIp = ip;
      foundUser.verificationToken = null;
      foundUser.verificationTokenExpiresAt = null;

      // Step 4: Update user record in DB
      await this.userService.updateUser(foundUser);
      return true;
    } catch (error) {
      this.logger.error(`AuthService.verifyEmail: ${error.message}`);
      return false;
    }
  }

  /**
   * Function to resend verification email.
   *
   * @param {JwtPayloadDto} user User's JWT payload
   * @return {*}  {Promise<RefreshTokensPlusResponseDto>}
   * @memberof AuthService
   */
  public async resendVerification(user: JwtPayloadDto): Promise<RefreshTokensPlusResponseDto> {
    try {
      // Step 1: Load user from DB
      const updateUser = this.payload2UserEntity(user);
      const userEntity = await this.findAndValidateUser(updateUser, user.ip, true);
      if (!userEntity) {
        // Should never happen, but just in case
        throw new NotFoundException('User not found!');
      }

      // Step 2: Generate a new token and save to database
      const verificationToken = uuid4();
      userEntity.verificationToken = await this.hashService.hash(verificationToken);
      userEntity.verificationTokenExpiresAt = addInterval(this.config.jwt.verifyExpiration);
      const tokens = await this.generateTokens(userEntity, true);

      // Step 3: Send verification email
      await this.mailService.sendVerificationEmail(userEntity.email, userEntity.verificationToken);

      return new RefreshTokensPlusResponseDto({ message: 'Verification email sent successfully.', tokens: tokens });
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new BadRequestException(`Resend verification email failed: ${error.message}`);
    }
  }

  /**
   * Function to enable 2FA.
   *
   * @param {JwtPayloadDto} user User's JWT payload
   * @return {*}  {Promise<RefreshTokensPlusResponseDto>}
   * @memberof AuthService
   */
  public async enable2FA(user: JwtPayloadDto): Promise<RefreshTokensPlusResponseDto> {
    try {
      // Step 1: Load user from DB
      const updateUser = this.payload2UserEntity(user);
      const userEntity = await this.findAndValidateUser(updateUser, user.ip, true);
      if (!userEntity) {
        // Should never happen, but just in case
        throw new NotFoundException('User not found!');
      }

      // Step 2: Send email with 2FA code
      const success = await this.send2FAemail(userEntity);
      if (success) {
        const tokens = await this.generateTokens(userEntity, true);
        return new RefreshTokensPlusResponseDto({ message: '2FA email sent successfully', tokens: tokens });
      }
      // TODO: Reply with failure?  Or throw error?
      //return new Login2FAResponseDto('Failed to send 2FA email.  Try again later.');
      throw new BadRequestException('Failed to send 2FA email');
    } catch (error) {
      if (error instanceof NotFoundException || error instanceof BadRequestException) {
        throw error;
      }
      throw new BadRequestException(`Enable 2FA failed: ${error.message}`);
    }
  }

  /**
   * Function to send 2FA email.
   *
   * @param {UserEntity} user User's entity
   * @return {*}  {Promise<boolean>}
   * @memberof AuthService
   */
  public async send2FA(body: Send2FARequestDto): Promise<MessageResponseDto> {
    try {
      // Step 1: Load user from DB
      const updateUser = Object.assign(new UserEntity(), body);
      const userEntity = await this.userService.findOne(updateUser);
      if (!userEntity) {
        throw new NotFoundException('User not found!');
      }

      // Step 2: Send email with 2FA code
      await this.send2FAemail(userEntity);
    } catch (error) {
      this.logger.error(`Error sending 2FA to ${body.userName}:${body.email}: ${error.message}`);
    }
    // Don't return an error.  This way, hackers cannot just guess email/usernames
    return new MessageResponseDto('A password reset code has been sent to the account if it exists.', true);
  }

  /**
   * Function to disable user's 2FA.
   *
   * @param {JwtPayloadDto} user User's JWT payload
   * @return {*}  {Promise<RefreshTokensPlusResponseDto>}
   * @memberof AuthService
   */
  public async disable2FA(user: JwtPayloadDto): Promise<RefreshTokensPlusResponseDto> {
    try {
      // Step 1: Load user from DB
      const updateUser = this.payload2UserEntity(user);
      const userEntity = await this.findAndValidateUser(updateUser, user.ip, true);
      if (!userEntity) {
        // Should never happen, but just in case
        throw new NotFoundException('User not found!');
      }

      // Step 2: Clear 2FA from database
      userEntity.enable2FA = false;
      userEntity.enabled2FAAt = currentTimeStamp();
      userEntity.enabled2FAFromIp = user.ip;
      userEntity.twoFASecret = null;
      userEntity.twoFASecretExpiresAt = null;
      await this.userService.updateUser(userEntity);

      // Step 3: Return success message
      const tokens = await this.generateTokens(userEntity, true);
      return new RefreshTokensPlusResponseDto({ message: '2FA disabled successfully', tokens: tokens });
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new BadRequestException(`Disable 2FA failed: ${error.message}`);
    }
  }

  /**
   * Function to verify user's 2FA
   *
   * @param {JwtPayloadDto} user User's JWT payload
   * @param {Verify2FARequestDto} body 2FA code to verify
   * @return {*}  {Promise<RefreshTokensResponseDto>}
   * @memberof AuthService
   */
  public async verify2FA(
    body: Verify2FARequestDto,
    user?: JwtPayloadDto,
  ): Promise<RefreshTokensResponseDto | MessageResponseDto> {
    try {
      // Step 1: Find user
      const findReply = await this.find2FAUser(body, user);
      const userEntity = findReply.user;
      const routeType = findReply.routeType;

      // Step 2: Check if code is expired
      const isCodeExpired = isExpired(userEntity.twoFASecretExpiresAt);
      if (isCodeExpired) {
        throw new BadRequestException('2FA code has expired');
      }

      // Step 3: Check if code is valid
      const isValid = await this.hashService.compare(body.code, userEntity.twoFASecret);
      if (!isValid) {
        throw new BadRequestException('Invalid 2FA code');
      }

      // Step 4: Check route type
      if (routeType === Enums.TwoFARouteType.PASSWORD) {
        // User is trying to reset password.

        // Clear 2FA token and save to DB
        userEntity.twoFASecret = null;
        userEntity.twoFASecretExpiresAt = null;
        await this.userService.updateUser(userEntity);
        // No need to return access/refresh tokens.  Just return a message.
        return new MessageResponseDto('2FA code verified successfully', true);
      }

      // Step 5: All checks passed, check if this call was to enable 2FA or validate 2FA
      if (!userEntity.enable2FA) {
        userEntity.enable2FA = true;
        userEntity.enabled2FAAt = currentTimeStamp();
        userEntity.enabled2FAFromIp = user.ip;
      }

      // Step 6: Clear 2FA token from database
      userEntity.twoFASecret = null;
      userEntity.twoFASecretExpiresAt = null;

      // Step 7: Mark user as logged in
      this.updateLastLoginSuccess(userEntity, user.ip);

      // Step 8: Generate tokens and return to caller
      const tokens = await this.generateTokens(userEntity, true);
      return new RefreshTokensResponseDto(tokens);
    } catch (error) {
      // In case of an error, client can resubmit code if not expired.  Otherwise,
      // just login again to get new code.
      if (error instanceof NotFoundException || error instanceof BadRequestException) {
        throw error;
      }
      throw new BadRequestException(`Verify 2FA failed: ${error.message}`);
    }
  }

  //#endregion
  //**********************************

  //**********************************
  //#region Private Methods
  //**********************************

  /**
   * Function to find and validate a user.
   *
   * @private
   * @param {Partial<UserEntity>} checkUser - User object to check
   * @param {string} ip - User's IP address
   * @param {boolean} [checkApiKey=false] - Flag to check API key
   * @param {boolean} [checkPassword=false] - Flag to check password
   * @return {*}  {Promise<UserEntity>} - User object if found and validated
   * @throws {NotFoundException} - If user is not found
   * @throws {UnauthorizedException} - If API key or password is invalid
   * @memberof AuthService
   */
  private async findAndValidateUser(
    checkUser: Partial<UserEntity>,
    ip: string,
    checkApiKey: boolean = false,
    checkPassword: boolean = false,
  ): Promise<UserEntity> {
    // Fetch user info from database
    const user = await this.userService.findOne(checkUser);
    if (!user) {
      throw new NotFoundException('User not found!');
    }

    // Check user's API key
    if (checkApiKey && checkUser.apiKey !== user.apiKey) {
      const reason = 'Invalid API key';
      await this.updateLastLoginFailedDetails(user, ip, reason);
      throw new UnauthorizedException(reason);
    }

    // Check user's password
    if (checkPassword) {
      const passwordMatched = await this.hashService.compare(checkUser.password, user.password);
      if (!passwordMatched) {
        const reason = 'Invalid password';
        await this.updateLastLoginFailedDetails(user, ip, reason);
        throw new UnauthorizedException(reason);
      }
    }

    // All checks passed, delete password and return user object
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...retUser } = user;
    return <UserEntity>retUser;
  }

  /**
   * Function to update the last login failed attempt for a user.
   *
   * @private
   * @param {UserEntity} user - User object to update
   * @param {string} ip - User's IP address
   * @param {string} reason - Reason for the last login attempt failure
   * @memberof AuthService
   */
  private async updateLastLoginFailedDetails(user: UserEntity, ip: string, reason: string) {
    user.failedLoginAttempts += 1;
    user.failedLoginAttemptsAt = currentTimeStamp();
    user.failedLoginAttemptsFromIp = ip;
    user.failedLoginAttemptsReason = reason;
    if (user.failedLoginAttempts >= this.config.misc.maxFailAttempts) {
      user.isLocked = true;
      user.isLockedExpiresAt = addInterval(this.config.misc.lockoutExpiration);
      user.isLockedReason = 'Too many failed login attempts';
    }
    await this.userService.updateUser(user);
  }

  /**
   * Function to update the last login success for a user.
   *
   * @private
   * @param {UserEntity} user - User object to update
   * @param {string} ip - User's IP address
   * @memberof AuthService
   */
  private updateLastLoginSuccess(user: UserEntity, ip: string) {
    user.lastLogin = currentTimeStamp();
    user.lastLoginIp = ip;
    user.failedLoginAttempts = 0;
    user.isLocked = false;
    user.isLockedExpiresAt = null;
    user.isLockedReason = null;
  }

  /**
   * Function to generate a JWT token.
   *
   * @private
   * @param {UserEntity} user - User object to generate token for
   * @param {Enums.TokenType} tokenType - Type of token to generate
   * @return {*}  {Promise<string>} - JWT token
   * @memberof AuthService
   */
  private async generateJwtToken(user: UserEntity, tokenType: Enums.TokenType): Promise<string> {
    const payload = instanceToPlain(new JwtPayloadDto(user)) as Record<string, unknown>;
    return await this.jwtService.signAsync(payload, this.jwtDetails.get(tokenType));
  }

  /**
   * Function to generate new API key and tokens.
   *
   * @private
   * @param {UserEntity} user - User object to generate tokens for
   * @param {boolean} [saveUser=true] - Flag to save user info to DB
   * @return {*}  {Promise<Tokens>} - API key and tokens
   * @memberof AuthService
   */
  private async generateTokens(user: UserEntity, saveUser: boolean = false): Promise<Tokens> {
    // Generate new API key and tokens
    user.apiKey = uuid4();
    const accessToken = await this.generateJwtToken(user, Enums.TokenType.ACCESS_TOKEN);
    const refreshToken = await this.generateJwtToken(user, Enums.TokenType.REFRESH_TOKEN);

    // Update user information
    if (saveUser) {
      const updateUser = <UserEntity>Object.assign({}, user);
      updateUser.accessToken = accessToken;
      updateUser.refreshToken = refreshToken;

      // Save user info to DB
      await this.userService.updateUser(updateUser, false, true);
    }

    // Return Access and Refresh tokens
    return {
      apiKey: user.apiKey,
      accessToken: accessToken,
      refreshToken: refreshToken,
    };
  }

  /**
   * Function to validate a password
   *
   * @private
   * @param {string} newPassword - New password to validate
   * @param {string} [oldPassword] - Old password to compare with
   * @return {*}  {string} - Error message if validation fails, null otherwise
   * @memberof AuthService
   */
  private validatePassword(newPassword: string, oldPassword?: string): string {
    // Step 1: If old password passed in, make sure it's different than new
    if (oldPassword && newPassword === oldPassword) {
      return 'New password cannot be the same as the old password';
    }

    // Step 2: Check new password for min length
    if (newPassword.length < Constants.PWD_MIN_LENGTH) {
      return `New password must be at least ${Constants.PWD_MIN_LENGTH} characters long`;
    }

    // Step 3: Check new password for max length
    if (newPassword.length > Constants.PWD_MAX_LENGTH) {
      return `New password must be less than ${Constants.PWD_MAX_LENGTH} characters long`;
    }

    // Step 4: Validate password using REGEX
    if (!Constants.PWD_REGEX.test(newPassword)) {
      return Constants.PWD_REGEX_ERROR_MESSAGE;
    }

    return null;
  }

  /**
   * Function to send 2FA email to user.
   * Function also generates the 2FA code.  The 2FA code
   * is hashed and saved to the database.
   *
   * @private
   * @param {UserEntity} user - User object to send email to
   * @return {*}  {Promise<boolean>} - True if email sent successfully, false otherwise
   * @memberof AuthService
   */
  private async send2FAemail(user: UserEntity): Promise<boolean> {
    try {
      // Step 1: Generate code
      const code = this.generate2FACode();

      // Step 2: Send email with code
      await this.mailService.send2FAEmail(user.email, code);

      // Step 3: Hash code and save to DB
      user.twoFASecret = await this.hashService.hash(code);
      user.twoFASecretExpiresAt = addInterval(this.config.misc.twoFaExpiration);
      await this.userService.updateUser(user);

      // Step 4: Return true
      return true;
    } catch (error) {
      // TODO: On failure, should we clear out the 2FA secret?
      throw new BadRequestException(`Send 2FA email failed: ${error.message}`);
    }
  }

  /**
   * Function to generate a 2FA code.
   *
   * @private
   * @return {*}  {string}
   * @memberof AuthService
   */
  private generate2FACode(): string {
    const multiplier = Math.pow(10, this.config.misc.twoFaLength - 1);
    return Math.floor(multiplier + Math.random() * 9 * multiplier).toString();
  }

  /**
   * Function to convert a JWT payload to a UserEntity object.
   *
   * @private
   * @param {JwtPayloadDto} payload - JWT payload to convert
   * @return {*}  {UserEntity} - UserEntity object
   * @memberof AuthService
   */
  private payload2UserEntity(payload: JwtPayloadDto): UserEntity {
    return <UserEntity>{
      id: payload.sub,
      email: payload.email,
      userName: payload.userName,
      apiKey: payload.apiKey,
      role: payload.role,
      isVerified: payload.isVerified,
      enable2FA: payload.enable2FA,
    };
  }

  private async find2FAUser(body: Verify2FARequestDto, user?: JwtPayloadDto): Promise<find2FAUserResponse> {
    if (user) {
      // User object passed in ... must be during Login or Enable/Disable 2FA
      const updateUser = this.payload2UserEntity(user);
      const userEntity = await this.findAndValidateUser(updateUser, user.ip, true);
      if (!userEntity) {
        // Should never happen, but just in case
        throw new NotFoundException('User not found!');
      }
      return new find2FAUserResponse(userEntity, Enums.TwoFARouteType.LOGIN);
    }
    // No user object passed in ... must be during forget password or reset password
    const userEntity = await this.userService.findOne(body);
    if (!userEntity) {
      throw new NotFoundException('User not found!');
    }
    return new find2FAUserResponse(userEntity, Enums.TwoFARouteType.PASSWORD);
  }

  //#endregion
  //**********************************
}
