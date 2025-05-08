import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { PinoLogger } from 'nestjs-pino';
import { v4 as uuid4 } from 'uuid';
import { BadRequestException, NotFoundException, UnauthorizedException } from '@nestjs/common';

// Mock external dependencies
jest.mock('nestjs-pino');
jest.mock('@nestjs/jwt');
jest.mock('uuid', () => ({ v4: jest.fn() }));

// Mock local utilities and config
jest.mock('../../common/config/service-config', () => ({
  getConfig: jest.fn(),
}));
jest.mock('../../common/utilities/date-time', () => ({
  currentTimeStamp: jest.fn(),
  addInterval: jest.fn(),
  isExpired: jest.fn(),
}));

import { AuthService } from './auth.service';
import { UserService } from '../user/user.service';
import { HashService } from '../hash/hash.service';
import { MailService } from '../mailer/mailer.service';
import { AppConfig, getConfig } from '../../common/config/service-config';
import { currentTimeStamp, addInterval, isExpired } from '../../common/utilities/date-time';
import { UserEntity } from '../../database/entities/user.entity';
import { CreateUserRequestDto } from './dto/create-user-request.dto';
import { LoginRequestDto } from './dto/login-request.dto';
import { ChangePwdRequestDto } from './dto/change-pwd-request.dto';
import { Send2FARequestDto } from './dto/send-2fa-request.dto';
import { Verify2FARequestDto } from './dto/verify-2fa-request.dto';
import { JwtPayloadDto } from '../../database/dto/jwt-payload.dto';
import { CreateUserResponseDto } from './dto/create-user-response.dto';
import { RefreshTokensResponseDto } from './dto/refresh-tokens-response.dto';
import { RefreshTokensPlusResponseDto } from './dto/refresh-tokens-plus-response.dto';
import { MessageResponseDto } from '../../database/dto/message-response.dto';
import { Constants, Enums } from '../../common/constants';
import { Tokens } from '../../common/types/global-types';
import exp from 'constants';

// Define mock implementations for services
const mockUserService = {
  checkUserAlreadyExists: jest.fn(),
  createUser: jest.fn(),
  findOne: jest.fn(),
  updateUser: jest.fn(),
};

const mockHashService = {
  hash: jest.fn(),
  compare: jest.fn(),
};

const mockMailService = {
  sendVerificationEmail: jest.fn(),
  send2FAEmail: jest.fn(),
};

const mockJwtService = {
  signAsync: jest.fn(),
};

const mockPinoLogger = {
  setContext: jest.fn(),
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
  trace: jest.fn(),
};

const mockConfig: AppConfig = {
  service: {
    serviceName: 'TestService',
    serviceUrl: 'test.com',
    identifier: 'test-id',
    api_key: 'test-api-key',
    nodeEnv: Enums.NodeEnv.TEST,
    port: 3000,
    dockerPort: 3001,
    app_name: 'Test App',
    isDevelopment: false,
    isTest: true,
    isProduction: false,
  },
  jwt: {
    accessSecret: 'access-secret',
    accessExpiration: '15m',
    refreshSecret: 'refresh-secret',
    refreshExpiration: '7d',
    resetExpiration: '1h',
    verifyExpiration: '1d',
  },
  database: {
    host: 'localhost',
    port: 5432,
    username: 'user',
    password: 'password',
    database: 'testdb',
    sync: false,
    logging: false,
    sslmode: false,
  },
  misc: {
    twoFaLength: 6,
    twoFaExpiration: '5m',
    maxFailAttempts: 5,
    lockoutExpiration: '1h',
    healthMemory: 250,
    healthDiskThreshold: 0.75,
    pinoLogLevel: Enums.PinoLogLevels.INFO,
  },
  mail: {
    from: 'noreply@example.com',
    transportOptions: {
      host: 'smtp.example.com',
      port: 587,
      auth: {
        user: 'user@example.com',
        pass: 'password',
      },
    },
  },
  throttler: {
    ttl: 60,
    limit: 10,
  },
  swagger: {
    enabled: false,
  },
};

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    jest.clearAllMocks(); // Clear mocks before each test, but after service instantiation if getConfig is called in constructor
    // Mock getConfig to return our mockConfig
    (getConfig as jest.Mock).mockReturnValue(mockConfig);
    // Mock date-time utilities
    (currentTimeStamp as jest.Mock).mockReturnValue(new Date('2023-01-01T00:00:00.000Z'));
    (addInterval as jest.Mock).mockImplementation((intervalString) => {
      // Simplified mock, real implementation would parse intervalString
      if (intervalString === mockConfig.jwt.verifyExpiration) return new Date('2023-01-02T00:00:00.000Z');
      if (intervalString === mockConfig.misc.twoFaExpiration) return new Date('2023-01-01T00:05:00.000Z');
      return new Date('2023-01-01T01:00:00.000Z');
    });
    (isExpired as jest.Mock).mockReturnValue(false);
    // Mock uuid
    (uuid4 as jest.Mock).mockReturnValue('mock-uuid-string');

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PinoLogger, useValue: mockPinoLogger },
        { provide: JwtService, useValue: mockJwtService },
        { provide: UserService, useValue: mockUserService },
        { provide: HashService, useValue: mockHashService },
        { provide: MailService, useValue: mockMailService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    // Re-apply mocks that might be cleared if they are module-level mocks affected by jest.clearAllMocks()
    (getConfig as jest.Mock).mockReturnValue(mockConfig);
    (uuid4 as jest.Mock).mockReturnValue('mock-uuid-string');
    (currentTimeStamp as jest.Mock).mockReturnValue(new Date('2023-01-01T00:00:00.000Z'));
    (addInterval as jest.Mock).mockImplementation((intervalString) => {
      if (intervalString === mockConfig.jwt.verifyExpiration) return new Date('2023-01-02T00:00:00.000Z');
      if (intervalString === mockConfig.misc.twoFaExpiration) return new Date('2023-01-01T00:05:00.000Z');
      return new Date('2023-01-01T01:00:00.000Z');
    });
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
    expect(mockPinoLogger.setContext).toHaveBeenCalledWith(AuthService.name);
    expect(getConfig).toHaveBeenCalledTimes(1); // Called in constructor
  });

  // --- signUp ---
  describe('signUp', () => {
    const createUserDto: CreateUserRequestDto = {
      email: 'test@example.com',
      userName: 'testuser',
      password: 'Password@123',
    };
    const mockUserEntity = {
      ...createUserDto,
      id: 'mock-user-id',
      verificationToken: 'hashed-verify-token',
      verificationTokenExpiresAt: new Date('2023-01-02T00:00:00.000Z'),
      role: Enums.UserRoles.USER,
      isVerified: false,
      enable2FA: false,
      createdAt: new Date('2023-01-01T00:00:00.000Z'),
      updatedAt: new Date('2023-01-01T00:00:00.000Z'),
    } as UserEntity;

    it('should successfully sign up a new user', async () => {
      mockUserService.checkUserAlreadyExists.mockResolvedValue(false);
      mockUserService.createUser.mockResolvedValue(mockUserEntity);
      mockMailService.sendVerificationEmail.mockResolvedValue(undefined);

      const result = await service.signUp(createUserDto);

      expect(mockUserService.checkUserAlreadyExists).toHaveBeenCalledWith(
        expect.objectContaining({ email: createUserDto.email, userName: createUserDto.userName }),
      );
      expect(mockUserService.createUser).toHaveBeenCalledWith(
        expect.objectContaining({ email: createUserDto.email, password: createUserDto.password }),
      );
      expect(mockMailService.sendVerificationEmail).toHaveBeenCalledWith(
        mockUserEntity.email,
        mockUserEntity.verificationToken,
      );
      expect(result).toBeInstanceOf(CreateUserResponseDto);
      expect(result.email).toBe(createUserDto.email);
    });

    it('should throw BadRequestException if user already exists', async () => {
      mockUserService.checkUserAlreadyExists.mockResolvedValue(true);
      await expect(service.signUp(createUserDto)).rejects.toThrow(
        new BadRequestException('A user with this email and/or username already exists!'),
      );
    });

    it('should throw BadRequestException for invalid password', async () => {
      mockUserService.checkUserAlreadyExists.mockResolvedValue(false);
      const invalidPasswordDto = { ...createUserDto, password: 'short' };
      await expect(service.signUp(invalidPasswordDto)).rejects.toThrow(
        new BadRequestException(`New password must be at least ${Constants.PWD_MIN_LENGTH} characters long`),
      );
    });

    it('should throw BadRequestException if createUser fails', async () => {
      mockUserService.checkUserAlreadyExists.mockResolvedValue(false);
      mockUserService.createUser.mockRejectedValue(new Error('DB error'));
      await expect(service.signUp(createUserDto)).rejects.toThrow(
        new BadRequestException('Failed to create user: DB error'),
      );
    });
  });

  // --- login ---
  describe('login', () => {
    const loginDto: LoginRequestDto = { email: 'test@example.com', password: 'Password@123' };
    const ip = '127.0.0.1';
    const mockUser = {
      id: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      password: 'hashedPassword', // Assume this is the hashed version of 'Password@123'
      enable2FA: false,
      apiKey: 'old-api-key',
      failedLoginAttempts: 0,
    } as UserEntity;
    const mockTokens: Tokens = {
      accessToken: 'new-access-token',
      refreshToken: 'new-refresh-token',
      apiKey: 'mock-uuid-string',
    };

    beforeEach(() => {
      mockUserService.findOne.mockResolvedValue(mockUser);
      mockHashService.compare.mockResolvedValue(true); // Password matches
      mockJwtService.signAsync.mockImplementation((payload, config) => {
        if (config.secret === mockConfig.jwt.accessSecret) return Promise.resolve('new-access-token');
        if (config.secret === mockConfig.jwt.refreshSecret) return Promise.resolve('new-refresh-token');
        return Promise.resolve('some-other-token');
      });
      (uuid4 as jest.Mock).mockReturnValue('mock-uuid-string'); // For new API key
    });

    it('should login user successfully without 2FA', async () => {
      const userWithout2FA = { ...mockUser, enable2FA: false };
      mockUserService.findOne.mockResolvedValue(userWithout2FA);

      const result = await service.login(loginDto, ip);

      expect(mockUserService.findOne).toHaveBeenCalledWith(expect.objectContaining({ email: loginDto.email }));
      expect(mockHashService.compare).toHaveBeenCalledWith(loginDto.password, userWithout2FA.password);
      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        // This call is from generateTokens
        expect.objectContaining({
          id: userWithout2FA.id,
          lastLoginIp: ip,
          accessToken: mockTokens.accessToken,
          refreshToken: mockTokens.refreshToken,
          apiKey: mockTokens.apiKey,
        }),
        false,
        true,
      );
      expect(result).toBeInstanceOf(RefreshTokensResponseDto);
      expect(result.accessToken).toBe(mockTokens.accessToken);
    });

    it('should send 2FA email if 2FA is enabled', async () => {
      const userWith2FA = { ...mockUser, enable2FA: true };
      mockUserService.findOne.mockResolvedValue(userWith2FA);
      mockMailService.send2FAEmail.mockResolvedValue(undefined); // 2FA email sent successfully
      mockHashService.hash.mockResolvedValue('hashed-2fa-code');

      const result = await service.login(loginDto, ip);

      expect(mockMailService.send2FAEmail).toHaveBeenCalled();
      // First updateUser call from send2FAemail
      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({ id: userWith2FA.id, twoFASecret: 'hashed-2fa-code' }),
      );
      // Second updateUser call from generateTokens
      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({ id: userWith2FA.id, apiKey: mockTokens.apiKey }),
        false,
        true,
      );
      expect(result).toBeInstanceOf(RefreshTokensPlusResponseDto);
      expect((result as RefreshTokensPlusResponseDto).message).toBe('2FA email sent successfully');
      // expect((result as RefreshTokensPlusResponseDto).tokens.apiKey).toBe(mockTokens.apiKey);
    });

    it('should throw BadRequestException if sending 2FA email fails', async () => {
      const userWith2FA = { ...mockUser, enable2FA: true };
      mockUserService.findOne.mockResolvedValue(userWith2FA);
      // mockMailService.send2FAEmail.mockRejectedValue(new Error('Mail service down')); // 2FA email fails
      const mailErrorMessage = 'Mail service down';
      mockMailService.send2FAEmail.mockRejectedValue(new Error(mailErrorMessage)); // 2FA email fails

      await expect(service.login(loginDto, ip)).rejects.toThrow(
        // new BadRequestException('Failed to send 2FA email.  Try again later.'),
        new BadRequestException(`Send 2FA email failed: ${mailErrorMessage}`),
      );
    });

    it('should throw UnauthorizedException for invalid password', async () => {
      mockHashService.compare.mockResolvedValue(false); // Password does not match
      await expect(service.login(loginDto, ip)).rejects.toThrow(new UnauthorizedException('Invalid password'));
      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({
          id: mockUser.id,
          failedLoginAttempts: 1, // It was 0, incremented to 1
        }),
      );
    });

    it('should throw NotFoundException if user not found', async () => {
      mockUserService.findOne.mockResolvedValue(null);
      // The login method's catch-all will convert NotFoundException to BadRequestException
      const expectedErrorMessage = 'User not found!';
      await expect(service.login(loginDto, ip)).rejects.toThrow(
        new BadRequestException(`Login failed: ${expectedErrorMessage}`),
      );
    });
  });

  // --- logout ---
  describe('logout', () => {
    const mockPayload: JwtPayloadDto = {
      sub: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      apiKey: 'current-api-key',
      role: Enums.UserRoles.USER,
      isVerified: true,
      enable2FA: false,
      createdAt: new Date(),
      ip: '127.0.0.1',
      reqId: 'req-id',
      iat: 0,
      exp: 0,
    };
    const mockUserFromDb = {
      id: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      apiKey: 'current-api-key', // Matches payload
      failedLoginAttempts: 0,
    } as UserEntity;

    it('should logout user successfully', async () => {
      mockUserService.findOne.mockResolvedValue(mockUserFromDb);

      const result = await service.logout(mockPayload);

      expect(mockUserService.findOne).toHaveBeenCalledWith(
        expect.objectContaining({ id: mockPayload.sub, apiKey: mockPayload.apiKey }),
      );
      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({
          id: mockUserFromDb.id,
          apiKey: null,
          accessToken: null,
          refreshToken: null,
          lastLogoutIp: mockPayload.ip,
        }),
      );
      expect(result).toEqual(new MessageResponseDto('Logout successful'));
    });

    it('should throw UnauthorizedException if API key mismatch during findAndValidateUser', async () => {
      const userWithDifferentApiKey = { ...mockUserFromDb, apiKey: 'different-api-key' };
      mockUserService.findOne.mockResolvedValue(userWithDifferentApiKey); // Simulate DB has different API key

      await expect(service.logout(mockPayload)).rejects.toThrow(new UnauthorizedException('Invalid API key'));
    });

    it('should throw NotFoundException if user not found during findAndValidateUser', async () => {
      mockUserService.findOne.mockResolvedValue(null);
      await expect(service.logout(mockPayload)).rejects.toThrow(new NotFoundException('User not found!'));
    });
  });

  // --- refreshToken ---
  describe('refreshToken', () => {
    const mockPayload: JwtPayloadDto = {
      sub: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      apiKey: 'current-api-key', // This will be regenerated
      role: Enums.UserRoles.USER,
      isVerified: true,
      enable2FA: false,
      createdAt: new Date(),
      ip: '127.0.0.1',
      reqId: 'req-id',
      iat: 0,
      exp: 0,
    };
    // const mockTokens: Tokens = {
    //   accessToken: 'refreshed-access-token',
    //   refreshToken: 'refreshed-refresh-token',
    //   apiKey: 'new-mock-uuid-string',
    // };

    it('should refresh tokens successfully', async () => {
      (uuid4 as jest.Mock).mockReturnValue('new-mock-uuid-string');
      mockJwtService.signAsync.mockImplementation((payload, config) => {
        if (config.secret === mockConfig.jwt.accessSecret) return Promise.resolve('refreshed-access-token');
        if (config.secret === mockConfig.jwt.refreshSecret) return Promise.resolve('refreshed-refresh-token');
        return Promise.resolve('some-other-token');
      });

      const result = await service.refreshToken(mockPayload);

      expect(uuid4).toHaveBeenCalledTimes(1); // For new API key
      expect(mockJwtService.signAsync).toHaveBeenCalledTimes(2); // For access and refresh tokens
      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({
          id: mockPayload.sub,
          apiKey: 'new-mock-uuid-string',
          accessToken: 'refreshed-access-token',
          refreshToken: 'refreshed-refresh-token',
        }),
        false,
        true,
      );
      expect(result).toBeInstanceOf(RefreshTokensResponseDto);
      // expect(result.apiKey).toBe('new-mock-uuid-string');
      expect(result.accessToken).toBe('refreshed-access-token');
    });
  });

  // --- changePassword ---
  describe('changePassword', () => {
    const mockPayload: JwtPayloadDto = {
      sub: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      apiKey: 'current-api-key',
      role: Enums.UserRoles.USER,
      isVerified: true,
      enable2FA: false,
      createdAt: new Date(),
      ip: '127.0.0.1',
      reqId: 'req-id',
      iat: 0,
      exp: 0,
    };
    const changePwdDto: ChangePwdRequestDto = { oldPassword: 'OldPassword@1', newPassword: 'NewPassword@1' };
    const mockUserFromDb = {
      id: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      password: 'hashedOldPassword', // Hashed 'OldPassword@1'
      apiKey: 'current-api-key',
      failedLoginAttempts: 0,
    } as UserEntity;
    const mockNewTokens: Tokens = {
      accessToken: 'new-access-after-pwd-change',
      refreshToken: 'new-refresh-after-pwd-change',
      apiKey: 'new-api-key-after-pwd-change',
    };

    beforeEach(() => {
      mockUserService.findOne.mockResolvedValue(mockUserFromDb);
      mockHashService.compare.mockResolvedValue(true); // Old password matches
      (uuid4 as jest.Mock).mockReturnValue('new-api-key-after-pwd-change');
      mockJwtService.signAsync.mockImplementation((payload, config) => {
        if (config.secret === mockConfig.jwt.accessSecret) return Promise.resolve('new-access-after-pwd-change');
        if (config.secret === mockConfig.jwt.refreshSecret) return Promise.resolve('new-refresh-after-pwd-change');
        return Promise.resolve('some-other-token');
      });
    });

    it('should change password successfully', async () => {
      const result = await service.changePassword(mockPayload, changePwdDto);

      expect(mockUserService.findOne).toHaveBeenCalledWith(
        expect.objectContaining({
          id: mockPayload.sub,
          password: changePwdDto.oldPassword,
          apiKey: mockPayload.apiKey,
        }),
      );
      expect(mockHashService.compare).toHaveBeenCalledWith(changePwdDto.oldPassword, mockUserFromDb.password);
      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({
          id: mockUserFromDb.id,
          password: changePwdDto.newPassword,
          apiKey: mockNewTokens.apiKey,
          accessToken: mockNewTokens.accessToken,
          refreshToken: mockNewTokens.refreshToken,
        }),
        true,
        true, // hashPassword: true, saveTokens: true
      );
      expect(result).toBeInstanceOf(RefreshTokensPlusResponseDto);
      expect(result.message).toBe('Password changed successfully');
      // expect(result.tokens.apiKey).toBe(mockNewTokens.apiKey);
    });

    it('should throw BadRequestException if new password is same as old', async () => {
      const samePasswordDto: ChangePwdRequestDto = { oldPassword: 'OldPassword@1', newPassword: 'OldPassword@1' };
      await expect(service.changePassword(mockPayload, samePasswordDto)).rejects.toThrow(
        new BadRequestException('New password cannot be the same as the old password'),
      );
    });

    it('should throw BadRequestException for invalid new password format', async () => {
      const invalidNewPasswordDto: ChangePwdRequestDto = { oldPassword: 'OldPassword@1', newPassword: 'new' };
      await expect(service.changePassword(mockPayload, invalidNewPasswordDto)).rejects.toThrow(
        new BadRequestException(`New password must be at least ${Constants.PWD_MIN_LENGTH} characters long`),
      );
    });

    it('should throw UnauthorizedException if old password does not match', async () => {
      mockHashService.compare.mockResolvedValue(false); // Old password mismatch
      await expect(service.changePassword(mockPayload, changePwdDto)).rejects.toThrow(
        new UnauthorizedException('Invalid password'),
      );
    });
  });

  // --- verifyEmail ---
  describe('verifyEmail', () => {
    const ip = '127.0.0.1';
    const token = 'valid-verify-token';
    const mockUser = {
      id: 'user-id',
      verificationToken: token,
      verificationTokenExpiresAt: new Date('2023-01-02T00:00:00.000Z'), // Not expired
      isVerified: false,
    } as UserEntity;

    it('should verify email successfully', async () => {
      mockUserService.findOne.mockResolvedValue(mockUser);
      (isExpired as jest.Mock).mockReturnValue(false); // Token not expired

      const result = await service.verifyEmail(ip, token);

      expect(mockUserService.findOne).toHaveBeenCalledWith({ verificationToken: token });
      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({
          id: mockUser.id,
          isVerified: true,
          verifiedFromIp: ip,
          verificationToken: null,
        }),
      );
      expect(result).toBe(true);
    });

    it('should return false if user not found', async () => {
      mockUserService.findOne.mockResolvedValue(null);
      const result = await service.verifyEmail(ip, token);
      expect(result).toBe(false);
      expect(mockPinoLogger.error).toHaveBeenCalledWith(expect.stringContaining('User not found!'));
    });

    it('should return false if token is expired', async () => {
      mockUserService.findOne.mockResolvedValue(mockUser);
      (isExpired as jest.Mock).mockReturnValue(true); // Token expired

      const result = await service.verifyEmail(ip, token);
      expect(result).toBe(false);
      expect(mockPinoLogger.error).toHaveBeenCalledWith(expect.stringContaining('Verification token expired'));
    });

    it('should return false on generic error and log it', async () => {
      mockUserService.findOne.mockRejectedValue(new Error('DB connection failed'));
      const result = await service.verifyEmail(ip, token);
      expect(result).toBe(false);
      expect(mockPinoLogger.error).toHaveBeenCalledWith(expect.stringContaining('DB connection failed'));
    });
  });

  // --- resendVerification ---
  describe('resendVerification', () => {
    const mockPayload: JwtPayloadDto = {
      sub: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      apiKey: 'api-key',
      role: Enums.UserRoles.USER,
      isVerified: false,
      enable2FA: false,
      createdAt: new Date(),
      ip: '127.0.0.1',
      reqId: 'req-id',
      iat: 0,
      exp: 0,
    };
    const mockUserFromDb = {
      id: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      apiKey: 'api-key',
      failedLoginAttempts: 0,
    } as UserEntity;
    const newVerificationToken = 'hashed-new-verify-token';

    beforeEach(() => {
      mockUserService.findOne.mockResolvedValue(mockUserFromDb);
      (uuid4 as jest.Mock).mockReturnValueOnce('new-raw-verify-token'); // Raw token before hashing for verificationToken
      mockHashService.hash.mockResolvedValue(newVerificationToken); // Hashed token
      mockMailService.sendVerificationEmail.mockResolvedValue(undefined);
      // Mock token generation for the response
      (uuid4 as jest.Mock).mockReturnValueOnce('new-api-key-for-resend'); // For API key in generateTokens
      mockJwtService.signAsync.mockResolvedValueOnce('new-access-token').mockResolvedValueOnce('new-refresh-token');
    });

    it('should resend verification email successfully', async () => {
      const result = await service.resendVerification(mockPayload);

      expect(mockUserService.findOne).toHaveBeenCalledWith(
        expect.objectContaining({ id: mockPayload.sub, apiKey: mockPayload.apiKey }),
      );
      expect(mockHashService.hash).toHaveBeenCalledWith('new-raw-verify-token');
      // The updateUser call from generateTokens will save the user with new verification token, new API key, and new access/refresh tokens
      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({
          id: mockUserFromDb.id,
          verificationToken: newVerificationToken,
          apiKey: 'new-api-key-for-resend',
          accessToken: 'new-access-token',
          refreshToken: 'new-refresh-token',
        }),
        false,
        true, // from generateTokens
      );
      expect(mockMailService.sendVerificationEmail).toHaveBeenCalledWith(mockUserFromDb.email, newVerificationToken);
      expect(result).toBeInstanceOf(RefreshTokensPlusResponseDto);
      expect(result.message).toBe('Verification email sent successfully.');
      // expect(result.tokens.apiKey).toBe('new-api-key-for-resend');
    });

    it('should throw NotFoundException if user not found', async () => {
      mockUserService.findOne.mockResolvedValue(null);
      await expect(service.resendVerification(mockPayload)).rejects.toThrow(NotFoundException);
    });
  });

  // --- enable2FA ---
  describe('enable2FA', () => {
    const mockPayload: JwtPayloadDto = {
      sub: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      apiKey: 'api-key',
      role: Enums.UserRoles.USER,
      isVerified: true,
      enable2FA: false,
      createdAt: new Date(),
      ip: '127.0.0.1',
      reqId: 'req-id',
      iat: 0,
      exp: 0,
    };
    const mockUserFromDb = {
      id: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      apiKey: 'api-key',
      enable2FA: false,
      failedLoginAttempts: 0,
    } as UserEntity;

    beforeEach(() => {
      mockUserService.findOne.mockResolvedValue(mockUserFromDb);
      mockMailService.send2FAEmail.mockResolvedValue(undefined);
      mockHashService.hash.mockResolvedValue('hashed-2fa-code');
      // Mock token generation for the response
      (uuid4 as jest.Mock).mockReturnValueOnce('new-api-key-for-enable2fa');
      mockJwtService.signAsync.mockResolvedValueOnce('new-access-token').mockResolvedValueOnce('new-refresh-token');
    });

    it('should enable 2FA and send email successfully', async () => {
      const result = await service.enable2FA(mockPayload);

      expect(mockMailService.send2FAEmail).toHaveBeenCalled();
      // First updateUser from send2FAemail
      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({ id: mockUserFromDb.id, twoFASecret: 'hashed-2fa-code' }),
      );
      // Second updateUser from generateTokens
      expect(mockUserService.updateUser).toHaveBeenCalledTimes(2);
      expect(mockUserService.updateUser).toHaveBeenNthCalledWith(
        1,
        expect.objectContaining({
          apiKey: 'new-raw-verify-token',
          email: 'test@example.com',
          enable2FA: false,
          failedLoginAttempts: 0,
          id: 'user-id',
          twoFASecret: 'hashed-2fa-code',
          twoFASecretExpiresAt: new Date('2023-01-01T00:05:00.000Z'),
          userName: 'testuser',
        }),
      );
      expect(mockUserService.updateUser).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({
          accessToken: 'new-access-token',
          apiKey: 'new-raw-verify-token',
          email: 'test@example.com',
          enable2FA: false,
          failedLoginAttempts: 0,
          id: 'user-id',
          refreshToken: 'new-refresh-token',
          twoFASecret: 'hashed-2fa-code',
          twoFASecretExpiresAt: new Date('2023-01-01T00:05:00.000Z'),
          userName: 'testuser',
        }),
        false,
        true,
      );
      expect(result).toBeInstanceOf(RefreshTokensPlusResponseDto);
      expect(result.message).toBe('2FA email sent successfully');
      expect(result.accessToken).toBe('new-access-token');
    });

    it('should throw BadRequestException if send2FAemail fails', async () => {
      mockMailService.send2FAEmail.mockRejectedValue(new Error('Mail error'));
      await expect(service.enable2FA(mockPayload)).rejects.toThrow(
        new BadRequestException('Send 2FA email failed: Mail error'),
      );
    });
  });

  // --- send2FA (public method for password reset etc) ---
  describe('send2FA (public)', () => {
    const sendDto: Send2FARequestDto = { email: 'test@example.com' };
    const mockUserFromDb = { id: 'user-id', email: 'test@example.com' } as UserEntity;

    it('should send 2FA email and return success message even if user exists', async () => {
      mockUserService.findOne.mockResolvedValue(mockUserFromDb);
      mockMailService.send2FAEmail.mockResolvedValue(undefined);
      mockHashService.hash.mockResolvedValue('hashed-2fa-code');

      const result = await service.send2FA(sendDto);

      expect(mockMailService.send2FAEmail).toHaveBeenCalled();
      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({ id: mockUserFromDb.id, twoFASecret: 'hashed-2fa-code' }),
      );
      expect(result).toEqual(
        new MessageResponseDto('A password reset code has been sent to the account if it exists.', true),
      );
    });

    it('should return success message and log error if send2FAemail fails, without exposing failure', async () => {
      mockUserService.findOne.mockResolvedValue(mockUserFromDb);
      mockMailService.send2FAEmail.mockRejectedValue(new Error('Mail error')); // Simulate email sending failure

      const result = await service.send2FA(sendDto);

      expect(mockPinoLogger.error).toHaveBeenCalledWith(expect.stringContaining('Error sending 2FA to'));
      expect(result).toEqual(
        new MessageResponseDto('A password reset code has been sent to the account if it exists.', true),
      );
    });

    it('should return success message even if user does not exist, to prevent enumeration', async () => {
      mockUserService.findOne.mockResolvedValue(null); // User not found
      const result = await service.send2FA(sendDto);
      expect(mockMailService.send2FAEmail).not.toHaveBeenCalled();
      expect(mockPinoLogger.error).toHaveBeenCalledWith(expect.stringContaining('User not found!'));
      expect(result).toEqual(
        new MessageResponseDto('A password reset code has been sent to the account if it exists.', true),
      );
    });
  });

  // --- disable2FA ---
  describe('disable2FA', () => {
    const mockPayload: JwtPayloadDto = {
      sub: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      apiKey: 'api-key',
      role: Enums.UserRoles.USER,
      isVerified: true,
      enable2FA: true,
      createdAt: new Date(),
      ip: '127.0.0.1',
      reqId: 'req-id',
      iat: 0,
      exp: 0,
    };
    const mockUserFromDb = {
      id: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      apiKey: 'api-key',
      enable2FA: true,
      failedLoginAttempts: 0,
    } as UserEntity;

    beforeEach(() => {
      mockUserService.findOne.mockResolvedValue(mockUserFromDb);
      // Mock token generation for the response
      (uuid4 as jest.Mock).mockReturnValueOnce('new-api-key-for-disable2fa');
      mockJwtService.signAsync.mockResolvedValueOnce('new-access-token').mockResolvedValueOnce('new-refresh-token');
    });

    it('should disable 2FA successfully', async () => {
      const result = await service.disable2FA(mockPayload);

      // First updateUser call from disable2FA logic
      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({
          id: mockUserFromDb.id,
          enable2FA: false,
          twoFASecret: null,
          twoFASecretExpiresAt: null,
        }),
      );
      // Second updateUser call from generateTokens
      expect(mockUserService.updateUser).toHaveBeenCalledTimes(2);
      // expect(mockUserService.updateUser).toHaveBeenCalledWith(1,
      //   expect.objectContaining({ id: mockUserFromDb.id, apiKey: 'new-api-key-for-disable2fa' }),
      //   false,
      //   true,
      // );
      expect(result).toBeInstanceOf(RefreshTokensPlusResponseDto);
      expect(result.message).toBe('2FA disabled successfully');
      // expect(result.tokens.apiKey).toBe('new-api-key-for-disable2fa');
    });
  });

  // --- verify2FA ---
  describe('verify2FA', () => {
    const verifyDto: Verify2FARequestDto = { code: '123456', userName: 'testuser' };
    const mockUserPayload: JwtPayloadDto = {
      sub: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      apiKey: 'api-key',
      role: Enums.UserRoles.USER,
      isVerified: true,
      enable2FA: true,
      createdAt: new Date(),
      ip: '127.0.0.1',
      reqId: 'req-id',
      iat: 0,
      exp: 0,
    };
    const mockUserFromDb = {
      id: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      apiKey: 'api-key',
      enable2FA: false, // Will be set to true if this is the enabling verification
      twoFASecret: 'hashed-123456',
      twoFASecretExpiresAt: new Date('2023-01-01T00:05:00.000Z'), // Not expired
      failedLoginAttempts: 0,
    } as UserEntity;

    beforeEach(() => {
      mockUserService.findOne.mockResolvedValue(mockUserFromDb); // For findAndValidateUser or direct findOne
      mockHashService.compare.mockResolvedValue(true); // Code matches
      (isExpired as jest.Mock).mockReturnValue(false); // Code not expired
      // Mock token generation
      (uuid4 as jest.Mock).mockReturnValueOnce('new-api-key-for-verify2fa');
      mockJwtService.signAsync.mockResolvedValueOnce('new-access-token').mockResolvedValueOnce('new-refresh-token');
    });

    it('should verify 2FA successfully for login/enable route (user payload provided)', async () => {
      const userCurrentlyEnabling2FA = { ...mockUserFromDb, enable2FA: false }; // Simulating user is in process of enabling
      mockUserService.findOne.mockResolvedValue(userCurrentlyEnabling2FA); // findAndValidateUser will be called

      const result = await service.verify2FA(verifyDto, mockUserPayload);

      expect(mockUserService.findOne).toHaveBeenCalledWith(
        expect.objectContaining({ id: mockUserPayload.sub, apiKey: mockUserPayload.apiKey }),
      );
      expect(mockHashService.compare).toHaveBeenCalledWith(verifyDto.code, userCurrentlyEnabling2FA.twoFASecret);
      // This updateUser is from generateTokens, after userEntity has been modified in memory
      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({
          accessToken: 'new-access-token',
          apiKey: 'new-api-key-for-enable2fa',
          email: 'test@example.com',
          enable2FA: true,
          enabled2FAAt: new Date('2023-01-01T00:00:00.000Z'),
          enabled2FAFromIp: mockUserPayload.ip,
          failedLoginAttempts: 0,
          id: 'user-id',
          isLocked: false,
          isLockedExpiresAt: null,
          isLockedReason: null,
          lastLogin: new Date('2023-01-01T00:00:00.000Z'),
          lastLoginIp: mockUserPayload.ip,
          refreshToken: 'new-refresh-token',
          twoFASecret: null,
          twoFASecretExpiresAt: null,
          userName: 'testuser',
        }),
        false,
        true,
      );
      expect(result).toBeInstanceOf(RefreshTokensResponseDto);
      // expect((result as RefreshTokensResponseDto).apiKey).toBe('new-api-key-for-verify2fa');
    });

    it('should verify 2FA successfully for password reset route (no user payload)', async () => {
      // For password reset, find2FAUser uses body (Verify2FARequestDto) to find user
      const userForPasswordReset = { ...mockUserFromDb, enable2FA: true }; // 2FA already enabled
      mockUserService.findOne.mockResolvedValue(userForPasswordReset); // Direct findOne in find2FAUser

      const result = await service.verify2FA(verifyDto); // No user payload

      expect(mockUserService.findOne).toHaveBeenCalledWith(verifyDto); // find2FAUser calls this
      expect(mockHashService.compare).toHaveBeenCalledWith(verifyDto.code, mockUserFromDb.twoFASecret);
      expect(mockUserService.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({
          id: userForPasswordReset.id,
          twoFASecret: null, // Cleared
        }),
      );
      expect(result).toEqual(new MessageResponseDto('2FA code verified successfully', true));
    });

    it('should throw BadRequestException if 2FA code is expired', async () => {
      (isExpired as jest.Mock).mockReturnValue(true); // Code expired
      await expect(service.verify2FA(verifyDto, mockUserPayload)).rejects.toThrow(
        new BadRequestException('2FA code has expired'),
      );
    });

    it('should throw BadRequestException if 2FA code is invalid', async () => {
      mockHashService.compare.mockResolvedValue(false); // Code does not match
      await expect(service.verify2FA(verifyDto, mockUserPayload)).rejects.toThrow(
        new BadRequestException('Invalid 2FA code'),
      );
    });

    it('should throw NotFoundException if user not found (login route)', async () => {
      mockUserService.findOne.mockResolvedValue(null); // findAndValidateUser fails
      await expect(service.verify2FA(verifyDto, mockUserPayload)).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException if user not found (password reset route)', async () => {
      mockUserService.findOne.mockResolvedValue(null); // findOne in find2FAUser fails
      await expect(service.verify2FA(verifyDto)).rejects.toThrow(NotFoundException);
    });
  });
});
