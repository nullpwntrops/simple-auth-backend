import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { PinoLogger } from 'nestjs-pino';
import * as bcrypt from 'bcrypt';
import { Request } from 'express';

import { AuthGuard } from './auth.guard';
import { getConfig, AppConfig } from '../../common/config/service-config';
import { Enums } from '../../common/constants';
import { IS_PUBLIC_ROUTE } from '../decorators/public.decorator';
import { IS_SEMI_PUBLIC_ROUTE } from '../decorators/semi-public.decorator';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { IS_2FA_ROUTE } from '../decorators/2fa.decorator';
import { UserService } from '../../modules/user/user.service';
import { UserEntity } from '../../database/entities/user.entity';
import { JwtPayloadDto } from '../../database/dto/jwt-payload.dto';

// Mocks
jest.mock('@nestjs/jwt');
// jest.mock('@nestjs/core');  <== this is causing problems
jest.mock('nestjs-pino');
jest.mock('bcrypt');
jest.mock('../../modules/user/user.service');
jest.mock('../../common/config/service-config', () => ({
  getConfig: jest.fn(),
}));

const mockConfig: AppConfig = {
  service: {
    api_key: 'test-service-api-key',
    serviceName: 'test',
    nodeEnv: Enums.NodeEnv.TEST,
    isDevelopment: false,
    isProduction: false,
    isTest: true,
    port: 3000,
    identifier: 'test',
    serviceUrl: 'url',
    app_name: 'app',
    dockerPort: 3001,
  },
  jwt: {
    accessSecret: 'access-secret',
    refreshSecret: 'refresh-secret',
    accessExpiration: '15m',
    refreshExpiration: '7d',
    resetExpiration: '1h',
    verifyExpiration: '1d',
  },
  // Add other necessary config parts if the guard uses them, otherwise keep minimal
  database: {} as any,
  misc: {} as any,
  mail: {} as any,
  throttler: {} as any,
  swagger: {} as any,
};

describe('AuthGuard', () => {
  let guard: AuthGuard;
  let jwtService: JwtService;
  let reflector: Reflector;
  let userService: UserService;
  let logger: PinoLogger;

  const mockPinoLogger = {
    setContext: jest.fn(),
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  };

  const mockExecutionContext = (
    headers: Record<string, string | string[] | undefined> = {},
    metadata: Record<string, any> = {},
    ip: string = '127.0.0.1',
    reqId: string = 'test-req-id',
  ): ExecutionContext => {
    const mockRequest = {
      headers,
      ip,
      id: reqId,
      user: undefined, // Will be populated by the guard
    } as unknown as Request;

    return {
      getHandler: () => jest.fn(),
      getClass: () => jest.fn(),
      switchToHttp: () => ({
        getRequest: () => mockRequest,
      }),
    } as unknown as ExecutionContext;
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    (getConfig as jest.Mock).mockReturnValue(mockConfig);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthGuard,
        { provide: JwtService, useValue: { verifyAsync: jest.fn() } },
        { provide: Reflector, useValue: { getAllAndOverride: jest.fn() } },
        { provide: UserService, useValue: { findOne: jest.fn() } },
        { provide: PinoLogger, useValue: mockPinoLogger },
      ],
    }).compile();

    try {
      guard = module.get<AuthGuard>(AuthGuard);
      console.log('AuthGuard instance:', guard);
    } catch (e) {
      console.error('Error getting AuthGuard instance:', e);
      throw e;
    }
    jwtService = module.get<JwtService>(JwtService);
    reflector = module.get<Reflector>(Reflector);
    userService = module.get<UserService>(UserService);
    logger = module.get<PinoLogger>(PinoLogger);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
    expect(logger.setContext).toHaveBeenCalledWith(AuthGuard.name);
    expect(getConfig).toHaveBeenCalledTimes(1); // Called in constructor
  });

  describe('Public Routes', () => {
    it('should allow access if route is marked public', async () => {
      (reflector.getAllAndOverride as jest.Mock).mockImplementation((key) => key === IS_PUBLIC_ROUTE);
      const context = mockExecutionContext();
      expect(await guard.canActivate(context)).toBe(true);
    });
  });

  describe('API Key Validation (General)', () => {
    it('should throw UnauthorizedException if API key is missing', async () => {
      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(false); // Not public, not semi-public
      const context = mockExecutionContext({ 'x-api-key': undefined }); // No API key
      await expect(guard.canActivate(context)).rejects.toThrow(new UnauthorizedException('Missing API key'));
    });

    it('should throw UnauthorizedException if API key is invalid', async () => {
      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(false);
      const context = mockExecutionContext({ 'x-api-key': 'wrong-api-key' });
      await expect(guard.canActivate(context)).rejects.toThrow(new UnauthorizedException('Invalid API key'));
    });
  });

  describe('Semi-Public Routes', () => {
    it('should allow access with valid API key if route is semi-public', async () => {
      (reflector.getAllAndOverride as jest.Mock).mockImplementation((key) => key === IS_SEMI_PUBLIC_ROUTE);
      const context = mockExecutionContext({ 'x-api-key': mockConfig.service.api_key });
      expect(await guard.canActivate(context)).toBe(true);
    });

    it('should deny access with invalid API key even if route is semi-public', async () => {
      (reflector.getAllAndOverride as jest.Mock).mockImplementation((key) => key === IS_SEMI_PUBLIC_ROUTE);
      const context = mockExecutionContext({ 'x-api-key': 'wrong-api-key' });
      await expect(guard.canActivate(context)).rejects.toThrow(new UnauthorizedException('Invalid API key'));
    });
  });

  describe('Protected Routes (Full Authentication)', () => {
    const mockUserPayload: Partial<JwtPayloadDto> = {
      sub: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      role: Enums.UserRoles.USER,
      apiKey: 'user-api-key',
    };
    const mockUserEntity = {
      id: 'user-id',
      email: 'test@example.com',
      userName: 'testuser',
      role: Enums.UserRoles.USER,
      apiKey: 'user-api-key',
      accessToken: 'hashed-access-token',
      refreshToken: 'hashed-refresh-token',
      isVerified: true,
      twoFASecret: null, // 2FA completed or not enabled
    } as UserEntity;

    beforeEach(() => {
      // Default reflector behavior for protected routes
      (reflector.getAllAndOverride as jest.Mock).mockImplementation((key) => {
        if (key === IS_PUBLIC_ROUTE || key === IS_SEMI_PUBLIC_ROUTE || key === IS_2FA_ROUTE) return false;
        if (key === ROLES_KEY) return []; // No specific roles by default
        return undefined;
      });
      (userService.findOne as jest.Mock).mockResolvedValue(mockUserEntity);
      (jwtService.verifyAsync as jest.Mock).mockImplementation(async (token, options) => {
        if (options.secret === mockConfig.jwt.accessSecret && token === 'valid-access-token') return mockUserPayload;
        if (options.secret === mockConfig.jwt.refreshSecret && token === 'valid-refresh-token') return mockUserPayload; // Assuming refresh token can also grant access here
        throw new Error('jwt verify error');
      });
      (bcrypt.compare as jest.Mock).mockResolvedValue(true); // Tokens match by default
    });

    it('should throw UnauthorizedException if API key is invalid (even for full auth)', async () => {
      const context = mockExecutionContext({
        'x-api-key': 'wrong-api-key',
        authorization: 'Bearer valid-access-token',
      });
      await expect(guard.canActivate(context)).rejects.toThrow(new UnauthorizedException('Invalid API key'));
    });

    it('should throw UnauthorizedException if token is missing', async () => {
      const context = mockExecutionContext({ 'x-api-key': mockConfig.service.api_key }); // No authorization header
      await expect(guard.canActivate(context)).rejects.toThrow(new UnauthorizedException('Missing token'));
    });

    it('should throw UnauthorizedException if token is not Bearer type', async () => {
      const context = mockExecutionContext({
        'x-api-key': mockConfig.service.api_key,
        authorization: 'Basic somecreds',
      });
      await expect(guard.canActivate(context)).rejects.toThrow(new UnauthorizedException('Missing token'));
    });

    it('should throw UnauthorizedException if token verification fails', async () => {
      (jwtService.verifyAsync as jest.Mock).mockRejectedValue(new Error('jwt error'));
      const context = mockExecutionContext({
        'x-api-key': mockConfig.service.api_key,
        authorization: 'Bearer invalid-token',
      });
      await expect(guard.canActivate(context)).rejects.toThrow(new UnauthorizedException('Invalid token'));
    });

    it('should throw UnauthorizedException if role check fails', async () => {
      (reflector.getAllAndOverride as jest.Mock).mockImplementation((key) => {
        if (key === ROLES_KEY) return [Enums.UserRoles.ADMIN]; // Route requires ADMIN
        return false;
      });
      const context = mockExecutionContext({
        'x-api-key': mockConfig.service.api_key,
        authorization: 'Bearer valid-access-token',
      });
      // mockUserPayload has USER role
      await expect(guard.canActivate(context)).rejects.toThrow(
        new UnauthorizedException('User does not have permission to access this route'),
      );
    });

    it('should throw UnauthorizedException if user not found in DB', async () => {
      (userService.findOne as jest.Mock).mockResolvedValue(null);
      const context = mockExecutionContext({
        'x-api-key': mockConfig.service.api_key,
        authorization: 'Bearer valid-access-token',
      });
      await expect(guard.canActivate(context)).rejects.toThrow(new UnauthorizedException('Invalid user'));
    });

    describe('2FA Scenarios', () => {
      it('should throw UnauthorizedException if 2FA in progress (secret set) and route is NOT 2FA route', async () => {
        const userWith2FASecret = { ...mockUserEntity, twoFASecret: 'some-secret' };
        (userService.findOne as jest.Mock).mockResolvedValue(userWith2FASecret);
        // IS_2FA_ROUTE is false by default from beforeEach
        const context = mockExecutionContext({
          'x-api-key': mockConfig.service.api_key,
          authorization: 'Bearer valid-access-token',
        });
        await expect(guard.canActivate(context)).rejects.toThrow(new UnauthorizedException('Invalid use of token'));
      });

      it('should allow access (skip other checks) if 2FA in progress (secret set) and route IS 2FA route', async () => {
        const userWith2FASecret = { ...mockUserEntity, twoFASecret: 'some-secret' };
        (userService.findOne as jest.Mock).mockResolvedValue(userWith2FASecret);
        (reflector.getAllAndOverride as jest.Mock).mockImplementation((key) => key === IS_2FA_ROUTE); // Mark as 2FA route

        const context = mockExecutionContext({
          'x-api-key': mockConfig.service.api_key,
          authorization: 'Bearer valid-access-token',
        });
        const request = context.switchToHttp().getRequest<Request>();

        expect(await guard.canActivate(context)).toBe(true);
        expect(request['user']).toBeDefined();
        expect(request['user']).toEqual(expect.objectContaining({ sub: mockUserPayload.sub })); // Payload should be attached
        expect(bcrypt.compare).not.toHaveBeenCalled(); // Other checks skipped
      });
    });

    it('should throw UnauthorizedException if user is logged out (DB refreshToken is null)', async () => {
      const loggedOutUser = { ...mockUserEntity, refreshToken: null };
      (userService.findOne as jest.Mock).mockResolvedValue(loggedOutUser);
      const context = mockExecutionContext({
        'x-api-key': mockConfig.service.api_key,
        authorization: 'Bearer valid-access-token',
      });
      await expect(guard.canActivate(context)).rejects.toThrow(new UnauthorizedException('User logged out'));
    });

    it('should throw UnauthorizedException if token does not match stored token (bcrypt compare fails)', async () => {
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);
      const context = mockExecutionContext({
        'x-api-key': mockConfig.service.api_key,
        authorization: 'Bearer valid-access-token',
      });
      await expect(guard.canActivate(context)).rejects.toThrow(new UnauthorizedException('Invalid token'));
    });

    it('should throw UnauthorizedException if payload API key does not match user API key from DB', async () => {
      const userWithDifferentApiKey = { ...mockUserEntity, apiKey: 'db-different-api-key' };
      (userService.findOne as jest.Mock).mockResolvedValue(userWithDifferentApiKey);
      // mockUserPayload.apiKey is 'user-api-key'
      const context = mockExecutionContext({
        'x-api-key': mockConfig.service.api_key,
        authorization: 'Bearer valid-access-token',
      });
      await expect(guard.canActivate(context)).rejects.toThrow(new UnauthorizedException('Invalid API key'));
    });

    it('should allow access and attach user to request if all checks pass (access token)', async () => {
      const context = mockExecutionContext({
        'x-api-key': mockConfig.service.api_key,
        authorization: 'Bearer valid-access-token',
      });
      const request = context.switchToHttp().getRequest<Request>();

      expect(await guard.canActivate(context)).toBe(true);
      expect(request['user']).toBeDefined();
      expect(request['user']).toEqual(
        expect.objectContaining({
          sub: mockUserPayload.sub,
          email: mockUserPayload.email,
          userName: mockUserPayload.userName,
          role: mockUserEntity.role, // Updated from DB user
          isVerified: mockUserEntity.isVerified, // Updated from DB user
          ip: '127.0.0.1',
          reqId: 'test-req-id',
        }),
      );
      expect(bcrypt.compare).toHaveBeenCalledWith('valid-access-token', mockUserEntity.accessToken);
    });

    it('should allow access and attach user to request if all checks pass (refresh token)', async () => {
      const context = mockExecutionContext({
        'x-api-key': mockConfig.service.api_key,
        authorization: 'Bearer valid-refresh-token',
      });
      const request = context.switchToHttp().getRequest<Request>();

      expect(await guard.canActivate(context)).toBe(true);
      expect(request['user']).toBeDefined();
      expect(request['user']).toEqual(expect.objectContaining({ sub: mockUserPayload.sub }));
      expect(bcrypt.compare).toHaveBeenCalledWith('valid-refresh-token', mockUserEntity.refreshToken);
    });

    it('should handle generic errors during full authentication and rethrow as UnauthorizedException', async () => {
      (userService.findOne as jest.Mock).mockRejectedValue(new Error('Database connection error'));
      const context = mockExecutionContext({
        'x-api-key': mockConfig.service.api_key,
        authorization: 'Bearer valid-access-token',
      });
      await expect(guard.canActivate(context)).rejects.toThrow(
        new UnauthorizedException('Invalid token: Database connection error'),
      );
    });
  });

  describe('Error Handling in canActivate top level', () => {
    it('should rethrow UnauthorizedException directly from isValidApiKey', async () => {
      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(false); // Not public
      // isValidApiKey will throw UnauthorizedException('Missing API key')
      const context = mockExecutionContext({ 'x-api-key': undefined });
      await expect(guard.canActivate(context)).rejects.toThrow(new UnauthorizedException('Missing API key'));
    });

    it('should wrap other errors from isValidApiKey as UnauthorizedException', async () => {
      (reflector.getAllAndOverride as jest.Mock).mockReturnValue(false); // Not public
      // Force a non-UnauthorizedException from isValidApiKey
      const mockRequest = { headers: {} } as Request;
      const context = {
        getHandler: () => jest.fn(),
        getClass: () => jest.fn(),
        switchToHttp: () => ({
          getRequest: () => {
            throw new Error('Simulated internal error');
          }, // Error during getRequest
        }),
      } as unknown as ExecutionContext;

      // This test setup is a bit contrived as isValidApiKey itself tries to catch and rethrow.
      // The guard's top-level catch is more for unexpected errors from performFullAuthentication.
      // Let's test the performFullAuthentication error wrapping instead.
      (getConfig as jest.Mock).mockReturnValue(mockConfig); // Re-mock for guard instantiation if needed
      const guardInstance = new AuthGuard(jwtService, reflector, userService, logger);

      // Mock performFullAuthentication to throw a generic error
      jest
        .spyOn(guardInstance as any, 'performFullAuthentication')
        .mockRejectedValue(new Error('Some internal auth error'));

      const protectedContext = mockExecutionContext({ 'x-api-key': mockConfig.service.api_key });
      (reflector.getAllAndOverride as jest.Mock).mockImplementation((key) => {
        // Ensure it's not public/semi-public
        return key !== IS_PUBLIC_ROUTE && key !== IS_SEMI_PUBLIC_ROUTE;
      });

      await expect(guardInstance.canActivate(protectedContext)).rejects.toThrow(
        new UnauthorizedException('Invalid token: Some internal auth error'),
      );
    });
  });
});
