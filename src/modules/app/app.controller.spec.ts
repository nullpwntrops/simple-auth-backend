import { Test, TestingModule } from '@nestjs/testing';
import { Response } from 'express';
import { v4 as uuid4 } from 'uuid';
import { PinoLogger } from 'nestjs-pino';
import { Enums } from '../../common/constants';
import { AppConfig, getConfig } from '../../common/config/service-config';
import { JwtPayloadDto } from '../../database/dto/jwt-payload.dto';
import { MessageResponseDto } from '../../database/dto/message-response.dto';
import { Verify2FARequestDto } from '../auth/dto/verify-2fa-request.dto';
import { AuthService } from '../auth/auth.service';
import { AppController } from './app.controller';
import { AppService } from './app.service';

// Mock getConfig before it's imported by the controller
jest.mock('../../common/config/service-config', () => ({
  getConfig: jest.fn(),
}));

const mockAppService = {
  getHello: jest.fn(),
};

const mockAuthService = {
  verifyEmail: jest.fn(),
  verify2FA: jest.fn(),
};

const mockLogger = {
  setContext: jest.fn(),
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
  trace: jest.fn(),
};

const mockUserPayload: JwtPayloadDto = {
  sub: 'user-id-123',
  email: 'test@example.com',
  userName: 'testuser',
  apiKey: 'api-key-123',
  role: Enums.UserRoles.USER,
  isVerified: true,
  enable2FA: false,
  createdAt: new Date('2023-01-01T00:00:00.000Z'),
  ip: '127.0.0.1',
  reqId: uuid4(),
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
};

const mockAppConfig: Partial<AppConfig> = {
  service: {
    serviceName: 'TestService',
    serviceUrl: 'test.example.com',
    identifier: '',
    api_key: 'test-api-key',
    nodeEnv: Enums.NodeEnv.TEST,
    port: 3000,
    dockerPort: 2000,
    app_name: 'Test Service API',
    isDevelopment: false,
    isTest: true,
    isProduction: false,
  },
  jwt: {
    accessSecret: 'access',
    accessExpiration: '15m',
    refreshSecret: 'refresh',
    refreshExpiration: '7d',
    resetExpiration: '1h',
    verifyExpiration: '1d',
  },
  misc: {
    twoFaLength: 4,
    twoFaExpiration: '1d',
    maxFailAttempts: 5,
    lockoutExpiration: '1d',
    healthMemory: 150,
    healthDiskThreshold: 0.75,
    pinoLogLevel: Enums.PinoLogLevels.INFO,
  },
  // Add other necessary mock config parts if your controller uses them
};

describe('AppController', () => {
  let appController: AppController;
  let appService: AppService;
  let authService: AuthService;

  beforeEach(async () => {
    jest.clearAllMocks(); // Clear mocks at the beginning
    // Reset getConfig mock for each test
    (getConfig as jest.Mock).mockReturnValue(mockAppConfig);

    const app: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
      providers: [
        { provide: AppService, useValue: mockAppService },
        { provide: AuthService, useValue: mockAuthService },
        { provide: PinoLogger, useValue: mockLogger },
      ],
    }).compile();

    appController = app.get<AppController>(AppController);
    appService = app.get<AppService>(AppService);
    authService = app.get<AuthService>(AuthService);
    (getConfig as jest.Mock).mockReturnValue(mockAppConfig); // Ensure config is mocked for constructor
  });

  it('should be defined and initialize correctly', () => {
    expect(appController).toBeDefined();
    expect(mockLogger.setContext).toHaveBeenCalledWith(AppController.name);
    expect(getConfig).toHaveBeenCalledTimes(1); // Called once in the constructor
  });

  describe('sayHello', () => {
    it('should call appService.getHello with verbose=false and return its result', () => {
      const expectedResponse = new MessageResponseDto('Hello World!');
      mockAppService.getHello.mockReturnValue(expectedResponse);

      const result = appController.sayHello();

      expect(appService.getHello).toHaveBeenCalledWith(false); // undefined for user when verbose is false
      expect(result).toEqual(expectedResponse);
    });
  });

  describe('verify', () => {
    const ip = '127.0.0.1';
    const token = 'verification-token';
    const mockRes = { redirect: jest.fn() } as unknown as Response;

    it('should call authService.verifyEmail and redirect to success URL if verification is successful', async () => {
      mockAuthService.verifyEmail.mockResolvedValue(true); // Simulate successful verification
      await appController.verify(ip, token, mockRes);
      expect(authService.verifyEmail).toHaveBeenCalledWith(ip, token);
      expect(mockRes.redirect).toHaveBeenCalledWith(
        `http://${mockAppConfig.service.serviceUrl}/email-verification-success.html`,
      );
    });

    it('should call authService.verifyEmail and redirect to fail URL if verification fails', async () => {
      mockAuthService.verifyEmail.mockResolvedValue(false); // Simulate failed verification
      await appController.verify(ip, token, mockRes);
      expect(authService.verifyEmail).toHaveBeenCalledWith(ip, token);
      expect(mockRes.redirect).toHaveBeenCalledWith(
        `http://${mockAppConfig.service.serviceUrl}/email-verification-fail.html`,
      );
    });
  });

  describe('verify2FA', () => {
    const mockVerify2FARequest: Verify2FARequestDto = {
      userName: 'testuser',
      email: 'test@example.com',
      code: '1234',
    };

    it('should call authService.verify2FA and return success message if 2FA is verified', async () => {
      mockAuthService.verify2FA.mockResolvedValue(undefined); // Simulate successful 2FA verification

      const result = await appController.verify2FA(mockVerify2FARequest);

      expect(authService.verify2FA).toHaveBeenCalledWith(mockVerify2FARequest);
      expect(result).toEqual(new MessageResponseDto('2FA code verified successfully.', true));
      expect(mockLogger.error).not.toHaveBeenCalled();
    });

    it('should call authService.verify2FA, log error, and return failure message if 2FA verification fails', async () => {
      const errorMessage = 'Invalid 2FA code';
      mockAuthService.verify2FA.mockRejectedValue(new Error(errorMessage)); // Simulate failed 2FA verification

      const result = await appController.verify2FA(mockVerify2FARequest);

      expect(authService.verify2FA).toHaveBeenCalledWith(mockVerify2FARequest);
      expect(mockLogger.error).toHaveBeenCalledWith(
        `Error trying to verify 2FA for ${mockVerify2FARequest.userName} (${mockVerify2FARequest.email}): ${errorMessage}`,
      );
      // The controller currently returns a "success" message text even on failure, but with success=false
      expect(result).toEqual(new MessageResponseDto('2FA code verified successfully.', false));
    });

    it('should handle unexpected errors during 2FA verification and return failure message', async () => {
      mockAuthService.verify2FA.mockRejectedValue('Some unexpected string error'); // Simulate non-Error object rejection
      const result = await appController.verify2FA(mockVerify2FARequest);
      expect(authService.verify2FA).toHaveBeenCalledWith(mockVerify2FARequest);
      expect(mockLogger.error).toHaveBeenCalled();
      expect(result).toEqual(new MessageResponseDto('2FA code verified successfully.', false));
    });
  });

  describe('getHeartbeat', () => {
    it('should call appService.getHello with verbose=true and user payload, then return its result', () => {
      const expectedResponse = new MessageResponseDto(`Hello ${mockUserPayload.userName}!`);
      mockAppService.getHello.mockReturnValue(expectedResponse);

      const result = appController.getHeartbeat(mockUserPayload);

      expect(appService.getHello).toHaveBeenCalledWith(true, mockUserPayload);
      expect(result).toEqual(expectedResponse);
    });
  });
});
