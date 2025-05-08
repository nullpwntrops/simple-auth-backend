import { Test, TestingModule } from '@nestjs/testing';
import { createTransport } from 'nodemailer';
import Mail from 'nodemailer/lib/mailer';
import { AppConfig, getConfig } from '../../common/config/service-config';
import { AuthRoutes } from '../../common/constants/routes';
import { MailService } from './mailer.service';

// Mock getConfig
jest.mock('../../common/config/service-config', () => ({
  getConfig: jest.fn(),
}));

// Mock nodemailer
const mockSendMail = jest.fn();
const mockTransporter = {
  sendMail: mockSendMail,
};
jest.mock('nodemailer', () => ({
  createTransport: jest.fn(() => mockTransporter),
}));

const mockMailConfig = {
  from: 'default-sender@example.com',
  transportOptions: {
    host: 'smtp.example.com',
    port: 587,
    auth: {
      user: 'testuser',
      pass: 'testpass',
    },
  },
};

const mockServiceConfig = {
  serviceUrl: 'test.app.com',
  app_name: 'My Test App',
};

const mockAppConfig: Partial<AppConfig> = {
  mail: mockMailConfig,
  service: mockServiceConfig as any, // Cast to any if only partial service config is mocked
};

describe('MailService', () => {
  let service: MailService;

  beforeEach(async () => {
    jest.clearAllMocks(); // Clear all mocks at the beginning of each test

    // Reset getConfig mock for each test
    (getConfig as jest.Mock).mockReturnValue(mockAppConfig);
    // The nodemailer.createTransport mock is set up globally and will be fresh due to clearAllMocks.

    const module: TestingModule = await Test.createTestingModule({
      providers: [MailService],
    }).compile();

    service = module.get<MailService>(MailService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('constructor', () => {
    it('should initialize with config and create a transporter', () => {
      // getConfig is called during module setup when MailService is instantiated
      expect(getConfig).toHaveBeenCalledTimes(1); // Called once during initial instantiation
      expect(createTransport).toHaveBeenCalledWith({
        host: mockMailConfig.transportOptions.host,
        port: mockMailConfig.transportOptions.port,
        auth: {
          user: mockMailConfig.transportOptions.auth.user,
          pass: mockMailConfig.transportOptions.auth.pass,
        },
      });
      expect((service as any).fromValue).toBe(mockMailConfig.from);
    });
  });

  describe('send', () => {
    const mailOptions: Mail.Options = {
      to: 'recipient@example.com',
      subject: 'Test Email',
      text: 'This is a test email.',
    };
    const mockResponse = '250 OK';

    it('should send an email using the transporter and return the response', async () => {
      mockSendMail.mockResolvedValue({ response: mockResponse });

      const result = await service.send(mailOptions);

      expect(mockTransporter.sendMail).toHaveBeenCalledWith(mailOptions);
      expect(result).toBe(mockResponse);
    });

    it('should use default "from" if not provided in options', async () => {
      mockSendMail.mockResolvedValue({ response: mockResponse });
      const optionsWithoutFrom = { ...mailOptions };
      delete optionsWithoutFrom.from;

      await service.send(optionsWithoutFrom);

      expect(mockTransporter.sendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          from: mockMailConfig.from, // Default from value
          to: mailOptions.to,
          subject: mailOptions.subject,
        }),
      );
    });

    it('should use provided "from" if it exists in options', async () => {
      mockSendMail.mockResolvedValue({ response: mockResponse });
      const customFrom = 'custom-sender@example.com';
      const optionsWithFrom = { ...mailOptions, from: customFrom };

      await service.send(optionsWithFrom);

      expect(mockTransporter.sendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          from: customFrom,
        }),
      );
    });
  });

  describe('sendVerificationEmail', () => {
    it('should call send with correct verification email options', async () => {
      const to = 'verify@example.com';
      const token = 'verificationToken123';
      const expectedUrl = `http://${mockServiceConfig.serviceUrl}/${AuthRoutes.VERIFY_EMAIL}?token=${token}`;
      const mockSendResponse = 'Verification email sent';
      jest.spyOn(service, 'send').mockResolvedValue(mockSendResponse);

      const result = await service.sendVerificationEmail(to, token);

      expect(service.send).toHaveBeenCalledWith({
        to,
        subject: 'Please verify your email address',
        text: `Please verify your email address by clicking on the following link: ${expectedUrl}`,
        html: `<p>Dear User,</p><p>Please verify your email address by clicking on the following link:</p><a href="${expectedUrl}">Verify Email</a>`,
      });
      expect(result).toBe(mockSendResponse);
    });
  });

  describe('send2FAEmail', () => {
    it('should call send with correct 2FA email options', async () => {
      const to = '2fa-user@example.com';
      const code = '123456';
      const mockSendResponse = '2FA email sent';
      jest.spyOn(service, 'send').mockResolvedValue(mockSendResponse);

      const result = await service.send2FAEmail(to, code);

      expect(service.send).toHaveBeenCalledWith({
        to,
        subject: `${mockServiceConfig.app_name} Verification Code`,
        text: `Your verification code is : ${code}`,
        html: `<p>Dear User,</p><p>Your verification code is : <strong>${code}</strong></p>`,
      });
      expect(result).toBe(mockSendResponse);
    });
  });
});
