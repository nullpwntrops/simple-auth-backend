import { Injectable } from '@nestjs/common';
import { createTransport, Transporter } from 'nodemailer';
import SMTPTransport from 'nodemailer/lib/smtp-transport';
import Mail from 'nodemailer/lib/mailer';
import { AppConfig, getConfig } from '../../common/config/service-config';
import { AuthRoutes } from '../../common/constants/routes';

type MailOptions = Mail.Options;

@Injectable()
export class MailService {
  //*****************************
  //#region Local Variables
  //*****************************

  private readonly config: AppConfig;
  private readonly fromValue: string;
  private readonly transport: Transporter<SMTPTransport.SentMessageInfo>;

  //#endregion
  //*****************************

  //*****************************
  //#region Constructor
  //*****************************

  constructor() {
    this.config = getConfig();

    this.fromValue = this.config.mail.from;
    this.transport = createTransport({
      host: this.config.mail.transportOptions.host,
      port: this.config.mail.transportOptions.port,
      auth: {
        user: this.config.mail.transportOptions.auth.user,
        pass: this.config.mail.transportOptions.auth.pass,
      },
    });
  }

  //#endregion
  //*****************************

  //*****************************
  //#region Public Methods
  //*****************************

  /**
   * Function to send an email.
   *
   * @param {MailOptions} options - Options for the email.
   * @return {*}  {Promise<string>} - The response from the email server.
   * @memberof MailService
   */
  public async send(options: MailOptions): Promise<string> {
    if (!options.from) {
      options.from = this.fromValue;
    }
    const result = await this.transport.sendMail(options);
    return result.response;
  }

  /**
   * Function to send a verification email.
   *
   * @param {string} to - The email address to send the verification email to.
   * @param {string} token - The token to include in the verification email.
   * @return {*}  {Promise<string>} - The response from the email server.
   * @memberof MailService
   */
  public async sendVerificationEmail(to: string, token: string): Promise<string> {
    // TODO: Change this to HTTPS when we have SSL set up
    const url = `http://${this.config.service.serviceUrl}/${AuthRoutes.VERIFY_EMAIL}?token=${token}`;
    const mailOptions: MailOptions = {
      to,
      subject: 'Please verify your email address',
      text: `Please verify your email address by clicking on the following link: ${url}`,
      html: `<p>Dear User,</p><p>Please verify your email address by clicking on the following link:</p><a href="${url}">Verify Email</a>`,
    };
    return await this.send(mailOptions);
  }

  /**
   * Function to send a 2FA email.
   *
   * @param {string} to The email address to send the 2FA email to.
   * @param {string} code The 2FA code to include in the email.
   * @return {*}  {Promise<string>}
   * @memberof MailService
   */
  public async send2FAEmail(to: string, code: string): Promise<string> {
    const mailOptions: MailOptions = {
      to,
      subject: `${this.config.service.app_name} Verification Code`,
      text: `Your verification code is : ${code}`,
      html: `<p>Dear User,</p><p>Your verification code is : <strong>${code}</strong></p>`,
    };
    return await this.send(mailOptions);
  }

  //#endregion
  //*****************************
}
