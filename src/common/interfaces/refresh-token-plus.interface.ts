import { Tokens } from '../types/global-types';

export interface RefreshTokensPlusResponseOptions {
  message: string;
  success?: boolean;
  tokens?: Tokens;
}
