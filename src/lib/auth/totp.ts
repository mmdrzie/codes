import crypto from 'crypto';
import { authenticator } from 'otplib';

// Configure otplib for our needs
authenticator.options = {
  digits: 6,
  algorithm: 'sha1',
  period: 30, // 30 seconds validity window
};

export interface TotpVerificationResult {
  isValid: boolean;
  delta: number; // Time drift in periods
}

export interface TotpSetupResult {
  secret: string;
  qrCodeUrl: string;
  backupCodes: string[];
}

export class TotpService {
  /**
   * Generate a new TOTP secret
   */
  public static generateSecret(): string {
    // Generate a random base32 encoded secret
    return authenticator.generateSecret();
  }

  /**
   * Generate QR code URL for authenticator app setup
   */
  public static generateQrCodeUrl(accountName: string, issuer: string, secret: string): string {
    return authenticator.keyuri(accountName, issuer, secret);
  }

  /**
   * Verify a TOTP code
   */
  public static verifyTotp(token: string, secret: string, window: number = 1): TotpVerificationResult {
    try {
      // Verify the token allowing for time drift
      const isValid = authenticator.check(token, secret, { window });
      const delta = authenticator.delta(token, secret);
      
      return {
        isValid,
        delta: delta || 0
      };
    } catch (error) {
      console.error('TOTP verification error:', error);
      return {
        isValid: false,
        delta: 0
      };
    }
  }

  /**
   * Generate backup codes for account recovery
   */
  public static generateBackupCodes(count: number = 10): string[] {
    const backupCodes: string[] = [];
    
    for (let i = 0; i < count; i++) {
      // Generate a random 10-character alphanumeric code
      const code = crypto.randomBytes(5).toString('hex').toUpperCase();
      backupCodes.push(code);
    }
    
    return backupCodes;
  }

  /**
   * Hash a backup code for secure storage
   */
  public static hashBackupCode(backupCode: string): string {
    return crypto.createHash('sha256').update(backupCode).digest('hex');
  }

  /**
   * Verify a backup code against stored hash
   */
  public static verifyBackupCode(providedCode: string, storedHash: string): boolean {
    const hashedProvided = this.hashBackupCode(providedCode);
    return hashedProvided === storedHash;
  }

  /**
   * Initialize MFA setup for a user
   */
  public static async initializeUserMfa(userId: string, accountName: string, issuer: string): Promise<TotpSetupResult> {
    const secret = this.generateSecret();
    const qrCodeUrl = this.generateQrCodeUrl(accountName, issuer, secret);
    const backupCodes = this.generateBackupCodes(10);
    
    return {
      secret,
      qrCodeUrl,
      backupCodes
    };
  }

  /**
   * Validate initial TOTP setup (verify the code user enters after scanning QR)
   */
  public static validateInitialSetup(token: string, secret: string): boolean {
    // Allow a small window for time drift during setup
    const result = this.verifyTotp(token, secret, 1);
    return result.isValid;
  }
}