import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoBase64URL, isoUint8Array } from '@simplewebauthn/server/helpers';
import type {
  GenerateRegistrationOptionsOpts,
  VerifyRegistrationResponseOpts,
  GenerateAuthenticationOptionsOpts,
  VerifyAuthenticationResponseOpts,
  VerifiedRegistrationResponse,
  VerifiedAuthenticationResponse,
} from '@simplewebauthn/server';

// Types for our WebAuthn service
export interface WebAuthnCredential {
  id: string;
  publicKey: string;
  counter: number;
  transports?: AuthenticatorTransport[];
  userId: string;
}

export interface RegistrationChallenge {
  challenge: string;
  userId: string;
}

export interface AuthenticationChallenge {
  challenge: string;
  credentialIds: string[];
}

export class WebAuthnService {
  private static RP_NAME = process.env.RP_NAME || 'QuantumIQ';
  private static RP_ID = process.env.RP_ID || 'localhost';
  private static ORIGIN = process.env.ORIGIN || 'http://localhost:3000';

  /**
   * Generate registration options for a new credential
   */
  public static async generateRegistrationOptions(
    userId: string,
    username: string,
    displayName: string
  ): Promise<any> {
    const options: GenerateRegistrationOptionsOpts = {
      rpName: this.RP_NAME,
      rpID: this.RP_ID,
      userID: userId,
      userName: username,
      userDisplayName: displayName,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      excludeCredentials: [],
      timeout: 60000,
    };

    const regOptions = await generateRegistrationOptions(options);
    
    // Store the challenge for later verification
    // In a real implementation, this would be stored in Redis/DB
    await this.storeChallenge(userId, regOptions.challenge, 'registration');
    
    return regOptions;
  }

  /**
   * Verify a registration response
   */
  public static async verifyRegistration(
    body: any,
    expectedChallenge: string
  ): Promise<VerifiedRegistrationResponse> {
    const options: VerifyRegistrationResponseOpts = {
      response: body,
      expectedChallenge,
      expectedOrigin: this.ORIGIN,
      expectedRPID: this.RP_ID,
    };

    const verification = await verifyRegistrationResponse(options);
    
    if (!verification.verified || !verification.registrationInfo) {
      throw new Error('Registration verification failed');
    }
    
    return verification;
  }

  /**
   * Generate authentication options for login
   */
  public static async generateAuthenticationOptions(
    userId: string,
    allowCredentials: string[]
  ): Promise<any> {
    const options: GenerateAuthenticationOptionsOpts = {
      rpID: this.RP_ID,
      timeout: 60000,
      allowCredentials: allowCredentials.map(id => ({
        id: isoBase64URL.toBuffer(id),
        type: 'public-key',
        transports: ['usb', 'ble', 'nfc', 'internal'],
      })),
      userVerification: 'preferred',
    };

    const authOptions = await generateAuthenticationOptions(options);
    
    // Store the challenge for later verification
    await this.storeChallenge(userId, authOptions.challenge, 'authentication');
    
    return authOptions;
  }

  /**
   * Verify an authentication response
   */
  public static async verifyAuthentication(
    body: any,
    expectedChallenge: string,
    credential: WebAuthnCredential
  ): Promise<VerifiedAuthenticationResponse> {
    const options: VerifyAuthenticationResponseOpts = {
      response: body,
      expectedChallenge,
      expectedOrigin: this.ORIGIN,
      expectedRPID: this.RP_ID,
      authenticator: {
        credentialID: isoBase64URL.toBuffer(credential.id),
        credentialPublicKey: isoBase64URL.toBuffer(credential.publicKey),
        counter: credential.counter,
      },
    };

    const verification = await verifyAuthenticationResponse(options);
    
    if (!verification.verified) {
      throw new Error('Authentication verification failed');
    }
    
    // Update the counter in DB
    await this.updateCounter(credential.id, verification.authenticationInfo.newCounter);
    
    return verification;
  }

  /**
   * Store challenge in session/cache for verification
   */
  private static async storeChallenge(
    userId: string,
    challenge: string,
    type: 'registration' | 'authentication'
  ): Promise<void> {
    // In a real implementation, this would store the challenge in Redis/DB
    // with expiration time
    console.log(`Storing ${type} challenge for user ${userId}: ${challenge}`);
  }

  /**
   * Update credential counter after successful authentication
   */
  private static async updateCounter(credentialId: string, newCounter: number): Promise<void> {
    // In a real implementation, this would update the counter in DB
    console.log(`Updating counter for credential ${credentialId} to ${newCounter}`);
  }

  /**
   * Format credential for storage
   */
  public static formatCredentialForStorage(
    credential: any,
    userId: string
  ): WebAuthnCredential {
    return {
      id: isoBase64URL.fromBuffer(credential.id),
      publicKey: isoBase64URL.fromBuffer(credential.publicKey),
      counter: credential.counter,
      transports: credential.transports,
      userId,
    };
  }
}