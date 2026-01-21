import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

let secretsManagerClient: SecretsManagerClient | null = null;

export async function initializeSecretsManager() {
  if (process.env.AWS_REGION) {
    secretsManagerClient = new SecretsManagerClient({
      region: process.env.AWS_REGION
    });
  }
}

export async function getSecret(secretName: string): Promise<string> {
  if (!secretsManagerClient) {
    // Fallback to environment variable if no secrets manager
    const envValue = process.env[secretName];
    if (!envValue) {
      throw new Error(`Secret ${secretName} not found`);
    }
    return envValue;
  }

  try {
    const command = new GetSecretValueCommand({
      SecretId: secretName
    });
    
    const response = await secretsManagerClient.send(command);
    return response.SecretString || '';
  } catch (error) {
    console.error(`Failed to retrieve secret ${secretName}:`, error);
    throw error;
  }
}