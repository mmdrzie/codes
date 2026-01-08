// src/lib/validation.ts
import { z } from 'zod';

const PASSWORD_MIN = 12;
const PASSWORD_MAX = 128;
const EMAIL_MAX = 255;

const COMMON_PASSWORDS = new Set(['password', '123456', '123456789', 'qwerty', 'admin', 'letmein', 'welcome', 'monkey', '1234567890']);

function isStrongPassword(password: string): boolean {
  if (COMMON_PASSWORDS.has(password.toLowerCase())) return false;
  return /[a-z]/.test(password) && /[A-Z]/.test(password) && /\d/.test(password) && /[^A-Za-z0-9]/.test(password);
}

const DISPOSABLE_DOMAINS = new Set([
  'tempmail.com', '10minutemail.com', 'guerrillamail.com', 'guerrillamail.net',
  'mailinator.com', 'throwaway.email', 'yopmail.com', 'sharklasers.com', 'trashmail.com'
]);

function isNotDisposableEmail(email: string): boolean {
  const domain = email.split('@')[1]?.toLowerCase();
  return !!domain && !DISPOSABLE_DOMAINS.has(domain);
}

// Email schema with strict validation
const emailSchema = z.string()
  .email({ message: 'Invalid email format' })
  .max(EMAIL_MAX, { message: 'Email too long' })
  .transform((v: string) => v.trim().toLowerCase())
  .refine(isNotDisposableEmail, { message: 'Disposable email addresses are not allowed' });

// Password schema with strict validation
const passwordSchema = z.string()
  .min(PASSWORD_MIN, { message: `Password must be at least ${PASSWORD_MIN} characters` })
  .max(PASSWORD_MAX, { message: `Password must be no more than ${PASSWORD_MAX} characters` })
  .refine(isStrongPassword, {
    message: 'Password must contain uppercase, lowercase, number and special character',
  });

// Login schema with strict validation
export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, { message: 'Password is required' }),
}).strict(); // Strict mode rejects unknown fields

// Registration schema with strict validation
export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  confirmPassword: z.string(),
}).strict() // Reject unknown fields
.refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
});

// Wallet authentication schema with strict validation
export const walletAuthSchema = z.object({
  address: z.string()
    .regex(/^0x[a-fA-F0-9]{40}$/, { message: 'Invalid Ethereum address format' })
    .transform((v: string) => v.toLowerCase()),
  signature: z.string()
    .min(10, { message: 'Signature is required and must be at least 10 characters' }),
  nonce: z.string()
    .min(16, { message: 'Nonce must be at least 16 characters' })
    .max(128, { message: 'Nonce too long' }),
  message: z.string()
    .min(10, { message: 'Message must be at least 10 characters' })
    .max(2048, { message: 'Message too long' })
    .optional(),
}).strict(); // Reject unknown fields

// Password reset request schema
export const passwordResetRequestSchema = z.object({
  email: emailSchema,
}).strict(); // Reject unknown fields

// Password reset schema
export const passwordResetSchema = z.object({
  token: z.string()
    .min(20, { message: 'Token must be at least 20 characters' })
    .max(512, { message: 'Token too long' }),
  password: passwordSchema,
  confirmPassword: z.string(),
}).strict() // Reject unknown fields
.refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
});

// Change password schema
export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, { message: 'Current password is required' }),
  newPassword: passwordSchema,
  confirmPassword: z.string(),
}).strict() // Reject unknown fields
.refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
})
.refine((data) => data.currentPassword !== data.newPassword, {
  message: 'New password must be different from current password',
  path: ['newPassword'],
});

// Tenant schema for multi-tenant applications
export const tenantSchema = z.object({
  tenantId: z.string()
    .min(3, { message: 'Tenant ID must be at least 3 characters' })
    .max(50, { message: 'Tenant ID must be no more than 50 characters' })
    .regex(/^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$/, { 
      message: 'Tenant ID must be alphanumeric with hyphens/underscores, starting and ending with alphanumeric' 
    }),
  name: z.string()
    .min(1, { message: 'Tenant name is required' })
    .max(100, { message: 'Tenant name must be no more than 100 characters' }),
  plan: z.enum(['free', 'pro', 'enterprise'], {
    errorMap: () => ({ message: 'Invalid subscription plan' })
  }).default('free'),
}).strict(); // Reject unknown fields

// API request schema for general use
export const apiRequestSchema = z.object({
  action: z.string()
    .min(1, { message: 'Action is required' })
    .max(100, { message: 'Action too long' }),
  data: z.record(z.unknown()).optional(), // Allow flexible data structure but validate it
  timestamp: z.number()
    .gte(Date.now() - 5 * 60 * 1000, { message: 'Request timestamp too old (max 5 minutes)' }) // 5 min window
    .lte(Date.now() + 5 * 60 * 1000, { message: 'Request timestamp in future' }),
}).strict(); // Reject unknown fields

// Rate limiting schema
export const rateLimitSchema = z.object({
  identifier: z.string()
    .min(1, { message: 'Identifier is required' })
    .max(255, { message: 'Identifier too long' }),
  action: z.string()
    .min(1, { message: 'Action is required' })
    .max(100, { message: 'Action too long' }),
  windowMs: z.number()
    .gte(1000, { message: 'Window must be at least 1 second' })
    .lte(3600000, { message: 'Window must be no more than 1 hour' }),
}).strict(); // Reject unknown fields

// SIWE (Sign-In With Ethereum) message schema
export const siweMessageSchema = z.object({
  domain: z.string()
    .min(1, { message: 'Domain is required' })
    .max(100, { message: 'Domain too long' })
    .regex(/^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/, { 
      message: 'Invalid domain format' 
    }),
  address: z.string()
    .regex(/^0x[a-fA-F0-9]{40}$/, { message: 'Invalid Ethereum address format' }),
  statement: z.string()
    .max(1000, { message: 'Statement too long' })
    .optional(),
  uri: z.string()
    .url({ message: 'URI must be a valid URL' }),
  version: z.literal('1'),
  chainId: z.number()
    .int({ message: 'Chain ID must be an integer' })
    .gte(1, { message: 'Chain ID must be positive' })
    .lte(999999999, { message: 'Chain ID too large' }),
  nonce: z.string()
    .min(8, { message: 'Nonce must be at least 8 characters' })
    .max(64, { message: 'Nonce too long' }),
  issuedAt: z.string()
    .datetime({ message: 'Invalid datetime format' }),
  expirationTime: z.string()
    .datetime({ message: 'Invalid datetime format' })
    .optional(),
  notBefore: z.string()
    .datetime({ message: 'Invalid datetime format' })
    .optional(),
  requestId: z.string()
    .max(255, { message: 'Request ID too long' })
    .optional(),
  resources: z.array(z.string().url()).max(10).optional(),
}).strict(); // Reject unknown fields

/**
 * Generic validation function with strict error handling
 */
export function validateAndParse<T extends z.ZodRawShape>(
  schema: z.ZodObject<T>, 
  data: unknown
): { success: true; data: z.infer<typeof schema> } | { success: false; errors: string[] } {
  const result = schema.safeParse(data);
  
  if (result.success) {
    return { success: true, data: result.data };
  }
  
  // Format errors in a user-friendly way
  const errors = result.error.issues.map((issue) => {
    // Format the error path as a dot-separated string
    const path = issue.path.join('.');
    return `${path}: ${issue.message}`;
  });
  
  return { success: false, errors };
}

/**
 * Validate any data against a schema with strict unknown field rejection
 */
export function strictValidate<T extends z.ZodRawShape>(
  schema: z.ZodObject<T>, 
  data: unknown
): { valid: boolean; data?: z.infer<typeof schema>; errors?: string[] } {
  try {
    // First check if data is an object
    if (!data || typeof data !== 'object') {
      return { valid: false, errors: ['Data must be an object'] };
    }
    
    // Check for unknown fields manually before parsing
    const schemaKeys = Object.keys(schema.shape);
    const dataKeys = Object.keys(data);
    const unknownKeys = dataKeys.filter(key => !schemaKeys.includes(key));
    
    if (unknownKeys.length > 0) {
      return { 
        valid: false, 
        errors: [`Unknown fields: ${unknownKeys.join(', ')}`] 
      };
    }
    
    // Parse with strict validation
    const parsed = schema.parse(data);
    return { valid: true, data: parsed };
  } catch (error: any) {
    if (error instanceof z.ZodError) {
      const errors = error.issues.map(issue => `${issue.path.join('.')}: ${issue.message}`);
      return { valid: false, errors };
    }
    return { valid: false, errors: [error.message || 'Validation error occurred'] };
  }
}

// Export types for TypeScript
export type LoginInput = z.infer<typeof loginSchema>;
export type RegisterInput = z.infer<typeof registerSchema>;
export type WalletAuthInput = z.infer<typeof walletAuthSchema>;
export type PasswordResetRequestInput = z.infer<typeof passwordResetRequestSchema>;
export type PasswordResetInput = z.infer<typeof passwordResetSchema>;
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
export type TenantInput = z.infer<typeof tenantSchema>;
export type ApiRequestInput = z.infer<typeof apiRequestSchema>;
export type SiweMessageInput = z.infer<typeof siweMessageSchema>;