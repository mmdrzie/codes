import { z } from 'zod';

// Enhanced validation with allow-lists and comprehensive input validation
const COMMON_PASSWORDS = new Set([
  'password', '123456', '123456789', 'qwerty', 'admin', 'letmein', 'welcome', 
  'monkey', '1234567890', 'password123', 'admin123', 'letmein123'
]);

const DISPOSABLE_DOMAINS = new Set([
  'tempmail.com', '10minutemail.com', 'guerrillamail.com', 'guerrillamail.net',
  'mailinator.com', 'throwaway.email', 'yopmail.com', 'sharklasers.com', 'trashmail.com'
]);

// Sanitization function to prevent injection attacks
function sanitizeInput(input: string): string {
  // Remove potentially dangerous characters while preserving legitimate ones
  return input
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
    .replace(/javascript:/gi, '') // Remove javascript protocol
    .replace(/on\w+\s*=/gi, '') // Remove event handlers
    .replace(/data:/gi, '') // Remove data URIs
    .trim();
}

// Strong password validation
function isStrongPassword(password: string): boolean {
  if (COMMON_PASSWORDS.has(password.toLowerCase())) return false;
  return /[a-z]/.test(password) && 
         /[A-Z]/.test(password) && 
         /\d/.test(password) && 
         /[^A-Za-z0-9]/.test(password) &&
         password.length >= 12; // Minimum 12 characters
}

// Disposable email validation
function isNotDisposableEmail(email: string): boolean {
  const domain = email.split('@')[1]?.toLowerCase();
  return !!domain && !DISPOSABLE_DOMAINS.has(domain);
}

// Whitelist of valid country codes
const VALID_COUNTRY_CODES = new Set([
  'US', 'CA', 'GB', 'DE', 'FR', 'JP', 'AU', 'IN', 'BR', 'CN', 'RU', 'MX', 'IT', 'ES', 'NL'
]);

// Enhanced email schema with strict validation
export const emailSchema = z.string()
  .email({ message: 'Invalid email format' })
  .max(255, { message: 'Email too long' })
  .transform((v: string) => {
    const sanitized = sanitizeInput(v);
    return sanitized.trim().toLowerCase();
  })
  .refine(isNotDisposableEmail, { message: 'Disposable email addresses are not allowed' });

// Enhanced password schema with strict validation
export const passwordSchema = z.string()
  .min(12, { message: 'Password must be at least 12 characters' })
  .max(128, { message: 'Password must be no more than 128 characters' })
  .refine(isStrongPassword, {
    message: 'Password must contain uppercase, lowercase, number, special character, and be at least 12 characters'
  });

// Whitelist of valid action types for API requests
const VALID_API_ACTIONS = new Set([
  'transfer', 'deposit', 'withdraw', 'balance', 'transaction_history', 'profile_update', 'settings_change'
]);

// Enhanced API request schema with allow-list validation
export const apiRequestSchema = z.object({
  action: z.string()
    .min(1, { message: 'Action is required' })
    .max(100, { message: 'Action too long' })
    .refine(val => VALID_API_ACTIONS.has(val), { 
      message: `Invalid action. Valid actions are: ${Array.from(VALID_API_ACTIONS).join(', ')}` 
    }),
  data: z.record(z.unknown()).optional(), // Allow flexible data structure but validate it
  timestamp: z.number()
    .gte(Date.now() - 5 * 60 * 1000, { message: 'Request timestamp too old (max 5 minutes)' }) // 5 min window
    .lte(Date.now() + 5 * 60 * 1000, { message: 'Request timestamp in future' }),
  // Add signature for request authenticity
  signature: z.string().optional()
}).strict(); // Reject unknown fields

// Enhanced login schema with strict validation
export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, { message: 'Password is required' }),
}).strict(); // Strict mode rejects unknown fields

// Enhanced registration schema with strict validation
export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  confirmPassword: z.string(),
  firstName: z.string()
    .min(1, { message: 'First name is required' })
    .max(50, { message: 'First name too long' })
    .regex(/^[a-zA-Z\s\-']+$/, { message: 'First name contains invalid characters' }),
  lastName: z.string()
    .min(1, { message: 'Last name is required' })
    .max(50, { message: 'Last name too long' })
    .regex(/^[a-zA-Z\s\-']+$/, { message: 'Last name contains invalid characters' }),
  country: z.string()
    .length(2, { message: 'Country code must be 2 letters' })
    .refine(code => VALID_COUNTRY_CODES.has(code.toUpperCase()), { 
      message: `Invalid country code. Valid codes are: ${Array.from(VALID_COUNTRY_CODES).join(', ')}` 
    }),
}).strict() // Reject unknown fields
.refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
});

// Enhanced wallet authentication schema with strict validation
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
    .transform(sanitizeInput) // Sanitize message to prevent injection
    .optional(),
}).strict(); // Reject unknown fields

// Enhanced password reset request schema
export const passwordResetRequestSchema = z.object({
  email: emailSchema,
}).strict(); // Reject unknown fields

// Enhanced password reset schema
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

// Enhanced change password schema
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

// Enhanced tenant schema for multi-tenant applications
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

// Enhanced SIWE (Sign-In With Ethereum) message schema with allow-list validation
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
    .transform(sanitizeInput) // Sanitize to prevent injection
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

// Transaction-specific validation schemas
const VALID_TRANSACTION_TYPES = new Set(['transfer', 'payment', 'withdrawal', 'deposit']);
const VALID_CURRENCIES = new Set(['USD', 'EUR', 'GBP', 'BTC', 'ETH', 'USDC', 'USDT']);

export const transactionSchema = z.object({
  type: z.string()
    .refine(val => VALID_TRANSACTION_TYPES.has(val), { 
      message: `Invalid transaction type. Valid types are: ${Array.from(VALID_TRANSACTION_TYPES).join(', ')}` 
    }),
  amount: z.number()
    .positive({ message: 'Amount must be positive' })
    .max(10000000, { message: 'Transaction amount too large' }), // Max $10M equivalent
  currency: z.string()
    .refine(val => VALID_CURRENCIES.has(val.toUpperCase()), { 
      message: `Invalid currency. Valid currencies are: ${Array.from(VALID_CURRENCIES).join(', ')}` 
    }),
  recipient: z.string()
    .min(5, { message: 'Recipient address too short' })
    .max(100, { message: 'Recipient address too long' }),
  description: z.string()
    .max(500, { message: 'Description too long' })
    .transform(sanitizeInput) // Sanitize description
    .optional(),
}).strict();

// Generic validation function with strict error handling and sanitization
export function validateAndParse<T extends z.ZodRawShape>(
  schema: z.ZodObject<T>, 
  data: unknown
): { success: true; data: z.infer<typeof schema> } | { success: false; errors: string[] } {
  // Deep clone and sanitize the data before validation
  const sanitizedData = JSON.parse(JSON.stringify(data), (key, value) => {
    if (typeof value === 'string') {
      return sanitizeInput(value);
    }
    return value;
  });
  
  const result = schema.safeParse(sanitizedData);
  
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

// Enhanced validation function with allow-lists
export function strictValidateWithAllowLists<T extends z.ZodRawShape>(
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
    
    // Deep clone and sanitize the data before validation
    const sanitizedData = JSON.parse(JSON.stringify(data), (key, value) => {
      if (typeof value === 'string') {
        return sanitizeInput(value);
      }
      return value;
    });
    
    // Parse with strict validation
    const parsed = schema.parse(sanitizedData);
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
export type TransactionInput = z.infer<typeof transactionSchema>;