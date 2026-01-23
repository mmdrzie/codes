import { z } from 'zod';

// Common validation patterns
const patterns = {
  email: /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
  phone: /^\+?[1-9]\d{1,14}$/, // E.164 format
  password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
  accountNumber: /^\d{8,12}$/, // 8-12 digits
  routingNumber: /^\d{9}$/, // 9 digits
  ssn: /^\d{3}-?\d{2}-?\d{4}$/, // XXX-XX-XXXX
  zipCode: /^\d{5}(?:-\d{4})?$/, // 5 digits or 5-4 format
  currencyCode: /^[A-Z]{3}$/, // ISO 4217
  countryCode: /^[A-Z]{2}$/, // ISO 3166-1 alpha-2
  iban: /^[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]{3})?$/, // IBAN format
  swift: /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/ // SWIFT code
};

// Custom validators
const customValidators = {
  strongPassword: (val: string) => patterns.password.test(val),
  validEmail: (val: string) => patterns.email.test(val),
  validAccountNumber: (val: string) => patterns.accountNumber.test(val),
  validRoutingNumber: (val: string) => patterns.routingNumber.test(val),
  validSSN: (val: string) => patterns.ssn.test(val),
  validPhone: (val: string) => patterns.phone.test(val),
  validCurrencyCode: (val: string) => patterns.currencyCode.test(val),
  validCountryCode: (val: string) => patterns.countryCode.test(val),
  validIBAN: (val: string) => patterns.iban.test(val),
  validSWIFT: (val: string) => patterns.swift.test(val)
};

// Login Schema
export const LoginSchema = z.object({
  email: z.string()
    .min(1, 'Email is required')
    .max(255, 'Email must be less than 255 characters')
    .refine(customValidators.validEmail, 'Invalid email format'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must be less than 128 characters')
    .refine(customValidators.strongPassword, 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
});

// Registration Schema
export const RegisterSchema = z.object({
  firstName: z.string()
    .min(1, 'First name is required')
    .max(50, 'First name must be less than 50 characters')
    .regex(/^[a-zA-Z\s'-]+$/, 'First name can only contain letters, spaces, hyphens, and apostrophes'),
  lastName: z.string()
    .min(1, 'Last name is required')
    .max(50, 'Last name must be less than 50 characters')
    .regex(/^[a-zA-Z\s'-]+$/, 'Last name can only contain letters, spaces, hyphens, and apostrophes'),
  email: z.string()
    .min(1, 'Email is required')
    .max(255, 'Email must be less than 255 characters')
    .refine(customValidators.validEmail, 'Invalid email format')
    .toLowerCase(),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must be less than 128 characters')
    .refine(customValidators.strongPassword, 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  confirmPassword: z.string()
    .min(1, 'Confirm password is required'),
  phoneNumber: z.string()
    .min(10, 'Phone number must be at least 10 digits')
    .max(15, 'Phone number must be less than 15 characters')
    .refine(customValidators.validPhone, 'Invalid phone number format'),
  dateOfBirth: z.string()
    .refine((val) => {
      const date = new Date(val);
      const today = new Date();
      const minAgeDate = new Date(today.getFullYear() - 18, today.getMonth(), today.getDate());
      return date <= minAgeDate;
    }, 'Must be at least 18 years old'),
  address: z.object({
    street: z.string().min(1, 'Street address is required').max(255),
    city: z.string().min(1, 'City is required').max(100),
    state: z.string().min(2, 'State is required').max(100),
    zipCode: z.string()
      .min(5, 'ZIP code is required')
      .max(10, 'ZIP code is too long')
      .refine((val) => patterns.zipCode.test(val), 'Invalid ZIP code format'),
    country: z.string()
      .min(2, 'Country is required')
      .max(2, 'Country code must be 2 characters')
      .refine(customValidators.validCountryCode, 'Invalid country code')
  }),
  ssn: z.string()
    .min(9, 'SSN must be 9 digits')
    .max(11, 'SSN format is invalid')
    .refine(customValidators.validSSN, 'Invalid SSN format')
}).refine((data) => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword']
});

// Transaction Schema
export const TransactionSchema = z.object({
  fromAccount: z.string()
    .min(8, 'Account number must be at least 8 digits')
    .max(12, 'Account number must be no more than 12 digits')
    .refine(customValidators.validAccountNumber, 'Invalid account number format'),
  toAccount: z.string()
    .min(8, 'Account number must be at least 8 digits')
    .max(12, 'Account number must be no more than 12 digits')
    .refine(customValidators.validAccountNumber, 'Invalid account number format'),
  amount: z.number()
    .positive('Amount must be greater than zero')
    .max(1000000, 'Transaction amount exceeds limit'), // $1M limit
  currency: z.string()
    .min(3, 'Currency code must be 3 characters')
    .max(3, 'Currency code must be 3 characters')
    .refine(customValidators.validCurrencyCode, 'Invalid currency code'),
  description: z.string()
    .max(255, 'Description must be less than 255 characters')
    .optional()
    .transform((val) => val?.trim()),
  transactionType: z.enum(['transfer', 'deposit', 'withdrawal', 'payment']),
  iban: z.string()
    .optional()
    .refine((val) => !val || customValidators.validIBAN(val), 'Invalid IBAN format'),
  swiftCode: z.string()
    .optional()
    .refine((val) => !val || customValidators.validSWIFT(val), 'Invalid SWIFT code format')
});

// Profile Update Schema
export const ProfileUpdateSchema = z.object({
  firstName: z.string()
    .min(1, 'First name is required')
    .max(50, 'First name must be less than 50 characters')
    .regex(/^[a-zA-Z\s'-]+$/, 'First name can only contain letters, spaces, hyphens, and apostrophes')
    .optional(),
  lastName: z.string()
    .min(1, 'Last name is required')
    .max(50, 'Last name must be less than 50 characters')
    .regex(/^[a-zA-Z\s'-]+$/, 'Last name can only contain letters, spaces, hyphens, and apostrophes')
    .optional(),
  email: z.string()
    .min(1, 'Email is required')
    .max(255, 'Email must be less than 255 characters')
    .refine(customValidators.validEmail, 'Invalid email format')
    .toLowerCase()
    .optional(),
  phoneNumber: z.string()
    .min(10, 'Phone number must be at least 10 digits')
    .max(15, 'Phone number must be less than 15 characters')
    .refine(customValidators.validPhone, 'Invalid phone number format')
    .optional(),
  address: z.object({
    street: z.string().min(1, 'Street address is required').max(255).optional(),
    city: z.string().min(1, 'City is required').max(100).optional(),
    state: z.string().min(2, 'State is required').max(100).optional(),
    zipCode: z.string()
      .min(5, 'ZIP code is required')
      .max(10, 'ZIP code is too long')
      .refine((val) => !val || patterns.zipCode.test(val), 'Invalid ZIP code format')
      .optional(),
    country: z.string()
      .min(2, 'Country is required')
      .max(2, 'Country code must be 2 characters')
      .refine(customValidators.validCountryCode, 'Invalid country code')
      .optional()
  }).optional()
});

// Password Reset Schema
export const PasswordResetSchema = z.object({
  email: z.string()
    .min(1, 'Email is required')
    .max(255, 'Email must be less than 255 characters')
    .refine(customValidators.validEmail, 'Invalid email format'),
  resetToken: z.string()
    .min(1, 'Reset token is required')
    .max(255, 'Reset token is too long'),
  newPassword: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must be less than 128 characters')
    .refine(customValidators.strongPassword, 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  confirmNewPassword: z.string()
    .min(1, 'Confirm password is required')
}).refine((data) => data.newPassword === data.confirmNewPassword, {
  message: 'Passwords do not match',
  path: ['confirmNewPassword']
});

// MFA Schema
export const MFASchema = z.object({
  userId: z.string().min(1, 'User ID is required'),
  mfaCode: z.string()
    .min(6, 'MFA code must be 6 digits')
    .max(6, 'MFA code must be 6 digits')
    .regex(/^\d{6}$/, 'MFA code must be 6 digits'),
  mfaType: z.enum(['totp', 'sms', 'email'])
});

// Admin Action Schema
export const AdminActionSchema = z.object({
  action: z.enum([
    'suspend_account', 
    'activate_account', 
    'freeze_funds', 
    'unfreeze_funds',
    'reset_mfa',
    'revoke_session',
    'generate_report'
  ]),
  targetUserId: z.string().min(1, 'Target user ID is required'),
  reason: z.string().min(1, 'Reason is required').max(500),
  metadata: z.record(z.any()).optional()
});

// Business Rules Validation
export const BusinessRuleSchema = z.object({
  accountNumber: z.string()
    .min(8, 'Account number must be at least 8 digits')
    .max(12, 'Account number must be no more than 12 digits')
    .refine(customValidators.validAccountNumber, 'Invalid account number format'),
  amount: z.number()
    .positive('Amount must be greater than zero'),
  dailyLimit: z.number().optional(),
  monthlyLimit: z.number().optional(),
  transactionCount: z.number().optional()
});

// File Upload Schema
export const FileUploadSchema = z.object({
  fileName: z.string().min(1, 'File name is required').max(255),
  fileType: z.string().refine(val => 
    ['image/jpeg', 'image/png', 'application/pdf', 'image/jpg'].includes(val),
    'Only JPEG, PNG, and PDF files are allowed'
  ),
  fileSize: z.number().max(5 * 1024 * 1024, 'File size must be less than 5MB'), // 5MB limit
  checksum: z.string().length(64, 'SHA-256 checksum must be 64 characters') // SHA-256 hash
});

// API Key Schema
export const APIKeySchema = z.object({
  name: z.string().min(1, 'API key name is required').max(100),
  permissions: z.array(z.enum(['read', 'write', 'admin'])).min(1, 'At least one permission is required'),
  expiresAt: z.string().datetime(),
  rateLimit: z.number().positive('Rate limit must be positive')
});

// Export all schemas
export const Schemas = {
  Login: LoginSchema,
  Register: RegisterSchema,
  Transaction: TransactionSchema,
  ProfileUpdate: ProfileUpdateSchema,
  PasswordReset: PasswordResetSchema,
  MFA: MFASchema,
  AdminAction: AdminActionSchema,
  BusinessRule: BusinessRuleSchema,
  FileUpload: FileUploadSchema,
  APIKey: APIKeySchema
};

// Helper function to validate data against a schema
export function validateSchema<T extends z.ZodSchema>(
  schema: T,
  data: unknown
): z.infer<T> {
  try {
    return schema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new Error(`Validation failed: ${error.errors.map(e => e.message).join(', ')}`);
    }
    throw error;
  }
}

// Helper function to safely parse data (returns result object instead of throwing)
export function safeParseSchema<T extends z.ZodSchema>(
  schema: T,
  data: unknown
): { success: boolean; data?: z.infer<T>; error?: string } {
  try {
    const parsed = schema.parse(data);
    return { success: true, data: parsed };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return { 
        success: false, 
        error: error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join(', ') 
      };
    }
    return { success: false, error: 'Unexpected validation error' };
  }
}