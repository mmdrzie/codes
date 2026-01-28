import { z } from 'zod';

// Profile information types
export interface UserProfile {
  id: string;
  displayName: string;
  username?: string;
  email: string;
  emailVerified: boolean;
  avatarUrl?: string;
  createdAt: Date;
  lastLoginAt?: Date;
  lastLoginIp?: string;
  lastLoginDevice?: string;
}

// Schema for updating profile information
export const profileUpdateSchema = z.object({
  displayName: z.string()
    .min(2, 'Display name must be at least 2 characters')
    .max(50, 'Display name must be less than 50 characters')
    .trim(),
  username: z.string()
    .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores')
    .min(3, 'Username must be at least 3 characters')
    .max(30, 'Username must be less than 30 characters')
    .optional()
    .or(z.literal('')),
  email: z.string().email('Invalid email address'),
});

// Schema for changing password
export const passwordChangeSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z.string()
    .min(12, 'New password must be at least 12 characters')
    .regex(/[A-Z]/, 'New password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'New password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'New password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'New password must contain at least one special character'),
  confirmPassword: z.string().min(1, 'Please confirm your new password'),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

// Schema for email verification
export const emailVerificationSchema = z.object({
  email: z.string().email('Invalid email address'),
});

// Schema for 2FA setup
export const twoFactorSetupSchema = z.object({
  code: z.string().length(6, 'Code must be 6 digits'),
});

// Schema for notification preferences
export const notificationPreferencesSchema = z.object({
  systemNotifications: z.boolean(),
  securityAlerts: z.boolean(),
  productUpdates: z.boolean(),
  tradingSignals: z.boolean(),
  emailNotifications: z.boolean(),
  pushNotifications: z.boolean(),
  smsNotifications: z.boolean(),
});

// Schema for account preferences
export const accountPreferencesSchema = z.object({
  language: z.enum(['en', 'fa', 'ar', 'de', 'fr', 'es', 'zh', 'ja']),
  timezone: z.string(),
  dateFormat: z.enum(['MM/DD/YYYY', 'DD/MM/YYYY', 'YYYY-MM-DD']),
  timeFormat: z.enum(['12h', '24h']),
  currency: z.string(),
  numberFormat: z.enum(['comma', 'space', 'period']),
  theme: z.enum(['dark']).default('dark'), // Only dark theme for now
});

// Schema for profile image upload
export const profileImageUploadSchema = z.object({
  file: z.instanceof(File)
    .refine(file => ['image/jpeg', 'image/png', 'image/webp'].includes(file.type), {
      message: 'File must be a JPEG, PNG, or WEBP image'
    })
    .refine(file => file.size <= 5 * 1024 * 1024, {
      message: 'File size must be less than 5MB'
    }),
});

// Session types
export interface SessionInfo {
  id: string;
  device: string;
  browser: string;
  os: string;
  ip: string;
  location: string;
  lastActive: Date;
  isActive: boolean;
  isCurrent: boolean;
}

// API Key types
export interface ApiKey {
  id: string;
  name: string;
  keyPrefix: string; // First few characters of the key for display
  createdAt: Date;
  lastUsedAt?: Date;
  permissions: string[];
  isActive: boolean;
}

// Account deletion confirmation
export const accountDeletionSchema = z.object({
  confirmationText: z.literal('DELETE MY ACCOUNT', {
    errorMap: () => ({ message: 'Please type DELETE MY ACCOUNT to confirm' })
  }),
  password: z.string().min(1, 'Password is required for account deletion'),
});