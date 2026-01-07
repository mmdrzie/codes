// src/lib/validation.ts
import { z } from 'zod/v4'; // named import

const PASSWORD_MIN = 12;
const PASSWORD_MAX = 128;
const EMAIL_MAX = 255;

const COMMON_PASSWORDS = new Set(['password', '123456', '123456789', 'qwerty', 'admin']);

function isStrongPassword(password: string): boolean {
  if (COMMON_PASSWORDS.has(password.toLowerCase())) return false;
  return /[a-z]/.test(password) && /[A-Z]/.test(password) && /\d/.test(password) && /[^A-Za-z0-9]/.test(password);
}

const DISPOSABLE_DOMAINS = new Set([
  'tempmail.com', '10minutemail.com', 'guerrillamail.com', 'guerrillamail.net',
  'mailinator.com', 'throwaway.email',
]);

function isNotDisposableEmail(email: string): boolean {
  const domain = email.split('@')[1]?.toLowerCase();
  return !!domain && !DISPOSABLE_DOMAINS.has(domain);
}

const emailSchema = z.email().max(EMAIL_MAX).trim().toLowerCase().refine(isNotDisposableEmail, { message: 'Disposable email addresses are not allowed' });

const passwordSchema = z.string().min(PASSWORD_MIN).max(PASSWORD_MAX).refine(isStrongPassword, {
  message: 'Password must contain uppercase, lowercase, number and special character',
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1),
});

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  confirmPassword: z.string(),
}).refine((data: any) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
});

export const walletAuthSchema = z.object({
  address: z.string().regex(/^0x[a-fA-F0-9]{40}$/).transform((v: string) => v.toLowerCase()),
  signature: z.string().min(10),
  nonce: z.string().min(16),
  message: z.string().min(10).optional(),
});

export const passwordResetRequestSchema = z.object({
  email: emailSchema,
});

export const passwordResetSchema = z.object({
  token: z.string().min(20),
  password: passwordSchema,
  confirmPassword: z.string(),
}).refine((data: any) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: passwordSchema,
  confirmPassword: z.string(),
}).refine((data: any) => data.newPassword === data.confirmPassword, {
  message: "Passwords don't match",
  path: ['confirmPassword'],
}).refine((data: any) => data.currentPassword !== data.newPassword, {
  message: 'New password must be different from current password',
  path: ['newPassword'],
});

export function validateAndParse<T>(schema: z.ZodSchema<T>, data: unknown) {
  const result = schema.safeParse(data);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return {
    success: false,
    errors: result.error.issues.map((issue: any) => `${issue.path.join('.')}: ${issue.message}`),
  };
}

export type LoginInput = z.infer<typeof loginSchema>;
export type RegisterInput = z.infer<typeof registerSchema>;
export type WalletAuthInput = z.infer<typeof walletAuthSchema>;
export type PasswordResetRequestInput = z.infer<typeof passwordResetRequestSchema>;
export type PasswordResetInput = z.infer<typeof passwordResetSchema>;
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;