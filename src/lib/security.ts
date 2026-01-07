// src/lib/security.ts
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

// تنظیمات امنیتی
const SALT_ROUNDS = 12;
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';

// بررسی وجود کلید رمزنگاری
function getEncryptionKey(): string {
  const key = process.env.ENCRYPTION_KEY;
  
  if (!key) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('ENCRYPTION_KEY must be defined in production environment');
    }
    // در development از یک کلید پیش‌فرض استفاده می‌کنیم (فقط برای تست)
    console.warn('⚠️  ENCRYPTION_KEY not set, using default key for development');
    return 'dev-key-change-in-production-32chars-minimum';
  }
  
  if (key.length < 32) {
    throw new Error('ENCRYPTION_KEY must be at least 32 characters long');
  }
  
  return key;
}

/**
 * Hash کردن Password با bcrypt
 */
export async function hashPassword(password: string): Promise<string> {
  try {
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    const hash = await bcrypt.hash(password, salt);
    return hash;
  } catch (error) {
    console.error('Error hashing password:', error);
    throw new Error('Failed to hash password');
  }
}

/**
 * تایید Password
 */
export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  try {
    return await bcrypt.compare(password, hash);
  } catch (error) {
    console.error('Error verifying password:', error);
    return false;
  }
}

/**
 * بررسی قدرت Password
 */
export function validatePasswordStrength(password: string): {
  valid: boolean;
  errors: string[];
  strength: 'weak' | 'medium' | 'strong';
} {
  const errors: string[] = [];
  let strength: 'weak' | 'medium' | 'strong' = 'weak';

  // حداقل طول
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }

  // حداکثر طول
  if (password.length > 128) {
    errors.push('Password must not exceed 128 characters');
  }

  // حروف کوچک
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  // حروف بزرگ
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  // اعداد
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  // کاراکترهای خاص
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  // محاسبه قدرت
  if (errors.length === 0) {
    if (password.length >= 12) {
      strength = 'strong';
    } else if (password.length >= 10) {
      strength = 'medium';
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    strength
  };
}

/**
 * رمزنگاری داده
 */
export function encrypt(text: string): string {
  const ENCRYPTION_KEY = getEncryptionKey();

  try {
    const iv = crypto.randomBytes(16);
    const key = crypto.scryptSync(ENCRYPTION_KEY, 'salt', 32);
    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    // ترکیب IV + AuthTag + Encrypted Data
    return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Encryption failed');
  }
}

/**
 * رمزگشایی داده
 */
export function decrypt(encryptedText: string): string {
  const ENCRYPTION_KEY = getEncryptionKey();

  try {
    const parts = encryptedText.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format');
    }

    const [ivHex, authTagHex, encrypted] = parts;
    if (!ivHex || !authTagHex || !encrypted) {
      throw new Error('Invalid encrypted data format');
    }

    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');

    const key = crypto.scryptSync(ENCRYPTION_KEY, 'salt', 32);
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Decryption failed');
  }
}

/**
 * تولید Token تصادفی امن
 */
export function generateSecureToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Hash کردن داده با SHA-256
 */
export function sha256Hash(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Sanitize کردن Input (جلوگیری از XSS)
 */
export function sanitizeInput(input: string): string {
  return input
    .replace(/[<>]/g, '') // حذف < و >
    .replace(/javascript:/gi, '') // حذف javascript:
    .replace(/on\w+=/gi, '') // حذف event handlers
    .trim();
}

/**
 * Validate کردن Email
 */
export function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 255;
}

/**
 * Validate کردن Wallet Address
 */
export function validateWalletAddress(address: string): boolean {
  const ethereumRegex = /^0x[a-fA-F0-9]{40}$/;
  return ethereumRegex.test(address);
}

/**
 * Validate کردن URL
 */
export function validateUrl(url: string): boolean {
  try {
    const parsedUrl = new URL(url);
    return ['http:', 'https:'].includes(parsedUrl.protocol);
  } catch {
    return false;
  }
}

/**
 * تولید OTP (One Time Password)
 */
export function generateOTP(length: number = 6): string {
  const digits = '0123456789';
  let otp = '';
  
  for (let i = 0; i < length; i++) {
    const randomIndex = crypto.randomInt(0, digits.length);
    otp += digits[randomIndex];
  }
  
  return otp;
}

/**
 * Hash کردن OTP برای ذخیره امن
 */
export function hashOTP(otp: string, secret: string): string {
  if (!secret) {
    throw new Error('Secret is required for OTP hashing');
  }
  return crypto
    .createHmac('sha256', secret)
    .update(otp)
    .digest('hex');
}

/**
 * تایید OTP
 */
export function verifyOTP(otp: string, hashedOTP: string, secret: string): boolean {
  if (!secret) {
    return false;
  }
  
  try {
    const hash = hashOTP(otp, secret);
    return crypto.timingSafeEqual(
      Buffer.from(hash, 'utf8'),
      Buffer.from(hashedOTP, 'utf8')
    );
  } catch {
    return false;
  }
}

/**
 * جلوگیری از Timing Attack با مقایسه امن
 */
export function secureCompare(a: string, b: string): boolean {
  if (!a || !b || a.length !== b.length) {
    return false;
  }

  try {
    return crypto.timingSafeEqual(
      Buffer.from(a, 'utf8'),
      Buffer.from(b, 'utf8')
    );
  } catch {
    return false;
  }
}

/**
 * Mask کردن Email برای نمایش
 */
export function maskEmail(email: string): string {
  const parts = email.split('@');
  if (parts.length !== 2) {
    return '***';
  }
  
  const username = parts[0];
  const domain = parts[1];
  
  if (!username || username.length === 0) {
    return `***@${domain}`;
  }
  
  if (username.length === 1) {
    return `${username}***@${domain}`;
  }
  
  if (username.length <= 2) {
    return `${username[0]}***@${domain}`;
  }
  
  return `${username.slice(0, 2)}***${username.slice(-1)}@${domain}`;
}

/**
 * Mask کردن شماره تلفن
 */
export function maskPhone(phone: string): string {
  if (phone.length <= 4) {
    return '****';
  }
  
  return `${phone.slice(0, 2)}****${phone.slice(-2)}`;
}

/**
 * تولید CSRF Token
 */
export function generateCSRFToken(): string {
  return generateSecureToken(32);
}

/**
 * تایید CSRF Token
 */
export function verifyCSRFToken(token: string, storedToken: string): boolean {
  return secureCompare(token, storedToken);
}

/**
 * Rate Limit Key Generator
 */
export function generateRateLimitKey(
  identifier: string,
  endpoint: string
): string {
  return sha256Hash(`${identifier}:${endpoint}`);
}

/**
 * Validate کردن File Upload
 */
export function validateFileUpload(
  file: File,
  options: {
    maxSize?: number; // bytes
    allowedTypes?: string[];
  } = {}
): { valid: boolean; error?: string } {
  const maxSize = options.maxSize || 5 * 1024 * 1024; // 5MB default
  const allowedTypes = options.allowedTypes || [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf'
  ];

  if (file.size > maxSize) {
    return {
      valid: false,
      error: `File size exceeds ${maxSize / (1024 * 1024)}MB limit`
    };
  }

  if (!allowedTypes.includes(file.type)) {
    return {
      valid: false,
      error: `File type ${file.type} is not allowed`
    };
  }

  return { valid: true };
}

/**
 * Escape HTML برای جلوگیری از XSS
 */
export function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Remove HTML Tags
 */
export function stripHtml(html: string): string {
  return html.replace(/<[^>]*>/g, '');
}