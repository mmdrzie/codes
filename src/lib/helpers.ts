import { NextRequest } from 'next/server';

/**
 * استخراج IP Address از Request
 */
export function getClientIp(request: NextRequest): string {
  // بررسی header های مختلف برای IP
  const forwarded = request.headers.get('x-forwarded-for');
  if (forwarded && forwarded.length > 0) {
    const first = forwarded.split(',')[0];
    return (first ?? '').trim();
  }

  const realIp = request.headers.get('x-real-ip');
  if (realIp) {
    return realIp.trim();
  }

  const cfConnectingIp = request.headers.get('cf-connecting-ip');
  if (cfConnectingIp) {
    return cfConnectingIp.trim();
  }

  // در صورتی که هیچ IP پیدا نشد
  return 'unknown';
}

/**
 * استخراج User Agent از Request
 */
export function getUserAgent(request: NextRequest): string {
  return request.headers.get('user-agent') || 'unknown';
}