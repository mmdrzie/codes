import { describe, it, expect, beforeEach } from '@jest/globals';
import { generateNonce, buildCSPHeader } from '../src/lib/csp-middleware';

describe('Content Security Policy (CSP) Tests', () => {
  it('should generate a valid nonce', () => {
    const nonce1 = generateNonce();
    const nonce2 = generateNonce();
    
    // Nonces should be different each time
    expect(nonce1).not.toBe(nonce2);
    
    // Nonces should be hex strings of appropriate length
    expect(nonce1).toMatch(/^[a-f0-9]{32}$/);
    expect(nonce2).toMatch(/^[a-f0-9]{32}$/);
  });

  it('should build a valid CSP header with nonce', () => {
    const nonce = 'test-nonce-12345';
    const cspHeader = buildCSPHeader(nonce);
    
    // Check that the header contains the nonce
    expect(cspHeader).toContain(`'nonce-${nonce}'`);
    
    // Check that it contains important directives
    expect(cspHeader).toContain('default-src \'self\'');
    expect(cspHeader).toContain('object-src \'none\'');
    expect(cspHeader).toContain('frame-ancestors \'none\'');
  });

  it('should not include unsafe directives', () => {
    const nonce = 'test-nonce-12345';
    const cspHeader = buildCSPHeader(nonce);
    
    // Ensure unsafe directives are not present
    expect(cspHeader).not.toContain("'unsafe-inline'");
    expect(cspHeader).not.toContain("'unsafe-eval'");
    expect(cspHeader).not.toContain("data:");
    
    // Except for specific cases where they're explicitly allowed (like img-src)
    // The general rule is to avoid them in script/style-src
    expect(cspHeader).toContain('script-src');
    expect(cspHeader).not.toMatch(/script-src[^;]*'unsafe-inline'/);
    expect(cspHeader).not.toMatch(/script-src[^;]*'unsafe-eval'/);
  });

  it('should include necessary security headers', () => {
    // Test that the middleware adds essential security headers
    const nonce = generateNonce();
    const cspHeader = buildCSPHeader(nonce);
    
    // The CSP header should include basic protections
    expect(cspHeader).toContain('default-src \'self\'');
    expect(cspHeader).toContain('object-src \'none\'');
    expect(cspHeader).toContain('base-uri \'self\'');
    expect(cspHeader).toContain('form-action \'self\'');
  });

  it('should have proper frame protection', () => {
    const nonce = generateNonce();
    const cspHeader = buildCSPHeader(nonce);
    
    // Should prevent framing to prevent clickjacking
    expect(cspHeader).toContain('frame-ancestors \'none\'');
  });

  it('should allow necessary external resources', () => {
    const nonce = generateNonce();
    const cspHeader = buildCSPHeader(nonce);
    
    // Should allow necessary external resources for the application
    expect(cspHeader).toContain('connect-src');
    expect(cspHeader).toContain('https://*.sentry.io');
    expect(cspHeader).toContain('https://*.infura.io');
    expect(cspHeader).toContain('wss://*.infura.io');
  });
});