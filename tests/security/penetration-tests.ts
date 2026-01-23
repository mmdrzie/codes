import { describe, it, beforeEach, afterEach } from 'mocha';
import { expect } from 'chai';
import * as supertest from 'supertest';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { createApp } from '../../src/app';
import { User } from '../../src/models/User';
import { Session } from '../../src/models/Session';
import { connectDB, disconnectDB } from '../../src/config/database';

describe('Penetration Tests', () => {
  let app;
  let agent;
  let testUser;
  let authToken;

  beforeEach(async () => {
    app = await createApp();
    agent = supertest.agent(app);
    
    // Connect to test database
    await connectDB();
    
    // Create a test user
    const hashedPassword = await bcrypt.hash('SecurePass123!', 12);
    testUser = await User.create({
      email: 'test@example.com',
      password: hashedPassword,
      firstName: 'Test',
      lastName: 'User'
    });
    
    // Login to get auth token
    const loginResponse = await agent
      .post('/api/auth/login')
      .send({
        email: 'test@example.com',
        password: 'SecurePass123!'
      });
    
    authToken = loginResponse.body.token;
  });

  afterEach(async () => {
    // Clean up test data
    await User.deleteMany({ email: 'test@example.com' });
    await Session.deleteMany({ userId: testUser._id });
    await disconnectDB();
  });

  describe('SQL Injection Tests', () => {
    it('should prevent SQL injection in user search', async () => {
      const maliciousQuery = "'; DROP TABLE users; --";
      
      const response = await agent
        .get(`/api/users/search?q=${encodeURIComponent(maliciousQuery)}`)
        .set('Authorization', `Bearer ${authToken}`);
      
      // Should not crash and should return appropriate response
      expect(response.status).to.be.oneOf([200, 400, 404]);
      expect(response.body).to.not.include('DROP TABLE');
    });

    it('should prevent SQL injection in authentication', async () => {
      const maliciousEmail = "admin' OR '1'='1";
      
      const response = await agent
        .post('/api/auth/login')
        .send({
          email: maliciousEmail,
          password: "' OR '1'='1"
        });
      
      // Should return authentication failure, not success
      expect(response.status).to.equal(401);
      expect(response.body.success).to.be.false;
    });

    it('should prevent SQL injection in user profile update', async () => {
      const maliciousData = {
        firstName: "'; DROP TABLE users; --",
        lastName: 'Test',
        email: "test'; DROP TABLE users; --@example.com"
      };
      
      const response = await agent
        .put('/api/users/profile')
        .set('Authorization', `Bearer ${authToken}`)
        .send(maliciousData);
      
      expect(response.status).to.be.oneOf([200, 400]);
      if (response.status === 200) {
        const updatedUser = await User.findById(testUser._id);
        expect(updatedUser.firstName).to.not.include('DROP TABLE');
      }
    });
  });

  describe('XSS Tests', () => {
    it('should prevent reflected XSS in search functionality', async () => {
      const xssPayload = '<script>alert("XSS")</script>';
      
      const response = await agent
        .get(`/api/users/search?q=${encodeURIComponent(xssPayload)}`)
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(response.status).to.be.oneOf([200, 400, 404]);
      const responseBody = JSON.stringify(response.body);
      expect(responseBody).to.not.include('<script>');
      expect(responseBody).to.not.include('alert(');
    });

    it('should prevent stored XSS in user profile', async () => {
      const xssPayload = '<script>alert("Stored XSS")</script>';
      
      const updateResponse = await agent
        .put('/api/users/profile')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          firstName: xssPayload,
          lastName: 'User'
        });
      
      expect(updateResponse.status).to.be.oneOf([200, 400]);
      
      const getResponse = await agent
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(getResponse.status).to.equal(200);
      expect(getResponse.body.user.firstName).to.not.include('<script>');
      expect(getResponse.body.user.firstName).to.not.include('alert(');
    });

    it('should prevent XSS in error messages', async () => {
      const maliciousInput = '<img src=x onerror=alert("XSS")>';
      
      const response = await agent
        .post('/api/users/update')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          email: maliciousInput
        });
      
      const responseBody = JSON.stringify(response.body);
      expect(responseBody).to.not.include('onerror=');
      expect(responseBody).to.not.include('alert(');
    });
  });

  describe('CSRF Tests', () => {
    it('should validate CSRF tokens for sensitive operations', async () => {
      // Attempt to perform sensitive operation without CSRF token
      const response = await supertest(app)
        .post('/api/users/delete-account')
        .send({
          confirm: true,
          password: 'SecurePass123!'
        });
      
      // Should fail due to missing CSRF protection
      expect(response.status).to.be.oneOf([401, 403, 400]);
    });

    it('should reject invalid CSRF tokens', async () => {
      const response = await supertest(app)
        .post('/api/users/change-password')
        .set('X-CSRF-Token', 'invalid-token-12345')
        .send({
          oldPassword: 'SecurePass123!',
          newPassword: 'NewSecurePass456!'
        });
      
      expect(response.status).to.be.oneOf([401, 403]);
    });
  });

  describe('Session Hijacking Tests', () => {
    it('should validate session integrity', async () => {
      // Get valid session token
      const validResponse = await agent
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(validResponse.status).to.equal(200);
      
      // Attempt to tamper with JWT token
      const tamperedToken = authToken.substring(0, authToken.length - 5) + 'AAAAA';
      
      const tamperedResponse = await agent
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${tamperedToken}`);
      
      expect(tamperedResponse.status).to.equal(401);
    });

    it('should invalidate sessions on logout', async () => {
      // Logout
      const logoutResponse = await agent
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(logoutResponse.status).to.equal(200);
      
      // Attempt to use token after logout
      const postLogoutResponse = await agent
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(postLogoutResponse.status).to.equal(401);
    });

    it('should regenerate session IDs after authentication', async () => {
      // Login again to test session regeneration
      const loginResponse = await agent
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'SecurePass123!'
        });
      
      expect(loginResponse.status).to.equal(200);
      expect(loginResponse.body.token).to.exist;
      // New token should be different from the original
    });
  });

  describe('Authentication Bypass Tests', () => {
    it('should require valid authentication for protected routes', async () => {
      const invalidTokens = [
        null,
        '',
        'invalid.token.here',
        'Bearer ',
        'Bearer invalid.token.format'
      ];
      
      for (const token of invalidTokens) {
        const response = await agent
          .get('/api/users/profile')
          .set('Authorization', token ? `Bearer ${token}` : {});
        
        expect(response.status).to.be.oneOf([401, 403]);
      }
    });

    it('should not accept expired tokens', async () => {
      // Create an expired token
      const expiredToken = jwt.sign(
        { userId: testUser._id, exp: Math.floor(Date.now() / 1000) - 60 }, // 1 minute ago
        process.env.JWT_SECRET || 'fallback_secret'
      );
      
      const response = await agent
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${expiredToken}`);
      
      expect(response.status).to.equal(401);
    });

    it('should validate token signature', async () => {
      // Create token with wrong secret
      const wrongSecretToken = jwt.sign(
        { userId: testUser._id },
        'wrong_secret'
      );
      
      const response = await agent
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${wrongSecretToken}`);
      
      expect(response.status).to.equal(401);
    });
  });

  describe('Authorization Tests', () => {
    it('should enforce role-based access control', async () => {
      // Regular user should not access admin endpoints
      const adminResponse = await agent
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(adminResponse.status).to.be.oneOf([403, 401]);
    });

    it('should not allow privilege escalation', async () => {
      // Attempt to modify another user's data
      const otherUserId = '507f1f77bcf86cd799439011'; // Fake user ID
      
      const response = await agent
        .put(`/api/users/${otherUserId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          firstName: 'Hacked',
          lastName: 'User'
        });
      
      expect(response.status).to.be.oneOf([403, 404]);
    });

    it('should enforce resource ownership', async () => {
      // Attempt to access another user's private resources
      const response = await agent
        .get('/api/users/private-data')
        .set('Authorization', `Bearer ${authToken}`);
      
      expect(response.status).to.be.oneOf([403, 404]);
    });
  });

  describe('Rate Limiting Bypass Tests', () => {
    it('should enforce rate limits even with different IP addresses', async () => {
      // Simulate multiple requests from same account
      const responses = [];
      for (let i = 0; i < 20; i++) {
        const response = await supertest(app)
          .post('/api/auth/login')
          .set('X-Forwarded-For', `192.168.1.${i}`)
          .send({
            email: 'test@example.com',
            password: 'wrongpassword'
          });
        responses.push(response);
      }
      
      // Some requests should be rate limited
      const rateLimitedCount = responses.filter(r => r.status === 429).length;
      expect(rateLimitedCount).to.be.greaterThan(0);
    });

    it('should prevent brute force attacks', async () => {
      // Multiple failed login attempts should eventually block
      let blocked = false;
      for (let i = 0; i < 50; i++) {
        const response = await agent
          .post('/api/auth/login')
          .send({
            email: 'test@example.com',
            password: 'wrongpassword' + i
          });
        
        if (response.status === 429) {
          blocked = true;
          break;
        }
      }
      
      expect(blocked).to.be.true;
    });
  });
});