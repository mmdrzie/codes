import { createHash } from 'crypto';

export class PIIMasker {
  // Regular expressions for detecting PII
  private readonly patterns = {
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    phone: /(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
    ssn: /\b\d{3}-?\d{2}-?\d{4}\b/g,
    creditCard: /(\d{4}[-\s]?){3}\d{4}|\d{13,19}/g,
    ipAddress: /(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/g,
    iban: /[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]{3})?/gi,
    swiftCode: /[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?/gi,
    routingNumber: /\b\d{9}\b/g,
    currencyCode: /^[A-Z]{3}$/g,
    countryCodes: /^[A-Z]{2}$/g,
  };

  // Fields that are likely to contain PII
  private readonly piiFields = new Set([
    'email', 'password', 'token', 'secret', 'apiKey', 'api_key',
    'accessToken', 'access_token', 'refreshToken', 'refresh_token',
    'sessionId', 'session_id', 'creditCard', 'credit_card', 'cvv',
    'ssn', 'social_security_number', 'phoneNumber', 'phone_number',
    'phone', 'address', 'dob', 'dateOfBirth', 'date_of_birth',
    'passport', 'national_id', 'iban', 'swift', 'routing_number',
    'account_number', 'pin', 'tax_id', 'driver_license', 'dl_number'
  ]);

  /**
   * Mask PII in an object recursively
   */
  mask(obj: any): any {
    if (obj === null || obj === undefined) {
      return obj;
    }

    if (typeof obj === 'string') {
      return this.maskString(obj);
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.mask(item));
    }

    if (typeof obj === 'object') {
      const maskedObj: any = {};
      
      for (const [key, value] of Object.entries(obj)) {
        // Check if the field name suggests it contains PII
        if (this.containsPIIField(key)) {
          maskedObj[key] = this.maskPIIValue(value);
        } else {
          maskedObj[key] = this.mask(value);
        }
      }
      
      return maskedObj;
    }

    // For primitive types (number, boolean), return as is
    return obj;
  }

  /**
   * Mask PII in a string
   */
  private maskString(str: string): string {
    if (typeof str !== 'string') {
      return str;
    }

    let maskedStr = str;

    // Mask emails
    maskedStr = maskedStr.replace(this.patterns.email, (match) => {
      const [localPart, domain] = match.split('@');
      return `${this.maskPart(localPart)}@${this.maskPart(domain)}`;
    });

    // Mask phone numbers
    maskedStr = maskedStr.replace(this.patterns.phone, (match) => {
      return this.maskPart(match);
    });

    // Mask SSNs
    maskedStr = maskedStr.replace(this.patterns.ssn, (match) => {
      return this.maskPart(match);
    });

    // Mask credit card numbers
    maskedStr = maskedStr.replace(this.patterns.creditCard, (match) => {
      return this.maskPart(match);
    });

    // Mask IP addresses
    maskedStr = maskedStr.replace(this.patterns.ipAddress, (match) => {
      // For IP addresses, we'll hash them instead of just masking
      return this.hashValue(match);
    });

    // Mask IBANs
    maskedStr = maskedStr.replace(this.patterns.iban, (match) => {
      return this.maskPart(match);
    });

    // Mask SWIFT codes
    maskedStr = maskedStr.replace(this.patterns.swiftCode, (match) => {
      return this.maskPart(match);
    });

    // Mask routing numbers
    maskedStr = maskedStr.replace(this.patterns.routingNumber, (match) => {
      return this.maskPart(match);
    });

    return maskedStr;
  }

  /**
   * Check if a field name suggests it contains PII
   */
  private containsPIIField(fieldName: string): boolean {
    const lowerFieldName = fieldName.toLowerCase();
    
    // Check exact matches
    if (this.piiFields.has(lowerFieldName)) {
      return true;
    }

    // Check for field names that contain PII-related terms
    const piiTerms = ['email', 'pass', 'token', 'secret', 'key', 'auth', 'ssid', 'card', 'credit', 'phone', 'tel', 'mobile', 'iban', 'swift', 'routing', 'account'];
    
    return piiTerms.some(term => lowerFieldName.includes(term));
  }

  /**
   * Mask a PII value based on its type
   */
  private maskPIIValue(value: any): any {
    if (value === null || value === undefined) {
      return value;
    }

    if (typeof value === 'string') {
      // If it's a string that looks like an email, phone, etc., mask it accordingly
      if (this.patterns.email.test(value)) {
        return this.maskString(value);
      } else if (this.patterns.phone.test(value)) {
        return this.maskString(value);
      } else if (this.patterns.creditCard.test(value)) {
        return this.maskString(value);
      } else if (this.patterns.ssn.test(value)) {
        return this.maskString(value);
      } else {
        // For other string values, hash them for privacy but keep them identifiable
        return this.hashValue(value);
      }
    } else if (typeof value === 'object' && value !== null) {
      // If it's an object, recursively mask its properties
      return this.mask(value);
    } else if (Array.isArray(value)) {
      // If it's an array, recursively mask its elements
      return value.map(item => this.maskPIIValue(item));
    } else {
      // For non-string primitives, convert to string and hash
      return this.hashValue(String(value));
    }
  }

  /**
   * Mask part of a string (keep first and last chars visible)
   */
  private maskPart(str: string): string {
    if (str.length <= 2) {
      return '*'.repeat(str.length);
    }
    
    const firstChar = str[0];
    const lastChar = str[str.length - 1];
    const middleLength = str.length - 2;
    
    return firstChar + '*'.repeat(middleLength) + lastChar;
  }

  /**
   * Hash a value for privacy (non-reversible)
   */
  private hashValue(value: string): string {
    return createHash('sha256').update(value).digest('hex');
  }

  /**
   * Mask sensitive fields in an object with configurable rules
   */
  maskWithRules(obj: any, rules: { [key: string]: 'mask' | 'hash' | 'remove' }): any {
    if (obj === null || obj === undefined) {
      return obj;
    }

    if (typeof obj === 'string') {
      return this.maskString(obj);
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.maskWithRules(item, rules));
    }

    if (typeof obj === 'object') {
      const maskedObj: any = {};
      
      for (const [key, value] of Object.entries(obj)) {
        const rule = rules[key.toLowerCase()];
        
        switch (rule) {
          case 'mask':
            maskedObj[key] = this.maskPIIValue(value);
            break;
          case 'hash':
            maskedObj[key] = typeof value === 'string' ? this.hashValue(value) : this.hashValue(JSON.stringify(value));
            break;
          case 'remove':
            // Don't add this field to the masked object
            break;
          default:
            // Apply default masking
            if (this.containsPIIField(key)) {
              maskedObj[key] = this.maskPIIValue(value);
            } else {
              maskedObj[key] = this.mask(value);
            }
        }
      }
      
      return maskedObj;
    }

    return obj;
  }

  /**
   * Check if a string contains PII
   */
  containsPII(str: string): boolean {
    if (typeof str !== 'string') {
      return false;
    }

    return this.patterns.email.test(str) ||
           this.patterns.phone.test(str) ||
           this.patterns.ssn.test(str) ||
           this.patterns.creditCard.test(str) ||
           this.patterns.iban.test(str) ||
           this.patterns.swiftCode.test(str) ||
           this.patterns.routingNumber.test(str);
  }

  /**
   * Extract PII from a string (for monitoring purposes)
   */
  extractPII(str: string): { type: string; value: string }[] {
    if (typeof str !== 'string') {
      return [];
    }

    const extracted: { type: string; value: string }[] = [];

    // Extract emails
    const emailMatches = str.match(this.patterns.email);
    if (emailMatches) {
      emailMatches.forEach(match => extracted.push({ type: 'email', value: match }));
    }

    // Extract phone numbers
    const phoneMatches = str.match(this.patterns.phone);
    if (phoneMatches) {
      phoneMatches.forEach(match => extracted.push({ type: 'phone', value: match }));
    }

    // Extract SSNs
    const ssnMatches = str.match(this.patterns.ssn);
    if (ssnMatches) {
      ssnMatches.forEach(match => extracted.push({ type: 'ssn', value: match }));
    }

    // Extract credit cards
    const ccMatches = str.match(this.patterns.creditCard);
    if (ccMatches) {
      ccMatches.forEach(match => extracted.push({ type: 'creditCard', value: match }));
    }

    // Extract IBANs
    const ibanMatches = str.match(this.patterns.iban);
    if (ibanMatches) {
      ibanMatches.forEach(match => extracted.push({ type: 'iban', value: match }));
    }

    // Extract SWIFT codes
    const swiftMatches = str.match(this.patterns.swiftCode);
    if (swiftMatches) {
      swiftMatches.forEach(match => extracted.push({ type: 'swift', value: match }));
    }

    return extracted;
  }
}