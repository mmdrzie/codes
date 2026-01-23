export interface DeviceFingerprint {
  userAgent: string;
  browserName: string;
  browserVersion: string;
  os: string;
  osVersion: string;
  deviceType: 'mobile' | 'tablet' | 'desktop' | 'unknown';
  screenResolution: string;
  timezone: string;
  language: string;
  canvasFingerprint: string;
  webglFingerprint: string;
  hardwareConcurrency: number;
  deviceMemory?: number;
  platform: string;
  vendor: string;
  plugins: string[];
  fonts: string[];
  audioContextFingerprint?: string;
  touchSupport: boolean;
  colorDepth: number;
  pixelRatio: number;
}

export class DeviceFingerprintGenerator {
  /**
   * Generate a comprehensive device fingerprint from client-side data
   */
  static generateFingerprint(clientData: Partial<DeviceFingerprint>): DeviceFingerprint {
    // Fill in defaults for missing properties
    const fingerprint: DeviceFingerprint = {
      userAgent: clientData.userAgent || 'unknown',
      browserName: clientData.browserName || this.detectBrowserName(clientData.userAgent || ''),
      browserVersion: clientData.browserVersion || this.detectBrowserVersion(clientData.userAgent || ''),
      os: clientData.os || this.detectOS(clientData.userAgent || ''),
      osVersion: clientData.osVersion || this.detectOSVersion(clientData.userAgent || ''),
      deviceType: clientData.deviceType || this.detectDeviceType(clientData.userAgent || ''),
      screenResolution: clientData.screenResolution || 'unknown',
      timezone: clientData.timezone || this.detectTimezone(),
      language: clientData.language || this.detectLanguage(),
      canvasFingerprint: clientData.canvasFingerprint || this.generateCanvasFingerprint(),
      webglFingerprint: clientData.webglFingerprint || this.generateWebGLFingerprint(),
      hardwareConcurrency: clientData.hardwareConcurrency || navigator?.hardwareConcurrency || 2,
      deviceMemory: clientData.deviceMemory || (navigator as any)?.deviceMemory,
      platform: clientData.platform || navigator?.platform || 'unknown',
      vendor: clientData.vendor || (navigator as any)?.vendor || 'unknown',
      plugins: clientData.plugins || this.getPlugins(),
      fonts: clientData.fonts || this.getFonts(),
      audioContextFingerprint: clientData.audioContextFingerprint || this.generateAudioContextFingerprint(),
      touchSupport: clientData.touchSupport || this.detectTouchSupport(),
      colorDepth: clientData.colorDepth || screen?.colorDepth || 24,
      pixelRatio: clientData.pixelRatio || window?.devicePixelRatio || 1
    };

    return fingerprint;
  }

  /**
   * Detect browser name from user agent
   */
  private static detectBrowserName(userAgent: string): string {
    if (userAgent.includes('Chrome') && !userAgent.includes('Edg')) {
      return 'Chrome';
    } else if (userAgent.includes('Firefox')) {
      return 'Firefox';
    } else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) {
      return 'Safari';
    } else if (userAgent.includes('Edg')) {
      return 'Edge';
    } else if (userAgent.includes('Opera') || userAgent.includes('OPR')) {
      return 'Opera';
    } else if (userAgent.includes('MSIE') || userAgent.includes('Trident')) {
      return 'Internet Explorer';
    }
    return 'Unknown';
  }

  /**
   * Detect browser version from user agent
   */
  private static detectBrowserVersion(userAgent: string): string {
    const regexes: Record<string, RegExp> = {
      Chrome: /Chrome\/(\d+\.\d+)/,
      Firefox: /Firefox\/(\d+\.\d+)/,
      Safari: /Version\/(\d+\.\d+)/,
      Edge: /Edg\/(\d+\.\d+)/,
      Opera: /(?:Opera|OPR)\/(\d+\.\d+)/,
      'Internet Explorer': /(?:MSIE |rv:)(\d+\.\d+)/
    };

    const browserName = this.detectBrowserName(userAgent);
    const regex = regexes[browserName];
    
    if (regex) {
      const match = userAgent.match(regex);
      return match ? match[1] : 'unknown';
    }
    
    return 'unknown';
  }

  /**
   * Detect operating system from user agent
   */
  private static detectOS(userAgent: string): string {
    if (userAgent.includes('Windows NT 10.0')) {
      return 'Windows 10';
    } else if (userAgent.includes('Windows NT 6.3')) {
      return 'Windows 8.1';
    } else if (userAgent.includes('Windows NT 6.2')) {
      return 'Windows 8';
    } else if (userAgent.includes('Windows NT 6.1')) {
      return 'Windows 7';
    } else if (userAgent.includes('Mac OS X')) {
      return 'macOS';
    } else if (userAgent.includes('Android')) {
      return 'Android';
    } else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) {
      return 'iOS';
    } else if (userAgent.includes('Linux')) {
      return 'Linux';
    }
    return 'Unknown';
  }

  /**
   * Detect OS version from user agent
   */
  private static detectOSVersion(userAgent: string): string {
    const os = this.detectOS(userAgent);
    
    if (os === 'macOS') {
      const match = userAgent.match(/Mac OS X (\d+_\d+(_\d+)?)/);
      return match ? match[1].replace(/_/g, '.') : 'unknown';
    } else if (os === 'Android') {
      const match = userAgent.match(/Android (\d+(\.\d+)?(\.\d+)?)/);
      return match ? match[1] : 'unknown';
    } else if (os === 'iOS') {
      const match = userAgent.match(/OS (\d+_\d+(_\d+)?)/);
      return match ? match[1].replace(/_/g, '.') : 'unknown';
    } else if (os.includes('Windows')) {
      const match = userAgent.match(/Windows NT (\d+\.\d+)/);
      return match ? match[1] : 'unknown';
    }
    
    return 'unknown';
  }

  /**
   * Detect device type from user agent
   */
  private static detectDeviceType(userAgent: string): 'mobile' | 'tablet' | 'desktop' | 'unknown' {
    const mobileRegex = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i;
    const tabletRegex = /Tablet|iPad/i;
    
    if (tabletRegex.test(userAgent)) {
      return 'tablet';
    } else if (mobileRegex.test(userAgent)) {
      return 'mobile';
    } else {
      return 'desktop';
    }
  }

  /**
   * Detect timezone
   */
  private static detectTimezone(): string {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone;
    } catch {
      return 'unknown';
    }
  }

  /**
   * Detect language
   */
  private static detectLanguage(): string {
    return navigator?.language || 'unknown';
  }

  /**
   * Generate canvas fingerprint
   */
  private static generateCanvasFingerprint(): string {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      if (!ctx) return 'unknown';
      
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('Canvas fingerprint', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('Canvas fingerprint', 4, 17);
      
      return canvas.toDataURL();
    } catch {
      return 'unknown';
    }
  }

  /**
   * Generate WebGL fingerprint
   */
  private static generateWebGLFingerprint(): string {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return 'unknown';
      
      const renderer = gl.getParameter(gl.RENDERER);
      const vendor = gl.getParameter(gl.VENDOR);
      const version = gl.getParameter(gl.VERSION);
      const shadingLanguageVersion = gl.getParameter(gl.SHADING_LANGUAGE_VERSION);
      
      return `${renderer}-${vendor}-${version}-${shadingLanguageVersion}`;
    } catch {
      return 'unknown';
    }
  }

  /**
   * Get installed plugins
   */
  private static getPlugins(): string[] {
    if (!navigator.plugins) return [];
    
    const plugins: string[] = [];
    for (let i = 0; i < navigator.plugins.length; i++) {
      plugins.push(navigator.plugins[i].name);
    }
    
    return plugins;
  }

  /**
   * Get available fonts (basic implementation)
   */
  private static getFonts(): string[] {
    // This is a simplified implementation
    // In a real implementation, you would perform font detection
    return ['Arial', 'Helvetica', 'Times New Roman', 'Courier New'];
  }

  /**
   * Generate audio context fingerprint
   */
  private static generateAudioContextFingerprint(): string {
    try {
      const AudioContext = window.AudioContext || (window as any).webkitAudioContext;
      if (!AudioContext) return 'unknown';
      
      const audioCtx = new AudioContext();
      const oscillator = audioCtx.createOscillator();
      const analyser = audioCtx.createAnalyser();
      const gain = audioCtx.createGain();
      const scriptProcessor = audioCtx.createScriptProcessor(4096, 1, 1);
      
      oscillator.connect(analyser);
      analyser.connect(gain);
      gain.connect(scriptProcessor);
      scriptProcessor.connect(audioCtx.destination);
      
      oscillator.start();
      audioCtx.close();
      
      // In a real implementation, you would capture the audio fingerprint
      return 'audio-context-available';
    } catch {
      return 'not-available';
    }
  }

  /**
   * Detect touch support
   */
  private static detectTouchSupport(): boolean {
    return 'ontouchstart' in window || navigator.maxTouchPoints > 0;
  }

  /**
   * Validate a device fingerprint
   */
  static validateFingerprint(fingerprint: DeviceFingerprint): boolean {
    // Basic validation
    if (!fingerprint.userAgent) return false;
    if (!fingerprint.browserName) return false;
    if (!fingerprint.os) return false;
    
    // Check that required fields exist
    const requiredFields: (keyof DeviceFingerprint)[] = [
      'userAgent', 'browserName', 'os', 'deviceType', 
      'timezone', 'language', 'canvasFingerprint', 'webglFingerprint'
    ];
    
    for (const field of requiredFields) {
      if (fingerprint[field] === undefined || fingerprint[field] === null) {
        return false;
      }
    }
    
    return true;
  }

  /**
   * Create a hash of the device fingerprint for comparison
   */
  static hashFingerprint(fingerprint: DeviceFingerprint): string {
    // In a real implementation, you would use a proper hashing algorithm
    // For now, we'll create a simple representation
    const str = JSON.stringify({
      userAgent: fingerprint.userAgent,
      browserName: fingerprint.browserName,
      os: fingerprint.os,
      deviceType: fingerprint.deviceType,
      canvasFingerprint: fingerprint.canvasFingerprint,
      webglFingerprint: fingerprint.webglFingerprint,
      timezone: fingerprint.timezone
    });
    
    // Simple hash function (in production, use a proper crypto library)
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0; // Convert to 32bit integer
    }
    
    return Math.abs(hash).toString(36);
  }

  /**
   * Compare two device fingerprints for similarity
   */
  static compareFingerprints(fp1: DeviceFingerprint, fp2: DeviceFingerprint): number {
    // Calculate similarity score (0-100)
    let score = 0;
    let totalChecks = 0;
    
    // Compare key identifying fields
    if (fp1.browserName === fp2.browserName) {
      score += 20;
    }
    totalChecks += 20;
    
    if (fp1.os === fp2.os) {
      score += 20;
    }
    totalChecks += 20;
    
    if (fp1.deviceType === fp2.deviceType) {
      score += 15;
    }
    totalChecks += 15;
    
    if (fp1.timezone === fp2.timezone) {
      score += 15;
    }
    totalChecks += 15;
    
    if (fp1.canvasFingerprint === fp2.canvasFingerprint) {
      score += 10;
    }
    totalChecks += 10;
    
    if (fp1.webglFingerprint === fp2.webglFingerprint) {
      score += 10;
    }
    totalChecks += 10;
    
    if (fp1.language === fp2.language) {
      score += 10;
    }
    totalChecks += 10;
    
    return Math.round((score / totalChecks) * 100);
  }
}