import { Redis } from 'ioredis';

export interface LocationInfo {
  ip: string;
  latitude: number;
  longitude: number;
  city: string;
  country: string;
  region: string;
  isp: string;
  timestamp: Date;
}

export interface GeographicAnomalyResult {
  isAnomaly: boolean;
  confidence: number; // 0-1
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  previousLocation?: LocationInfo;
  currentLocation?: LocationInfo;
  distance?: number; // in kilometers
  timeDelta?: number; // in hours
}

export class GeographicAnomaly {
  private redis: Redis;

  constructor(redisUrl?: string) {
    this.redis = new Redis(redisUrl || process.env.REDIS_URL || 'redis://localhost:6379');
  }

  /**
   * Checks for geographic anomalies (like impossible travel)
   */
  async checkGeographicAnomaly(ip: string, userId?: string): Promise<GeographicAnomalyResult> {
    if (!userId) {
      // Without a user ID, we can't track location history for a specific user
      return {
        isAnomaly: false,
        confidence: 0,
        severity: 'LOW',
        description: 'No user ID provided, cannot check for geographic anomalies'
      };
    }

    // Get the current location for this IP
    const currentLocation = await this.getLocationForIP(ip);
    if (!currentLocation) {
      return {
        isAnomaly: false,
        confidence: 0,
        severity: 'LOW',
        description: 'Could not determine location for IP'
      };
    }

    // Get the user's last known location
    const lastLocation = await this.getLastKnownLocation(userId);
    if (!lastLocation) {
      // First time seeing this user from a location, no anomaly
      await this.updateUserLocation(userId, currentLocation);
      return {
        isAnomaly: false,
        confidence: 0,
        severity: 'LOW',
        description: 'First location record for user',
        currentLocation
      };
    }

    // Calculate distance and time difference
    const distance = this.calculateDistance(
      lastLocation.latitude, lastLocation.longitude,
      currentLocation.latitude, currentLocation.longitude
    );

    const timeDeltaMs = currentLocation.timestamp.getTime() - lastLocation.timestamp.getTime();
    const timeDeltaHours = timeDeltaMs / (1000 * 60 * 60);

    // Check for impossible travel (traveling faster than physically possible)
    const maxSpeedKmh = 900; // Assume commercial aircraft max speed
    const requiredSpeed = distance / timeDeltaHours;

    if (requiredSpeed > maxSpeedKmh && distance > 100) { // More than 100km distance
      const confidence = Math.min(0.95, Math.max(0.6, (requiredSpeed - maxSpeedKmh) / 1000));
      
      // Update user location even though it's anomalous
      await this.updateUserLocation(userId, currentLocation);
      
      return {
        isAnomaly: true,
        confidence,
        severity: 'CRITICAL',
        description: `Impossible travel detected: ${distance.toFixed(2)}km in ${timeDeltaHours.toFixed(2)}h (required speed: ${requiredSpeed.toFixed(2)} km/h)`,
        previousLocation: lastLocation,
        currentLocation,
        distance,
        timeDelta: timeDeltaHours
      };
    }

    // Check for high-risk countries
    if (this.isHighRiskCountry(currentLocation.country)) {
      // Don't necessarily mark as anomaly, but log for review
      await this.updateUserLocation(userId, currentLocation);
      
      return {
        isAnomaly: true,
        confidence: 0.7,
        severity: 'HIGH',
        description: `User accessed account from high-risk country: ${currentLocation.country}`,
        previousLocation: lastLocation,
        currentLocation,
        distance,
        timeDelta: timeDeltaHours
      };
    }

    // Update user location since no anomaly was detected
    await this.updateUserLocation(userId, currentLocation);

    return {
      isAnomaly: false,
      confidence: 0,
      severity: 'LOW',
      description: 'No geographic anomalies detected',
      previousLocation: lastLocation,
      currentLocation,
      distance,
      timeDelta: timeDeltaHours
    };
  }

  /**
   * Gets location information for an IP address
   * In a real implementation, this would call a geolocation API
   */
  private async getLocationForIP(ip: string): Promise<LocationInfo | null> {
    // This is a mock implementation - in reality you would call a geolocation service
    // like MaxMind, IPinfo, or similar
    
    // For demo purposes, return mock data
    // In a real system, you'd want to cache these results to avoid repeated API calls
    
    // Simulate looking up IP location
    const mockLocations: Record<string, LocationInfo> = {
      '192.168.1.1': {
        ip: '192.168.1.1',
        latitude: 37.7749,
        longitude: -122.4194,
        city: 'San Francisco',
        country: 'US',
        region: 'California',
        isp: 'Example ISP',
        timestamp: new Date()
      },
      '10.0.0.1': {
        ip: '10.0.0.1',
        latitude: 40.7128,
        longitude: -74.0060,
        city: 'New York',
        country: 'US',
        region: 'New York',
        isp: 'Example ISP 2',
        timestamp: new Date()
      },
      '203.0.113.1': {
        ip: '203.0.113.1',
        latitude: 51.5074,
        longitude: -0.1278,
        city: 'London',
        country: 'GB',
        region: 'England',
        isp: 'Example UK ISP',
        timestamp: new Date()
      },
      '198.51.100.1': {
        ip: '198.51.100.1',
        latitude: 35.6895,
        longitude: 139.6917,
        city: 'Tokyo',
        country: 'JP',
        region: 'Tokyo',
        isp: 'Example JP ISP',
        timestamp: new Date()
      }
    };

    // Check if it's a known IP
    if (mockLocations[ip]) {
      return {
        ...mockLocations[ip],
        timestamp: new Date() // Update timestamp to now
      };
    }

    // For unknown IPs, generate random location (in a real system, you'd call the geolocation API)
    return {
      ip,
      latitude: 37.0902 + (Math.random() - 0.5) * 20, // Rough US location
      longitude: -95.7129 + (Math.random() - 0.5) * 40, // Rough US location
      city: 'Unknown City',
      country: 'US',
      region: 'Unknown Region',
      isp: 'Unknown ISP',
      timestamp: new Date()
    };
  }

  /**
   * Gets the last known location for a user
   */
  private async getLastKnownLocation(userId: string): Promise<LocationInfo | null> {
    try {
      const key = `user_location:${userId}`;
      const locationData = await this.redis.get(key);
      
      if (!locationData) {
        return null;
      }
      
      return JSON.parse(locationData) as LocationInfo;
    } catch (error) {
      console.error(`[GEO_ANOMALY] Error getting last location for user ${userId}:`, error);
      return null;
    }
  }

  /**
   * Updates the last known location for a user
   */
  private async updateUserLocation(userId: string, location: LocationInfo): Promise<void> {
    try {
      const key = `user_location:${userId}`;
      await this.redis.setex(key, 86400 * 30, JSON.stringify(location)); // Keep for 30 days
    } catch (error) {
      console.error(`[GEO_ANOMALY] Error updating location for user ${userId}:`, error);
    }
  }

  /**
   * Calculates the distance between two coordinates using Haversine formula
   */
  private calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const R = 6371; // Earth radius in km
    const dLat = this.toRadians(lat2 - lat1);
    const dLon = this.toRadians(lon2 - lon1);
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(this.toRadians(lat1)) *
      Math.cos(this.toRadians(lat2)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c; // Distance in km
  }

  /**
   * Converts degrees to radians
   */
  private toRadians(degrees: number): number {
    return degrees * (Math.PI / 180);
  }

  /**
   * Checks if a country is considered high-risk
   */
  private isHighRiskCountry(countryCode: string): boolean {
    // List of high-risk countries (this would come from FATF or similar organization)
    const highRiskCountries = [
      'IR', // Iran
      'KP', // North Korea
      'SY', // Syria
      'CU', // Cuba
      'RU', // Russia (depending on context)
      'BY', // Belarus
      'MM', // Myanmar
      'ZW', // Zimbabwe
      'CD', // Democratic Republic of Congo
      'CF', // Central African Republic
      'ET', // Eritrea
      'IQ', // Iraq
      'LB', // Lebanon
      'SO', // Somalia
      'VE', // Venezuela
      'YE', // Yemen
    ];

    return highRiskCountries.includes(countryCode.toUpperCase());
  }

  /**
   * Checks if an IP is from a VPN or proxy service
   */
  async checkVPNOrProxy(ip: string): Promise<boolean> {
    // In a real implementation, this would check against VPN/proxy databases
    // For now, we'll just return false
    return false;
  }

  /**
   * Gets location history for a user
   */
  async getUserLocationHistory(userId: string, limit: number = 10): Promise<LocationInfo[]> {
    // In a real implementation, this would return a history of locations
    // For now, returning an empty array
    try {
      const lastLocation = await this.getLastKnownLocation(userId);
      return lastLocation ? [lastLocation] : [];
    } catch (error) {
      console.error(`[GEO_ANOMALY] Error getting location history for user ${userId}:`, error);
      return [];
    }
  }
}