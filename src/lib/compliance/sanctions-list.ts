/**
 * Sanctions List Manager
 * Handles OFAC, EU, and UN sanctions list downloads and updates
 */

import { Redis } from '@upstash/redis';
import axios from 'axios';
import { logger } from '../logger';

export interface SanctionEntry {
  entityId: string;
  name: string;
  aliases: string[];
  programs: string[]; // OFAC programs like "SDGT", "FTO", etc.
  nationality?: string;
  citizenship?: string;
  datesOfBirth?: string[];
  titles?: string[];
  remarks?: string;
}

export class SanctionsListManager {
  private redis: Redis;
  private readonly SANCTIONS_SOURCES = {
    OFAC_SDN: 'https://www.treasury.gov/ofac/downloads/sdn.xml',
    OFAC_ALT: 'https://www.treasury.gov/ofac/downloads/alt.xml',  // Alternative names
    OFAC_ADD: 'https://www.treasury.gov/ofac/downloads/add.xml',  // Addresses
    EU_SANCTIONS: 'https://webgate.ec.europa.eu/fsd/fsf/public/files/xmlFull_en',
    UN_SANCTIONS: 'https://scsanctions.un.org/resources/xml/en/consolidated.xml'
  };

  constructor() {
    this.redis = Redis.fromEnv();
  }

  /**
   * Download and parse OFAC SDN list
   * Note: In production, this would connect to official OFAC endpoints
   * For this implementation, we'll simulate the process
   */
  async updateOFACList(): Promise<void> {
    try {
      logger.info('Starting OFAC list update');

      // In a real implementation, you would:
      // 1. Download from: https://www.treasury.gov/ofac/downloads/sdn.xml
      // 2. Parse the XML response
      // 3. Store in Redis with proper indexing
      
      // For this example, we'll create sample data
      const sampleOFACEntries: SanctionEntry[] = [
        {
          entityId: '12345',
          name: 'AL QAEDA',
          aliases: ['AL-QAEDA', 'AL QAEDA ORGANIZATION'],
          programs: ['SDGT', 'FTO'],
          nationality: 'International',
          remarks: 'Foreign Terrorist Organization'
        },
        {
          entityId: '12346',
          name: 'OSAMA BIN LADEN',
          aliases: ['BIN LADEN', 'OSAMA BIN LADIN'],
          programs: ['SDGT', 'FTO'],
          nationality: 'SAUDI ARABIA',
          datesOfBirth: ['1957-03-10'],
          remarks: 'Former leader of Al-Qaida'
        },
        {
          entityId: '12347',
          name: 'HAMAS',
          aliases: ['ISLAMIC RESISTANCE MOVEMENT', 'HARAKAT AL-MUQAWAMA AL-ISLAMIYYA'],
          programs: ['SDT', 'FTO'],
          nationality: 'Palestinian',
          remarks: 'Foreign Terrorist Organization'
        },
        {
          entityId: '12348',
          name: 'JOHN DOE',
          aliases: ['J. DOE', 'JON DOE'],
          programs: ['DRUG'],
          nationality: 'US',
          titles: ['Kingpin'],
          remarks: 'Significant foreign narcotics trafficker'
        }
      ];

      // Store in Redis with multiple indexes for efficient searching
      const pipeline = this.redis.pipeline();
      
      // Clear existing OFAC entries
      await this.redis.del('sanctions:ofac:list');
      
      // Add each entry
      for (const entry of sampleOFACEntries) {
        // Add to main list
        pipeline.sadd('sanctions:ofac:list', entry.entityId);
        
        // Index by primary name
        pipeline.set(`sanctions:ofac:name:${entry.name.toUpperCase()}`, JSON.stringify(entry));
        
        // Index by aliases
        for (const alias of entry.aliases) {
          pipeline.set(`sanctions:ofac:alias:${alias.toUpperCase()}`, JSON.stringify(entry));
        }
        
        // Store full entry
        pipeline.set(`sanctions:ofac:entity:${entry.entityId}`, JSON.stringify(entry));
      }
      
      await pipeline.exec();
      
      // Update last updated timestamp
      await this.redis.set('sanctions:ofac:last_updated', Date.now());
      
      logger.info('OFAC list updated successfully', {
        entries: sampleOFACEntries.length
      });
    } catch (error) {
      logger.error('Error updating OFAC list', {
        error: (error as Error).message
      });
      throw error;
    }
  }

  /**
   * Search for entities in sanctions lists
   */
  async searchSanctions(name: string, fuzzyThreshold: number = 0.8): Promise<SanctionEntry[]> {
    try {
      const results: SanctionEntry[] = [];
      const upperName = name.toUpperCase().trim();
      
      // Direct name match
      const directMatch = await this.redis.get<SanctionEntry>(`sanctions:ofac:name:${upperName}`);
      if (directMatch) {
        results.push(directMatch);
      }
      
      // Alias match
      const aliasMatch = await this.redis.get<SanctionEntry>(`sanctions:ofac:alias:${upperName}`);
      if (aliasMatch) {
        results.push(aliasMatch);
      }
      
      // Fuzzy matching (simplified version)
      // In production, you'd use more sophisticated algorithms
      const allEntityIds = await this.redis.smembers('sanctions:ofac:list');
      
      for (const entityId of allEntityIds) {
        const entity = await this.redis.get<SanctionEntry>(`sanctions:ofac:entity:${entityId}`);
        if (entity) {
          // Check primary name
          if (this.calculateSimilarity(upperName, entity.name.toUpperCase()) >= fuzzyThreshold) {
            if (!results.some(r => r.entityId === entity.entityId)) {
              results.push(entity);
            }
          }
          
          // Check aliases
          for (const alias of entity.aliases) {
            if (this.calculateSimilarity(upperName, alias.toUpperCase()) >= fuzzyThreshold) {
              if (!results.some(r => r.entityId === entity.entityId)) {
                results.push(entity);
              }
              break;
            }
          }
        }
      }
      
      return results;
    } catch (error) {
      logger.error('Error searching sanctions lists', {
        error: (error as Error).message
      });
      return [];
    }
  }

  /**
   * Check if a name is on any sanctions list
   */
  async isOnSanctionsList(name: string, fuzzyThreshold: number = 0.8): Promise<{ 
    isMatch: boolean; 
    matches: Array<{entry: SanctionEntry, confidence: number}> 
  }> {
    try {
      const matches = await this.searchSanctions(name, fuzzyThreshold);
      
      if (matches.length === 0) {
        return { isMatch: false, matches: [] };
      }
      
      // Calculate confidence scores
      const results = matches.map(entry => {
        const nameMatch = this.calculateSimilarity(name.toUpperCase(), entry.name.toUpperCase());
        const aliasMatches = entry.aliases.map(alias => 
          this.calculateSimilarity(name.toUpperCase(), alias.toUpperCase())
        );
        
        const maxConfidence = Math.max(nameMatch, ...aliasMatches);
        
        return {
          entry,
          confidence: Math.round(maxConfidence * 100)
        };
      });
      
      return {
        isMatch: true,
        matches: results.sort((a, b) => b.confidence - a.confidence)
      };
    } catch (error) {
      logger.error('Error checking sanctions list', {
        error: (error as Error).message
      });
      return { isMatch: false, matches: [] };
    }
  }

  /**
   * Calculate similarity between two strings (simplified version)
   */
  private calculateSimilarity(str1: string, str2: string): number {
    // Remove extra spaces and normalize
    const clean1 = str1.replace(/\s+/g, ' ').trim();
    const clean2 = str2.replace(/\s+/g, ' ').trim();
    
    const longer = clean1.length > clean2.length ? clean1 : clean2;
    const shorter = clean1.length > clean2.length ? clean2 : clean1;
    
    if (longer.length === 0) return 1.0;
    
    // Simple substring check first
    if (longer.includes(shorter) || shorter.includes(longer)) {
      return Math.max(0.7, Math.min(1.0, shorter.length / longer.length));
    }
    
    // Use Levenshtein distance for more complex comparison
    const editDistance = this.levenshteinDistance(clean1, clean2);
    return (longer.length - editDistance) / longer.length;
  }

  /**
   * Calculate Levenshtein distance between two strings
   */
  private levenshteinDistance(str1: string, str2: string): number {
    const matrix = [];
    
    if (str1.length === 0) return str2.length;
    if (str2.length === 0) return str1.length;

    // Initialize matrix
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    // Fill matrix
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  /**
   * Update all sanctions lists (OFAC, EU, UN)
   */
  async updateAllLists(): Promise<void> {
    logger.info('Starting update of all sanctions lists');
    
    try {
      await this.updateOFACList();
      // In production, you would also update EU and UN lists
      // await this.updateEUList();
      // await this.updateUNList();
      
      logger.info('All sanctions lists updated successfully');
    } catch (error) {
      logger.error('Error updating sanctions lists', {
        error: (error as Error).message
      });
      throw error;
    }
  }

  /**
   * Get last update timestamp for sanctions lists
   */
  async getLastUpdated(): Promise<number | null> {
    try {
      const timestamp = await this.redis.get<number>('sanctions:ofac:last_updated');
      return timestamp;
    } catch (error) {
      logger.error('Error getting last updated time', {
        error: (error as Error).message
      });
      return null;
    }
  }

  /**
   * Get statistics about sanctions lists
   */
  async getStatistics(): Promise<{
    ofacCount: number;
    euCount?: number;
    unCount?: number;
    lastUpdated: number | null;
  }> {
    try {
      const ofacCount = await this.redis.scard('sanctions:ofac:list');
      const lastUpdated = await this.getLastUpdated();
      
      return {
        ofacCount,
        lastUpdated
      };
    } catch (error) {
      logger.error('Error getting sanctions statistics', {
        error: (error as Error).message
      });
      
      return {
        ofacCount: 0,
        lastUpdated: null
      };
    }
  }
}