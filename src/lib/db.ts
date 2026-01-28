// Mock database module for QuantumIQ Analysis System
// In production, this would connect to your actual database

export interface DatabaseConnection {
  collection(name: string): Collection;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
}

export interface Collection {
  insertOne(doc: any): Promise<{ acknowledged: boolean; insertedId: string }>;
  findOne(filter: any): Promise<any>;
  find(filter: any): Promise<any[]>;
  updateOne(filter: any, update: any): Promise<any>;
  deleteOne(filter: any): Promise<any>;
}

// Mock implementation for development purposes
class MockCollection implements Collection {
  private data: Map<string, any> = new Map();

  constructor(private name: string) {}

  async insertOne(doc: any) {
    const id = doc.id || `mock_id_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const docWithId = { ...doc, id };
    this.data.set(id, docWithId);
    return { acknowledged: true, insertedId: id };
  }

  async findOne(filter: any) {
    for (const [key, value] of this.data.entries()) {
      if (this.matchesFilter(value, filter)) {
        return value;
      }
    }
    return null;
  }

  async find(filter: any) {
    const results: any[] = [];
    for (const [key, value] of this.data.entries()) {
      if (this.matchesFilter(value, filter)) {
        results.push(value);
      }
    }
    return results;
  }

  async updateOne(filter: any, update: any) {
    for (const [key, value] of this.data.entries()) {
      if (this.matchesFilter(value, filter)) {
        const updatedValue = { ...value, ...update.$set };
        this.data.set(key, updatedValue);
        return { matchedCount: 1, modifiedCount: 1 };
      }
    }
    return { matchedCount: 0, modifiedCount: 0 };
  }

  async deleteOne(filter: any) {
    for (const [key, value] of this.data.entries()) {
      if (this.matchesFilter(value, filter)) {
        this.data.delete(key);
        return { deletedCount: 1 };
      }
    }
    return { deletedCount: 0 };
  }

  private matchesFilter(obj: any, filter: any): boolean {
    for (const [key, value] of Object.entries(filter)) {
      if (obj[key] !== value) {
        return false;
      }
    }
    return true;
  }
}

class MockDatabaseConnection implements DatabaseConnection {
  private collections: Map<string, Collection> = new Map();

  collection(name: string): Collection {
    if (!this.collections.has(name)) {
      this.collections.set(name, new MockCollection(name));
    }
    return this.collections.get(name)!;
  }

  async connect(): Promise<void> {
    console.log('Mock database connected');
  }

  async disconnect(): Promise<void> {
    console.log('Mock database disconnected');
  }
}

// Export a singleton instance for the mock database
export const db: DatabaseConnection = new MockDatabaseConnection();

// Initialize with some sample data if needed
export async function initializeDb() {
  await db.connect();
  console.log('Database initialized for QuantumIQ Analysis System');
}