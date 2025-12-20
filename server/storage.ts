import { db } from "./db";
import { scans, type InsertScan, type Scan } from "@shared/schema";
import { eq, desc } from "drizzle-orm";

export interface IStorage {
  createScan(scan: InsertScan): Promise<Scan>;
  getScan(id: number): Promise<Scan | undefined>;
  getRecentScans(): Promise<Scan[]>;
  updateScan(id: number, updates: Partial<Scan>): Promise<Scan>;
}

export class DatabaseStorage implements IStorage {
  async createScan(insertScan: InsertScan): Promise<Scan> {
    const [scan] = await db
      .insert(scans)
      .values(insertScan)
      .returning();
    return scan;
  }

  async getScan(id: number): Promise<Scan | undefined> {
    const [scan] = await db
      .select()
      .from(scans)
      .where(eq(scans.id, id));
    return scan;
  }

  async getRecentScans(): Promise<Scan[]> {
    return await db
      .select()
      .from(scans)
      .orderBy(desc(scans.createdAt))
      .limit(10);
  }

  async updateScan(id: number, updates: Partial<Scan>): Promise<Scan> {
    const [updated] = await db
      .update(scans)
      .set(updates)
      .where(eq(scans.id, id))
      .returning();
    return updated;
  }
}

export const storage = new DatabaseStorage();
