import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { api } from "@shared/routes";
import { insertScanSchema } from "@shared/schema";
import axios from "axios";
import whois from "whois-json";
import validUrl from "valid-url";
import { z } from "zod";

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  
  app.post(api.scans.create.path, async (req, res) => {
    try {
      const input = insertScanSchema.parse(req.body);
      
      // Basic validation
      if (!validUrl.isWebUri(input.url)) {
        return res.status(400).json({ message: "Invalid URL format" });
      }

      // Create initial pending scan
      const scan = await storage.createScan(input);
      
      // Start async analysis (but we await it here for immediate results in this MVP)
      // In a production app, we might use a queue
      const analysis = await analyzeUrl(input.url);
      
      const updatedScan = await storage.updateScan(scan.id, {
        status: "completed",
        ...analysis
      });

      res.status(201).json(updatedScan);
    } catch (err) {
      console.error("Scan error:", err);
      if (err instanceof z.ZodError) {
        return res.status(400).json({
          message: err.errors[0].message,
          field: err.errors[0].path.join('.'),
        });
      }
      res.status(500).json({ message: "Internal server error" });
    }
  });

  app.get(api.scans.get.path, async (req, res) => {
    const scan = await storage.getScan(Number(req.params.id));
    if (!scan) {
      return res.status(404).json({ message: "Scan not found" });
    }
    res.json(scan);
  });

  app.get(api.scans.list.path, async (req, res) => {
    const scans = await storage.getRecentScans();
    res.json(scans);
  });

  return httpServer;
}

// === Analysis Logic ===

async function analyzeUrl(url: string) {
  // 1. Level 1: Keyword Analysis
  const level1 = analyzeKeywords(url);
  
  // 2. Level 2: Expansion
  const level2 = await analyzeExpansion(url);
  const targetUrl = level2.expandedUrl || url;
  
  // 3. Level 3: Safe Browsing
  const level3 = await analyzeSafeBrowsing(targetUrl);
  
  // 4. Level 4: Domain Age
  const level4 = await analyzeDomain(targetUrl);
  
  // 5. Level 5: Final Scoring
  const { score, riskLevel } = calculateRisk(level1, level2, level3, level4);
  
  return {
    score,
    riskLevel,
    details: { level1, level2, level3, level4 }
  };
}

function analyzeKeywords(url: string) {
  const suspiciousKeywords = ['login', 'verify', 'account', 'update', 'banking', 'secure', 'confirm', 'free', 'win', 'prize', 'gift'];
  const found = suspiciousKeywords.filter(k => url.toLowerCase().includes(k));
  
  const excessiveSymbols = (url.match(/[-_@.!#$%^&*]/g) || []).length > 5;
  
  let riskScore = 0;
  if (found.length > 0) riskScore += 0.3;
  if (excessiveSymbols) riskScore += 0.2;
  if (url.length > 100) riskScore += 0.1;
  
  return {
    hasSuspiciousKeywords: found.length > 0,
    suspiciousKeywordsFound: found,
    urlLength: url.length,
    excessiveSymbols,
    riskScore: Math.min(riskScore, 1)
  };
}

async function analyzeExpansion(url: string) {
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly'];
  const isShortened = shorteners.some(s => url.includes(s));
  
  let expandedUrl = null;
  const redirectChain: string[] = [];
  
  if (isShortened || url.length < 25) { // Simple heuristic
    try {
      const response = await axios.head(url, {
        maxRedirects: 5,
        validateStatus: () => true // Accept all status codes
      });
      // Axios follows redirects by default, so response.request.res.responseUrl is usually the final one
      // But for HEAD it might be different. Let's rely on checking if the final URL is different
      if (response.request.res && response.request.res.responseUrl && response.request.res.responseUrl !== url) {
        expandedUrl = response.request.res.responseUrl;
      }
    } catch (e) {
      console.log("Expansion failed", e);
    }
  }
  
  return {
    isShortened,
    expandedUrl,
    redirectChain // Keeping empty for now as axios auto-follows
  };
}

async function analyzeSafeBrowsing(url: string) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) {
    console.log("Skipping Safe Browsing check: No API Key");
    return { safeBrowsingMatch: false, threatType: null };
  }

  try {
    const response = await axios.post(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      client: {
        clientId: "replit-spam-detector",
        clientVersion: "1.0.0"
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    });

    const matches = response.data.matches;
    if (matches && matches.length > 0) {
      return {
        safeBrowsingMatch: true,
        threatType: matches[0].threatType
      };
    }
  } catch (e) {
    console.error("Safe Browsing API error", e);
  }

  return { safeBrowsingMatch: false, threatType: null };
}

async function analyzeDomain(url: string) {
  let domain = "";
  try {
    const parsed = new URL(url);
    domain = parsed.hostname;
  } catch {
    return { domainAgeDays: null, hasHttps: false, registrar: null, creationDate: null };
  }

  const hasHttps = url.startsWith("https://");
  
  let domainAgeDays = null;
  let registrar = null;
  let creationDate = null;

  try {
    const data = await whois(domain);
    if (data.creationDate) {
      const created = new Date(data.creationDate);
      creationDate = created.toISOString();
      const now = new Date();
      const diffTime = Math.abs(now.getTime() - created.getTime());
      domainAgeDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 
    }
    registrar = data.registrar;
  } catch (e) {
    console.log("WHOIS failed", e);
  }

  return {
    domainAgeDays,
    hasHttps,
    registrar,
    creationDate
  };
}

function calculateRisk(l1: any, l2: any, l3: any, l4: any) {
  let score = 0;
  
  // Level 1: Keywords
  score += l1.riskScore;
  
  // Level 2: Hidden behind shortener
  if (l2.isShortened) score += 0.15;
  
  // Level 3: Safe Browsing (Critical)
  if (l3.safeBrowsingMatch) score = 1.0; // Immediate max risk
  
  // Level 4: Domain Trust
  if (!l4.hasHttps) score += 0.15;
  if (l4.domainAgeDays !== null && l4.domainAgeDays < 30) score += 0.25;
  
  // Cap score
  score = Math.min(score, 1.0);
  
  let riskLevel = "Safe";
  if (score > 0.75) riskLevel = "Spam";
  else if (score > 0.50) riskLevel = "Suspicious";
  else if (score > 0.25) riskLevel = "Low Risk";
  
  // Override if Safe Browsing matched
  if (l3.safeBrowsingMatch) riskLevel = "Spam";

  return { score, riskLevel };
}
