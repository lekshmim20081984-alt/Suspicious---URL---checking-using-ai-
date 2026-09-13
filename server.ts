import { GoogleGenAI, Type } from '@google/genai';
import dotenv from 'dotenv';
import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { analyzeUrlDeterministically } from './src/lib/urlAnalyzer.ts';
import { UrlAnalysisResult, WarningSign } from './src/types.ts';

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '1mb' }));

// Initialize Gemini SDK with User-Agent header as required
let genAi: GoogleGenAI | null = null;
if (process.env.GEMINI_API_KEY) {
  genAi = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    hasAi: Boolean(process.env.GEMINI_API_KEY),
    timestamp: new Date().toISOString(),
  });
});

// URL Analysis endpoint
app.post('/api/analyze', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== 'string' || !url.trim()) {
      return res.status(400).json({ error: 'A valid URL string is required.' });
    }

    // 1. Run rigorous deterministic heuristic & RFC breakdown
    const baseResult: UrlAnalysisResult = analyzeUrlDeterministically(url.trim());

    // If Gemini is not configured, return the deterministic result
    if (!genAi || !process.env.GEMINI_API_KEY) {
      return res.json(baseResult);
    }

    // 2. Enhance with Gemini AI cybersecurity intelligence
    try {
      const prompt = `Analyze this URL string for suspicious patterns, phishing, brand impersonation, and security risks.

URL String to analyze: "${baseResult.url}"
Parsed Hostname: "${baseResult.breakdown.hostname}"
Parsed Protocol: "${baseResult.breakdown.protocol}"
Parsed Path: "${baseResult.breakdown.pathname}"
Parsed Query: "${baseResult.breakdown.search}"
Is IP Host: ${baseResult.breakdown.isIpAddress}
Root Domain: "${baseResult.breakdown.rootDomain}"
TLD: "${baseResult.breakdown.tld}"
Subdomains: [${baseResult.breakdown.subdomains.join(', ')}]
Heuristic Warning Signs Found: ${JSON.stringify(baseResult.warningSigns.map(w => w.title))}

CRITICAL RULES:
1. Do NOT visit, open, or fetch the URL. Analyze only the textual string.
2. Do NOT claim that a URL is definitely safe just because it uses HTTPS. HTTPS only encrypts the connection in transit; threat actors routinely use valid SSL/TLS certificates.
3. Check all 9 characteristics: URL structure, domain name, HTTPS, IP address usage, unusual characters, suspicious subdomains, excessive URL length, misleading or look-alike domains, suspicious parameters.
4. Output classification must be strictly one of: "SAFE", "SUSPICIOUS", "HIGH RISK".
5. Output riskScore must be an integer from 0 to 100.
6. Provide a concise, professional 2-3 sentence shortExplanation.
7. List any specific warning signs observed.`;

      const aiResponse = await genAi.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          systemInstruction: 'You are an AI-based Suspicious URL Analyzer and cybersecurity threat detection specialist. Analyze the input URL string strictly without opening it. You evaluate phishing indicators, deceptive look-alikes, IP address hosts, obfuscation, punycode, unusual characters, and suspicious parameters. Never treat HTTPS as proof of safety.',
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              classification: {
                type: Type.STRING,
                description: 'Must be SAFE, SUSPICIOUS, or HIGH RISK',
              },
              riskScore: {
                type: Type.INTEGER,
                description: 'Risk score from 0 (completely safe) to 100 (maximum risk / malicious)',
              },
              shortExplanation: {
                type: Type.STRING,
                description: 'Short explanation of findings and risk reasoning',
              },
              warningSigns: {
                type: Type.ARRAY,
                description: 'Warning signs detected in the URL string',
                items: {
                  type: Type.OBJECT,
                  properties: {
                    title: { type: Type.STRING },
                    description: { type: Type.STRING },
                    severity: { type: Type.STRING, description: 'high, medium, or low' },
                    category: { type: Type.STRING },
                  },
                  required: ['title', 'description', 'severity', 'category'],
                },
              },
            },
            required: ['classification', 'riskScore', 'shortExplanation', 'warningSigns'],
          },
        },
      });

      const aiText = aiResponse.text;
      if (aiText) {
        const parsedAi = JSON.parse(aiText);

        // Normalize classification to valid enum
        let validClassification: 'SAFE' | 'SUSPICIOUS' | 'HIGH RISK' = baseResult.classification;
        const rawClass = String(parsedAi.classification || '').toUpperCase();
        if (rawClass === 'SAFE' || rawClass === 'SUSPICIOUS' || rawClass === 'HIGH RISK') {
          validClassification = rawClass;
        }

        // Calibrate risk score (combine AI evaluation with heuristic ground truth to avoid false negatives)
        let aiScore = typeof parsedAi.riskScore === 'number' ? Math.round(parsedAi.riskScore) : baseResult.riskScore;
        aiScore = Math.max(0, Math.min(100, aiScore));

        // If heuristics detected a critical threat (like raw IP, direct brand spoofing, or deceptive @), enforce minimum risk floor
        if (baseResult.classification === 'HIGH RISK' && validClassification === 'SAFE') {
          validClassification = 'HIGH RISK';
          aiScore = Math.max(aiScore, 75);
        } else if (baseResult.classification === 'SUSPICIOUS' && validClassification === 'SAFE' && baseResult.riskScore > 35) {
          validClassification = 'SUSPICIOUS';
          aiScore = Math.max(aiScore, 35);
        }

        // Format warning signs cleanly
        const mergedWarnings: WarningSign[] = [];
        const seenTitles = new Set<string>();

        // Incorporate AI warning signs
        if (Array.isArray(parsedAi.warningSigns)) {
          for (let i = 0; i < parsedAi.warningSigns.length; i++) {
            const w = parsedAi.warningSigns[i];
            const title = String(w.title || '').trim();
            if (title && !seenTitles.has(title.toLowerCase())) {
              seenTitles.add(title.toLowerCase());
              mergedWarnings.push({
                id: `ai_warn_${i}`,
                severity: (w.severity === 'high' || w.severity === 'medium' || w.severity === 'low') ? w.severity : 'medium',
                title: w.title,
                description: w.description || '',
                category: w.category || 'AI Threat Detection',
              });
            }
          }
        }

        // Merge any deterministic warnings that weren't captured
        for (const dw of baseResult.warningSigns) {
          if (!seenTitles.has(dw.title.toLowerCase())) {
            seenTitles.add(dw.title.toLowerCase());
            mergedWarnings.push(dw);
          }
        }

        const mergedResult: UrlAnalysisResult = {
          ...baseResult,
          classification: validClassification,
          riskScore: aiScore,
          shortExplanation: parsedAi.shortExplanation || baseResult.shortExplanation,
          warningSigns: mergedWarnings,
          isAiEnhanced: true,
        };

        return res.json(mergedResult);
      }
    } catch (aiErr) {
      console.warn('Gemini AI analysis error, falling back to heuristic engine:', aiErr);
      // Seamless fallback to deterministic engine
      return res.json(baseResult);
    }

    return res.json(baseResult);
  } catch (err: unknown) {
    console.error('Analysis endpoint failure:', err);
    res.status(500).json({ error: (err as Error).message || 'Failed to analyze URL' });
  }
});

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Suspicious URL Analyzer server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
