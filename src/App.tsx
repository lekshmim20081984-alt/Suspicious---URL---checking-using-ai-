import React, { useState, useEffect, useCallback } from 'react';
import { Shield, Sparkles, AlertCircle, RefreshCw, Lock } from 'lucide-react';
import { UrlAnalysisResult } from './types.ts';
import { analyzeUrlDeterministically } from './lib/urlAnalyzer.ts';
import { UrlInputBar } from './components/UrlInputBar.tsx';
import { AnalysisSummaryCard } from './components/AnalysisSummaryCard.tsx';
import { CharacteristicsGrid } from './components/CharacteristicsGrid.tsx';
import { WarningSignsList } from './components/WarningSignsList.tsx';
import { UrlBreakdownViewer } from './components/UrlBreakdownViewer.tsx';
import { SafetyGuidance } from './components/SafetyGuidance.tsx';
import { RecentAnalyses } from './components/RecentAnalyses.tsx';

const DEFAULT_SAMPLE = 'https://paypa1-security-verification.com/login?token=9283fjs';

export default function App() {
  const [urlInput, setUrlInput] = useState<string>(DEFAULT_SAMPLE);
  const [result, setResult] = useState<UrlAnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<UrlAnalysisResult[]>([]);

  const analyzeUrl = useCallback(async (target?: string) => {
    const toAnalyze = (target ?? urlInput).trim();
    if (!toAnalyze) {
      setError('Please enter a URL to inspect.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      // First try calling backend API with server-side Gemini intelligence
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: toAnalyze }),
      });

      if (response.ok) {
        const data: UrlAnalysisResult = await response.json();
        setResult(data);
        setHistory((prev) => {
          const filtered = prev.filter((item) => item.url !== data.url);
          return [data, ...filtered].slice(0, 10);
        });
      } else {
        // Fallback to deterministic client-side engine if server endpoint fails
        const fallback = analyzeUrlDeterministically(toAnalyze);
        setResult(fallback);
        setHistory((prev) => {
          const filtered = prev.filter((item) => item.url !== fallback.url);
          return [fallback, ...filtered].slice(0, 10);
        });
      }
    } catch {
      // Local client-side fallback ensures uninterrupted functionality
      const localResult = analyzeUrlDeterministically(toAnalyze);
      setResult(localResult);
      setHistory((prev) => {
        const filtered = prev.filter((item) => item.url !== localResult.url);
        return [localResult, ...filtered].slice(0, 10);
      });
    } finally {
      setIsLoading(false);
    }
  }, [urlInput]);

  // Initial automatic analysis of the default demo URL so users see a live interface immediately
  useEffect(() => {
    analyzeUrl(DEFAULT_SAMPLE);
  }, [analyzeUrl]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Header */}
      <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3.5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 text-cyan-400 shadow-lg shadow-cyan-500/10">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg sm:text-xl font-black tracking-tight text-white">
                  Suspicious URL Analyzer
                </h1>
                <span className="hidden sm:inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800/60">
                  <Sparkles className="w-3 h-3 text-cyan-400" />
                  AI Assisted
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Cyber threat intelligence & static string signature inspection
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="hidden md:inline">Safe Offline Sandbox</span>
              <span className="md:hidden">Offline Mode</span>
            </span>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 py-6 sm:py-8 space-y-8">
        {/* Input Bar & Samples */}
        <section id="analyzer-input-section" className="space-y-3">
          <UrlInputBar
            url={urlInput}
            setUrl={setUrlInput}
            onAnalyze={analyzeUrl}
            isLoading={isLoading}
          />
        </section>

        {error && (
          <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 flex items-center gap-3 text-sm">
            <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Results Presentation */}
        {result && (
          <div className="space-y-8 animate-fadeIn">
            {/* 1. Primary Classification & Risk Gauge */}
            <AnalysisSummaryCard result={result} />

            {/* 2. Warning Signs Found */}
            <WarningSignsList warningSigns={result.warningSigns} />

            {/* 3. The 9 Required Characteristics Matrix */}
            <CharacteristicsGrid characteristics={result.characteristics} />

            {/* 4. Structural Deconstruction */}
            <UrlBreakdownViewer breakdown={result.breakdown} />

            {/* 5. Actionable Guidance & Sandbox Guarantee */}
            <SafetyGuidance classification={result.classification} advice={result.safetyAdvice} />

            {/* 6. Session History */}
            <RecentAnalyses
              history={history}
              onSelect={(selected) => {
                setUrlInput(selected.url);
                setResult(selected);
              }}
              onClear={() => setHistory([])}
            />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/90 py-6 mt-12 text-center text-xs text-slate-500">
        <div className="max-w-6xl mx-auto px-4 space-y-2">
          <p>
            Suspicious URL Analyzer evaluates URL strings without resolving DNS, downloading payloads, or visiting destination hosts.
          </p>
          <p className="text-slate-600">
            Strict Security Mandate: HTTPS indicates transit encryption only; it does not verify website authenticity or benign intent.
          </p>
        </div>
      </footer>
    </div>
  );
}
