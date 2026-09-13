import React, { useState } from 'react';
import { Search, ArrowRight, Clipboard, X, Sparkles, Globe } from 'lucide-react';

interface SampleUrl {
  label: string;
  category: 'safe' | 'suspicious' | 'high_risk';
  url: string;
}

const SAMPLE_URLS: SampleUrl[] = [
  {
    label: 'Legitimate Site (Wikipedia)',
    category: 'safe',
    url: 'https://www.wikipedia.org/wiki/Computer_security',
  },
  {
    label: 'Brand Look-Alike (PayPal Spoof)',
    category: 'high_risk',
    url: 'https://paypa1-security-verification.com/login?token=9283fjs',
  },
  {
    label: 'Raw IP Host (Phishing)',
    category: 'high_risk',
    url: 'http://192.168.1.150:8080/secure-update/login.php',
  },
  {
    label: 'Subdomain Brand Spoof',
    category: 'high_risk',
    url: 'http://chase.com.account-verify-login.xyz/portal?client_id=auth',
  },
  {
    label: 'Punycode Homograph',
    category: 'high_risk',
    url: 'https://xn--appl-43a.com/id/verify?account=locked',
  },
  {
    label: 'Open Redirect & Suspicious TLD',
    category: 'suspicious',
    url: 'https://track-package.top/status?redirect_to=http%3A%2F%2Fexternal-gate.cc%2Fcollect',
  },
];

interface UrlInputBarProps {
  url: string;
  setUrl: (val: string) => void;
  onAnalyze: (urlToAnalyze?: string) => void;
  isLoading: boolean;
}

export const UrlInputBar: React.FC<UrlInputBarProps> = ({
  url,
  setUrl,
  onAnalyze,
  isLoading,
}) => {
  const [pasteError, setPasteError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) {
      onAnalyze(url.trim());
    }
  };

  const handlePaste = async () => {
    try {
      setPasteError(null);
      if (navigator.clipboard && navigator.clipboard.readText) {
        const text = await navigator.clipboard.readText();
        if (text) {
          setUrl(text.trim());
          onAnalyze(text.trim());
        }
      }
    } catch {
      setPasteError('Clipboard access denied. Please paste manually.');
      setTimeout(() => setPasteError(null), 3000);
    }
  };

  const handleClear = () => {
    setUrl('');
  };

  return (
    <div id="url-input-container" className="w-full space-y-4">
      <form onSubmit={handleSubmit} className="relative">
        <div className="relative flex items-center bg-slate-900/90 border-2 border-slate-700 hover:border-slate-600 focus-within:border-cyan-500 focus-within:ring-4 focus-within:ring-cyan-500/20 rounded-2xl shadow-xl transition-all duration-200">
          <div className="pl-4 pr-2 text-slate-400">
            <Globe className="w-5 h-5 text-cyan-400" />
          </div>

          <input
            id="url-text-input"
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter any URL to analyze (e.g., https://example.com/path?param=value)"
            className="w-full py-4 pr-32 bg-transparent text-slate-100 placeholder-slate-500 text-base sm:text-lg focus:outline-none font-mono tracking-tight"
            autoComplete="off"
            spellCheck="false"
          />

          <div className="absolute right-2 flex items-center gap-1.5">
            {url && (
              <button
                type="button"
                id="btn-clear-url"
                onClick={handleClear}
                title="Clear input"
                className="p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            )}

            <button
              type="button"
              id="btn-paste-url"
              onClick={handlePaste}
              title="Paste from clipboard"
              className="hidden sm:inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 hover:text-white rounded-lg border border-slate-700 transition-colors"
            >
              <Clipboard className="w-3.5 h-3.5" />
              Paste
            </button>

            <button
              type="submit"
              id="btn-analyze-submit"
              disabled={isLoading || !url.trim()}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl shadow-lg shadow-cyan-500/25 transition-all active:scale-95"
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span className="text-sm">Analyzing...</span>
                </>
              ) : (
                <>
                  <span className="text-sm">Analyze</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </div>

        {pasteError && (
          <p className="mt-1 text-xs text-rose-400 pl-2">{pasteError}</p>
        )}
      </form>

      {/* Quick Test Samples */}
      <div id="sample-urls-section" className="space-y-2">
        <div className="flex items-center justify-between text-xs text-slate-400">
          <span className="flex items-center gap-1.5 font-medium">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            Quick Test Examples (Click to inspect):
          </span>
          <span className="text-slate-500">Static string analysis only &bull; No requests sent</span>
        </div>

        <div className="flex flex-wrap gap-2">
          {SAMPLE_URLS.map((sample, idx) => {
            const isBadgeDanger = sample.category === 'high_risk';
            const isBadgeSuspicious = sample.category === 'suspicious';
            const badgeBorder = isBadgeDanger
              ? 'border-rose-500/30 hover:border-rose-500/70 hover:bg-rose-950/40 text-rose-300'
              : isBadgeSuspicious
              ? 'border-amber-500/30 hover:border-amber-500/70 hover:bg-amber-950/40 text-amber-300'
              : 'border-emerald-500/30 hover:border-emerald-500/70 hover:bg-emerald-950/40 text-emerald-300';

            return (
              <button
                key={idx}
                id={`sample-btn-${idx}`}
                type="button"
                onClick={() => {
                  setUrl(sample.url);
                  onAnalyze(sample.url);
                }}
                className={`text-xs px-2.5 py-1.5 rounded-lg border bg-slate-900/60 transition-all font-mono text-left truncate max-w-full ${badgeBorder}`}
              >
                <span className="font-sans font-semibold mr-1.5 opacity-90">[{sample.label}]</span>
                <span className="opacity-70 text-[11px]">{sample.url.slice(0, 36)}...</span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};
