import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Unlock,
  Sparkles,
  Info,
  ExternalLink,
  Copy,
  Check,
} from 'lucide-react';
import { Classification, UrlAnalysisResult } from '../types.ts';

interface AnalysisSummaryCardProps {
  result: UrlAnalysisResult;
}

export const AnalysisSummaryCard: React.FC<AnalysisSummaryCardProps> = ({ result }) => {
  const [copied, setCopied] = React.useState(false);

  const handleCopyUrl = () => {
    navigator.clipboard.writeText(result.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getBadgeStyle = (classification: Classification) => {
    switch (classification) {
      case 'HIGH RISK':
        return {
          bg: 'bg-rose-500/10 border-rose-500/40 text-rose-300',
          indicator: 'bg-rose-500 shadow-rose-500/50',
          icon: <ShieldAlert className="w-8 h-8 text-rose-400" />,
          title: 'HIGH RISK',
          sub: 'Malicious or Severe Threat Patterns Detected',
          meterColor: 'from-rose-500 to-red-600',
          borderAccent: 'border-rose-500/30',
        };
      case 'SUSPICIOUS':
        return {
          bg: 'bg-amber-500/10 border-amber-500/40 text-amber-300',
          indicator: 'bg-amber-500 shadow-amber-500/50',
          icon: <AlertTriangle className="w-8 h-8 text-amber-400" />,
          title: 'SUSPICIOUS',
          sub: 'Deceptive or Anomalous Characteristics Present',
          meterColor: 'from-amber-400 to-orange-500',
          borderAccent: 'border-amber-500/30',
        };
      case 'SAFE':
      default:
        return {
          bg: 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300',
          indicator: 'bg-emerald-500 shadow-emerald-500/50',
          icon: <ShieldCheck className="w-8 h-8 text-emerald-400" />,
          title: 'SAFE',
          sub: 'Standard Domain Format & Clean URL Syntax',
          meterColor: 'from-emerald-400 to-teal-500',
          borderAccent: 'border-emerald-500/30',
        };
    }
  };

  const badge = getBadgeStyle(result.classification);
  const isHttps = result.breakdown.protocol === 'https:';

  return (
    <div
      id="analysis-summary-card"
      className={`relative overflow-hidden rounded-2xl bg-slate-900/90 border ${badge.borderAccent} shadow-2xl p-6 md:p-8 space-y-6`}
    >
      {/* Top Banner: Classification and Risk Score Gauge */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-slate-800">
        <div className="flex items-start gap-4">
          <div className={`p-3 rounded-2xl border ${badge.bg}`}>
            {badge.icon}
          </div>
          <div>
            <div className="flex items-center gap-3">
              <span
                id="classification-badge"
                className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-bold tracking-wider uppercase border ${badge.bg}`}
              >
                <span className={`w-2 h-2 rounded-full mr-2 animate-pulse ${badge.indicator}`} />
                {result.classification}
              </span>

              {result.isAiEnhanced && (
                <span
                  id="ai-enhanced-pill"
                  className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-950/80 text-cyan-300 border border-cyan-800/60"
                  title="Analysis enhanced with Gemini threat intelligence"
                >
                  <Sparkles className="w-3 h-3 text-cyan-400" />
                  AI Powered
                </span>
              )}
            </div>
            <p className="mt-1.5 text-slate-300 text-sm font-medium">{badge.sub}</p>
          </div>
        </div>

        {/* Risk Score Dial / Gauge */}
        <div id="risk-score-container" className="flex items-center gap-4 bg-slate-950/60 border border-slate-800 rounded-2xl p-4 min-w-[240px]">
          <div className="relative flex items-center justify-center">
            <svg className="w-20 h-20 transform -rotate-90" viewBox="0 0 36 36">
              <path
                className="text-slate-800"
                strokeWidth="3.5"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
              <path
                className={
                  result.riskScore >= 60
                    ? 'text-rose-500'
                    : result.riskScore >= 25
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }
                strokeDasharray={`${result.riskScore}, 100`}
                strokeWidth="3.5"
                strokeLinecap="round"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center">
              <span id="numeric-risk-score" className="text-xl font-black font-mono text-white">
                {result.riskScore}
              </span>
              <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider">
                / 100
              </span>
            </div>
          </div>

          <div className="flex-1">
            <div className="flex items-center justify-between text-xs text-slate-400 font-semibold mb-1">
              <span>Risk Score</span>
              <span
                className={
                  result.riskScore >= 60
                    ? 'text-rose-400'
                    : result.riskScore >= 25
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }
              >
                {result.riskScore >= 60 ? 'Critical' : result.riskScore >= 25 ? 'Moderate' : 'Low'}
              </span>
            </div>
            {/* Linear Progress Bar */}
            <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className={`h-full bg-gradient-to-r ${badge.meterColor} transition-all duration-500 rounded-full`}
                style={{ width: `${Math.max(4, result.riskScore)}%` }}
              />
            </div>
            <p className="text-[11px] text-slate-400 mt-1.5">
              {result.riskScore >= 60
                ? 'High probability of malicious intent'
                : result.riskScore >= 25
                ? 'Elevated caution advised'
                : 'Minimal risk indicators observed'}
            </p>
          </div>
        </div>
      </div>

      {/* Target URL string inspector line */}
      <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between gap-3 font-mono text-xs sm:text-sm">
        <div className="flex items-center gap-2 truncate text-slate-300">
          <span className="text-slate-400 font-sans font-semibold text-xs shrink-0">Analyzed Target:</span>
          <span className="text-cyan-300 truncate select-all">{result.url}</span>
        </div>
        <button
          type="button"
          id="btn-copy-analyzed-url"
          onClick={handleCopyUrl}
          className="shrink-0 flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 px-2 py-1 rounded bg-slate-900 border border-slate-700/60 transition-colors"
          title="Copy URL"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          <span className="hidden sm:inline">{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>

      {/* Short Explanation Section */}
      <div id="short-explanation-section" className="space-y-2">
        <h3 className="text-xs uppercase tracking-wider font-semibold text-slate-400 flex items-center gap-1.5">
          <Info className="w-4 h-4 text-cyan-400" />
          Short Explanation
        </h3>
        <p className="text-slate-200 text-sm sm:text-base leading-relaxed bg-slate-950/40 p-4 rounded-xl border border-slate-800/80">
          {result.shortExplanation}
        </p>
      </div>

      {/* MANDATORY HTTPS CAVEAT BANNER */}
      <div
        id="https-caveat-banner"
        className="flex items-start gap-3 p-4 rounded-xl bg-slate-950/80 border border-amber-500/30 text-xs text-amber-200/90 leading-relaxed"
      >
        <div className="p-1.5 rounded-lg bg-amber-500/20 text-amber-400 shrink-0 mt-0.5">
          {isHttps ? <Lock className="w-4 h-4" /> : <Unlock className="w-4 h-4 text-rose-400" />}
        </div>
        <div className="space-y-1">
          <div className="font-semibold text-amber-300 flex items-center gap-2">
            <span>Critical Security Note: HTTPS does NOT equal safe</span>
            <span className="text-[10px] px-1.5 py-0.5 bg-amber-500/20 text-amber-300 rounded font-mono">
              Protocol: {result.breakdown.protocol}
            </span>
          </div>
          <p className="text-slate-300 text-xs">
            {isHttps
              ? 'This URL utilizes HTTPS, meaning network data in transit is encrypted between your browser and the server. However, an HTTPS certificate alone is never proof of legitimacy. Over 80% of modern phishing websites utilize free, valid SSL/TLS certificates.'
              : 'This URL uses plain unencrypted HTTP. Any credentials, session cookies, or data transmitted over this connection can be intercepted or altered by unauthorized intermediaries.'}
          </p>
        </div>
      </div>
    </div>
  );
};
