import React from 'react';
import { History, ShieldAlert, ShieldCheck, AlertTriangle, ArrowUpRight, Trash2 } from 'lucide-react';
import { UrlAnalysisResult } from '../types.ts';

interface RecentAnalysesProps {
  history: UrlAnalysisResult[];
  onSelect: (result: UrlAnalysisResult) => void;
  onClear: () => void;
}

export const RecentAnalyses: React.FC<RecentAnalysesProps> = ({
  history,
  onSelect,
  onClear,
}) => {
  if (history.length === 0) return null;

  return (
    <div id="recent-analyses-history" className="space-y-3 pt-2">
      <div className="flex items-center justify-between">
        <h4 className="text-xs uppercase font-bold text-slate-400 flex items-center gap-1.5 tracking-wider">
          <History className="w-3.5 h-3.5 text-cyan-400" />
          Recent Session Analyses ({history.length})
        </h4>
        <button
          type="button"
          onClick={onClear}
          className="text-[11px] text-slate-500 hover:text-rose-400 flex items-center gap-1 transition-colors"
          title="Clear session history"
        >
          <Trash2 className="w-3 h-3" />
          Clear
        </button>
      </div>

      <div className="flex flex-col gap-2 max-h-48 overflow-y-auto pr-1">
        {history.map((item, idx) => {
          const isDanger = item.classification === 'HIGH RISK';
          const isSuspicious = item.classification === 'SUSPICIOUS';

          return (
            <button
              key={`${item.url}-${idx}`}
              type="button"
              onClick={() => onSelect(item)}
              className="w-full text-left p-2.5 rounded-lg bg-slate-900/80 hover:bg-slate-800/80 border border-slate-800 hover:border-slate-700 flex items-center justify-between gap-3 transition-all group"
            >
              <div className="flex items-center gap-2.5 min-w-0">
                {isDanger ? (
                  <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
                ) : isSuspicious ? (
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                ) : (
                  <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                )}
                <span className="font-mono text-xs text-slate-200 truncate group-hover:text-cyan-300">
                  {item.url}
                </span>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <span
                  className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase ${
                    isDanger
                      ? 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                      : isSuspicious
                      ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                      : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                  }`}
                >
                  {item.classification} ({item.riskScore})
                </span>
                <ArrowUpRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-slate-300 transition-colors" />
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
};
