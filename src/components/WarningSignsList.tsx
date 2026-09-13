import React from 'react';
import { AlertCircle, AlertTriangle, Info, CheckCircle2 } from 'lucide-react';
import { WarningSign } from '../types.ts';

interface WarningSignsListProps {
  warningSigns: WarningSign[];
}

export const WarningSignsList: React.FC<WarningSignsListProps> = ({ warningSigns }) => {
  const getSeverityStyle = (sev: WarningSign['severity']) => {
    switch (sev) {
      case 'high':
        return {
          icon: <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />,
          badge: 'bg-rose-500/10 text-rose-300 border-rose-500/30',
          border: 'border-rose-500/30 bg-rose-950/20',
          label: 'High Severity',
        };
      case 'medium':
        return {
          icon: <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />,
          badge: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
          border: 'border-amber-500/30 bg-amber-950/20',
          label: 'Medium Severity',
        };
      case 'low':
      default:
        return {
          icon: <Info className="w-4 h-4 text-cyan-400 shrink-0" />,
          badge: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
          border: 'border-cyan-500/30 bg-cyan-950/20',
          label: 'Low / Advisory',
        };
    }
  };

  return (
    <div id="warning-signs-section" className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base sm:text-lg font-bold text-white flex items-center gap-2">
          <span>Warning Signs Found</span>
          <span
            className={`text-xs font-bold px-2 py-0.5 rounded-full ${
              warningSigns.length > 0
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
            }`}
          >
            {warningSigns.length} {warningSigns.length === 1 ? 'Anomaly' : 'Anomalies'}
          </span>
        </h3>
      </div>

      {warningSigns.length === 0 ? (
        <div
          id="no-warnings-banner"
          className="p-5 rounded-xl bg-slate-900/60 border border-emerald-500/30 flex items-center gap-3 text-emerald-300 text-sm"
        >
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          <div>
            <p className="font-semibold text-white">No Suspicious Warning Signs Detected</p>
            <p className="text-xs text-slate-300 mt-0.5">
              The URL does not contain known brand impersonation patterns, IP hosts, deceptive punctuation, or credential lures.
            </p>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {warningSigns.map((warning, idx) => {
            const style = getSeverityStyle(warning.severity);

            return (
              <div
                key={warning.id || idx}
                id={`warning-sign-item-${idx}`}
                className={`p-4 rounded-xl border ${style.border} transition-all space-y-2`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2">
                    {style.icon}
                    <h4 className="font-semibold text-white text-sm">
                      {warning.title}
                    </h4>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {warning.category}
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wide ${style.badge}`}>
                      {style.label}
                    </span>
                  </div>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed pl-6">
                  {warning.description}
                </p>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
