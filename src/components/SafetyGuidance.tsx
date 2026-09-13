import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, EyeOff, CheckCircle2 } from 'lucide-react';
import { Classification } from '../types.ts';

interface SafetyGuidanceProps {
  classification: Classification;
  advice: string[];
}

export const SafetyGuidance: React.FC<SafetyGuidanceProps> = ({ classification, advice }) => {
  const getHeaderStyle = () => {
    switch (classification) {
      case 'HIGH RISK':
        return {
          icon: <ShieldAlert className="w-5 h-5 text-rose-400" />,
          title: 'Threat Containment Protocol',
          color: 'text-rose-300',
        };
      case 'SUSPICIOUS':
        return {
          icon: <AlertTriangle className="w-5 h-5 text-amber-400" />,
          title: 'Defensive Precautions',
          color: 'text-amber-300',
        };
      case 'SAFE':
      default:
        return {
          icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />,
          title: 'Safe Browsing Hygiene',
          color: 'text-emerald-300',
        };
    }
  };

  const header = getHeaderStyle();

  return (
    <div id="safety-guidance-section" className="space-y-3">
      <div className="flex items-center gap-2">
        {header.icon}
        <h4 className={`text-sm font-bold uppercase tracking-wider ${header.color}`}>
          {header.title}
        </h4>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {advice.map((item, idx) => (
          <div
            key={idx}
            className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-start gap-2.5 text-xs text-slate-300 leading-relaxed"
          >
            <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <span>{item}</span>
          </div>
        ))}
      </div>

      <div className="flex items-center gap-2 text-[11px] text-slate-500 pt-1">
        <EyeOff className="w-3.5 h-3.5" />
        <span>
          Static Analysis Guarantee: The URL string is parsed locally and through AI threat models without making HTTP requests, DNS lookups, or web connections to the target host.
        </span>
      </div>
    </div>
  );
};
