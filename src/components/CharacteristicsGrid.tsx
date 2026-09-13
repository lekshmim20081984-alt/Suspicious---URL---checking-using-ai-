import React from 'react';
import {
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Network,
  Globe2,
  Shield,
  Server,
  Binary,
  Layers,
  Ruler,
  ScanEye,
  FileCode2,
} from 'lucide-react';
import { CharacteristicCheck } from '../types.ts';

interface CharacteristicsGridProps {
  characteristics: CharacteristicCheck[];
}

export const CharacteristicsGrid: React.FC<CharacteristicsGridProps> = ({ characteristics }) => {
  const getIconForCheck = (key: string) => {
    switch (key) {
      case 'url_structure':
      case 'structure':
        return <Network className="w-5 h-5 text-cyan-400" />;
      case 'domain_name':
        return <Globe2 className="w-5 h-5 text-indigo-400" />;
      case 'https':
        return <Shield className="w-5 h-5 text-emerald-400" />;
      case 'ip_address':
        return <Server className="w-5 h-5 text-purple-400" />;
      case 'unusual_characters':
        return <Binary className="w-5 h-5 text-pink-400" />;
      case 'suspicious_subdomains':
        return <Layers className="w-5 h-5 text-blue-400" />;
      case 'url_length':
        return <Ruler className="w-5 h-5 text-teal-400" />;
      case 'lookalike_domains':
        return <ScanEye className="w-5 h-5 text-amber-400" />;
      case 'suspicious_parameters':
        return <FileCode2 className="w-5 h-5 text-orange-400" />;
      default:
        return <Shield className="w-5 h-5 text-slate-400" />;
    }
  };

  const getStatusBadge = (status: CharacteristicCheck['status']) => {
    switch (status) {
      case 'danger':
        return {
          icon: <XCircle className="w-4 h-4 text-rose-400 shrink-0" />,
          badge: 'bg-rose-500/10 text-rose-300 border-rose-500/30',
          text: 'Threat Detected',
          border: 'border-rose-500/30 bg-rose-950/10',
        };
      case 'warning':
        return {
          icon: <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />,
          badge: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
          text: 'Suspicious',
          border: 'border-amber-500/30 bg-amber-950/10',
        };
      case 'safe':
      default:
        return {
          icon: <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />,
          badge: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
          text: 'Pass / Safe',
          border: 'border-slate-800 bg-slate-900/60',
        };
    }
  };

  return (
    <div id="characteristics-grid-section" className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h3 className="text-base sm:text-lg font-bold text-white flex items-center gap-2">
            <span>Core Characteristic Analysis</span>
            <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-slate-800 text-cyan-300 border border-slate-700">
              {characteristics.length} Checks Inspected
            </span>
          </h3>
          <p className="text-xs text-slate-400">
            Comprehensive audit of structural, lexical, domain, and cryptographic attributes.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
        {characteristics.map((check) => {
          const statusStyle = getStatusBadge(check.status);
          const icon = getIconForCheck(check.key);

          return (
            <div
              key={check.key}
              id={`characteristic-card-${check.key}`}
              className={`p-4 rounded-xl border ${statusStyle.border} hover:border-slate-700 transition-all flex flex-col justify-between space-y-3`}
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <div className="p-1.5 rounded-lg bg-slate-800/80 border border-slate-700/60">
                      {icon}
                    </div>
                    <span className="text-sm font-semibold text-slate-200">
                      {check.label}
                    </span>
                  </div>

                  <span
                    className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${statusStyle.badge}`}
                  >
                    {statusStyle.icon}
                    {statusStyle.text}
                  </span>
                </div>

                {check.observedValue && (
                  <div className="px-2.5 py-1 bg-slate-950/70 border border-slate-800/80 rounded font-mono text-[11px] text-cyan-300 truncate">
                    <span className="text-slate-500 mr-1.5 font-sans">Observed:</span>
                    {check.observedValue}
                  </div>
                )}

                <p className="text-xs text-slate-300 leading-relaxed">
                  {check.details}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-400">
                <span>Risk Contribution</span>
                <span
                  className={`font-mono font-bold ${
                    check.score >= 35
                      ? 'text-rose-400'
                      : check.score > 0
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  +{check.score} pts
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
