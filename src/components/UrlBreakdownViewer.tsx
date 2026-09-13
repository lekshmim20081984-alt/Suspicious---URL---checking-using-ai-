import React from 'react';
import { UrlBreakdown } from '../types.ts';
import { Layers, Network, Terminal, Hash, FileCode } from 'lucide-react';

interface UrlBreakdownViewerProps {
  breakdown: UrlBreakdown;
}

export const UrlBreakdownViewer: React.FC<UrlBreakdownViewerProps> = ({ breakdown }) => {
  return (
    <div id="url-breakdown-section" className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base sm:text-lg font-bold text-white flex items-center gap-2">
          <Terminal className="w-5 h-5 text-cyan-400" />
          <span>Structural Deconstruction</span>
        </h3>
        <span className="text-xs text-slate-400 font-mono">
          Length: {breakdown.length} characters
        </span>
      </div>

      {/* Syntax-colored Interactive Component Breakdown */}
      <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl space-y-4">
        <div className="text-xs text-slate-400 font-semibold mb-2 flex items-center justify-between">
          <span>Component Breakdown:</span>
          <span className="text-slate-500 text-[11px]">Hover parts to view RFC role</span>
        </div>

        {/* Visual representation */}
        <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg font-mono text-xs sm:text-sm break-all flex flex-wrap items-center gap-1 leading-relaxed">
          <span
            className="px-1.5 py-0.5 rounded bg-blue-950/80 text-blue-300 border border-blue-800/60"
            title="Protocol Scheme"
          >
            {breakdown.protocol}//
          </span>

          {breakdown.subdomains.length > 0 && (
            <span
              className="px-1.5 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800/60"
              title="Subdomains"
            >
              {breakdown.subdomains.join('.')}.
            </span>
          )}

          <span
            className="px-1.5 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800/60 font-bold"
            title="Registered Root Domain"
          >
            {breakdown.rootDomain}
          </span>

          {breakdown.port && (
            <span
              className="px-1.5 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800/60"
              title="Port Number"
            >
              :{breakdown.port}
            </span>
          )}

          {breakdown.pathname && (
            <span
              className="px-1.5 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800/60"
              title="Resource Path"
            >
              {breakdown.pathname}
            </span>
          )}

          {breakdown.search && (
            <span
              className="px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/60"
              title="Query Parameters"
            >
              {breakdown.search}
            </span>
          )}

          {breakdown.hash && (
            <span
              className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700"
              title="URL Fragment / Hash"
            >
              {breakdown.hash}
            </span>
          )}
        </div>

        {/* Tabular detail metadata */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
          <div className="p-2.5 bg-slate-900/60 border border-slate-800/80 rounded-lg">
            <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-1">
              Registered Host
            </span>
            <span className="font-mono text-xs text-white font-medium truncate block">
              {breakdown.hostname || 'None'}
            </span>
          </div>

          <div className="p-2.5 bg-slate-900/60 border border-slate-800/80 rounded-lg">
            <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-1">
              Root Domain & TLD
            </span>
            <span className="font-mono text-xs text-cyan-300 font-medium truncate block">
              {breakdown.rootDomain || 'None'}
            </span>
          </div>

          <div className="p-2.5 bg-slate-900/60 border border-slate-800/80 rounded-lg">
            <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-1">
              Subdomain Tiers
            </span>
            <span className="font-mono text-xs text-white font-medium truncate block">
              {breakdown.subdomains.length > 0 ? breakdown.subdomains.join('.') : '(none)'}
            </span>
          </div>

          <div className="p-2.5 bg-slate-900/60 border border-slate-800/80 rounded-lg">
            <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-1">
              Host Type
            </span>
            <span
              className={`font-mono text-xs font-semibold ${
                breakdown.isIpAddress ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {breakdown.isIpAddress ? 'Raw IP Address' : 'DNS Domain'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
