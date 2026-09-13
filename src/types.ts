export type Classification = 'SAFE' | 'SUSPICIOUS' | 'HIGH RISK';

export interface WarningSign {
  id: string;
  severity: 'high' | 'medium' | 'low';
  title: string;
  description: string;
  category: string;
}

export interface CharacteristicCheck {
  key: string;
  label: string;
  status: 'safe' | 'warning' | 'danger' | 'info';
  score: number; // impact on risk score (0 to 100)
  details: string;
  observedValue?: string;
}

export interface UrlBreakdown {
  rawUrl: string;
  protocol: string;
  hostname: string;
  port: string;
  pathname: string;
  search: string;
  hash: string;
  subdomains: string[];
  rootDomain: string;
  tld: string;
  isIpAddress: boolean;
  length: number;
}

export interface UrlAnalysisResult {
  url: string;
  normalizedUrl: string;
  classification: Classification;
  riskScore: number; // 0 - 100
  shortExplanation: string;
  warningSigns: WarningSign[];
  characteristics: CharacteristicCheck[];
  breakdown: UrlBreakdown;
  safetyAdvice: string[];
  analyzedAt: string;
  isAiEnhanced?: boolean;
}
