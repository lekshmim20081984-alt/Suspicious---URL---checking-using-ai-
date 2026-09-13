import {
  Classification,
  CharacteristicCheck,
  UrlAnalysisResult,
  UrlBreakdown,
  WarningSign,
} from '../types.ts';

// Common high-profile targets for typosquatting / phishing
const TARGETED_BRANDS: Array<{ name: string; root: string; regex: RegExp; typos: RegExp[] }> = [
  {
    name: 'PayPal',
    root: 'paypal.com',
    regex: /paypal/i,
    typos: [/paypa[l1i]/i, /pay-pal/i, /paypaI/i, /peypal/i],
  },
  {
    name: 'Apple',
    root: 'apple.com',
    regex: /apple/i,
    typos: [/app[l1i]e/i, /aple/i, /app-le/i, /appl/i],
  },
  {
    name: 'Google',
    root: 'google.com',
    regex: /google/i,
    typos: [/g[o0][o0]g[l1i]e/i, /gogle/i, /googie/i, /goog-le/i],
  },
  {
    name: 'Microsoft',
    root: 'microsoft.com',
    regex: /microsoft/i,
    typos: [/micr[o0]s[o0]ft/i, /m1crosoft/i, /micro-soft/i, /msft/i],
  },
  {
    name: 'Amazon',
    root: 'amazon.com',
    regex: /amazon/i,
    typos: [/arnazon/i, /amaz[o0]n/i, /amazn/i, /amzn-verify/i],
  },
  {
    name: 'Netflix',
    root: 'netflix.com',
    regex: /netflix/i,
    typos: [/netfl[i1]x/i, /net-flix/i, /netf1ix/i],
  },
  {
    name: 'Chase Bank',
    root: 'chase.com',
    regex: /chase/i,
    typos: [/ch[a4]se/i, /chasee/i, /chase-bank/i],
  },
  {
    name: 'Facebook / Meta',
    root: 'facebook.com',
    regex: /facebook/i,
    typos: [/faceb[o0][o0]k/i, /face-book/i, /facbook/i],
  },
  {
    name: 'Bank of America',
    root: 'bankofamerica.com',
    regex: /bankofamerica/i,
    typos: [/bank[o0]famerica/i, /bofa-security/i],
  },
  {
    name: 'Wells Fargo',
    root: 'wellsfargo.com',
    regex: /wellsfargo/i,
    typos: [/wells-fargo/i, /weilsfargo/i, /wellsfarg[o0]/i],
  },
  {
    name: 'Coinbase',
    root: 'coinbase.com',
    regex: /coinbase/i,
    typos: [/c[o0][i1]nbase/i, /coin-base/i],
  },
  {
    name: 'Steam',
    root: 'steampowered.com',
    regex: /steampowered|steamcommunity/i,
    typos: [/stearmpowered/i, /steamcornmunity/i, /steam-community/i],
  },
];

// High risk / abused TLDs often correlated with disposable phishing & malware campaigns
const SUSPICIOUS_TLDS = new Set([
  'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'work', 'download',
  'cfd', 'rest', 'country', 'stream', 'click', 'link', 'racing', 'win',
  'bid', 'loan', 'cam', 'sbs', 'monster', 'icu', 'fit', 'party'
]);

// Suspicious parameter keys commonly associated with credential harvesting or open redirects
const SUSPICIOUS_PARAM_KEYS = [
  'password', 'pass', 'pwd', 'token', 'auth', 'redirect', 'redirect_to',
  'redirect_url', 'return_url', 'target', 'dest', 'destination', 'goto',
  'url', 'next', 'account_number', 'ssn', 'pin', 'cvv', 'session_id', 'relay'
];

// Phishing urgency / lure keywords
const SUSPICIOUS_PATH_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
  'update', 'confirm', 'confirmation', 'billing', 'security-check',
  'account-recovery', 'unlock', 'suspend', 'suspended', 'auth', 'portal',
  'wallet', 're-auth', 'restore'
];

export function parseUrlSafely(input: string): { parsed: URL | null; raw: string; error?: string } {
  let trimmed = (input || '').trim();
  if (!trimmed) {
    return { parsed: null, raw: trimmed, error: 'Empty URL provided' };
  }

  // Prepend https:// if no protocol was supplied so URL parsing succeeds
  const hasProtocol = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed);
  let urlToParse = trimmed;
  if (!hasProtocol) {
    urlToParse = 'https://' + trimmed;
  }

  try {
    const parsed = new URL(urlToParse);
    return { parsed, raw: trimmed };
  } catch (err: unknown) {
    return { parsed: null, raw: trimmed, error: (err as Error).message || 'Invalid URL syntax' };
  }
}

export function extractBreakdown(rawUrl: string, parsed: URL): UrlBreakdown {
  const hostname = parsed.hostname.toLowerCase();
  const isIpV4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isIpV6 = /^\[?[0-9a-fA-F:]+\]?$/.test(hostname) && hostname.includes(':');
  const isIpAddress = isIpV4 || isIpV6;

  const parts = hostname.split('.');
  let tld = '';
  let rootDomain = hostname;
  const subdomains: string[] = [];

  if (!isIpAddress && parts.length >= 2) {
    // Basic ccTLD handling (e.g. .co.uk, .com.au)
    const secondLevelTlds = ['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'gov.uk', 'org.uk'];
    const lastTwo = parts.slice(-2).join('.');
    if (secondLevelTlds.includes(lastTwo) && parts.length >= 3) {
      tld = lastTwo;
      rootDomain = parts.slice(-3).join('.');
      subdomains.push(...parts.slice(0, -3));
    } else {
      tld = parts[parts.length - 1];
      rootDomain = parts.slice(-2).join('.');
      subdomains.push(...parts.slice(0, -2));
    }
  }

  return {
    rawUrl,
    protocol: parsed.protocol,
    hostname,
    port: parsed.port,
    pathname: parsed.pathname,
    search: parsed.search,
    hash: parsed.hash,
    subdomains,
    rootDomain,
    tld,
    isIpAddress,
    length: rawUrl.length,
  };
}

export function analyzeUrlDeterministically(rawInput: string): UrlAnalysisResult {
  const { parsed, raw, error } = parseUrlSafely(rawInput);

  if (!parsed || error) {
    const brokenBreakdown: UrlBreakdown = {
      rawUrl: rawInput,
      protocol: 'unknown:',
      hostname: 'invalid-url',
      port: '',
      pathname: '',
      search: '',
      hash: '',
      subdomains: [],
      rootDomain: 'invalid',
      tld: '',
      isIpAddress: false,
      length: rawInput.length,
    };

    return {
      url: rawInput,
      normalizedUrl: rawInput,
      classification: 'HIGH RISK',
      riskScore: 85,
      shortExplanation: 'The provided string has an invalid or malformed URL structure, which is commonly used to evade basic string sanitizers or crash URL parsers.',
      warningSigns: [
        {
          id: 'malformed_url',
          severity: 'high',
          title: 'Malformed URL Syntax',
          description: error || 'Failed to parse into a valid RFC 3986 URL.',
          category: 'URL Structure',
        },
      ],
      characteristics: [
        {
          key: 'structure',
          label: 'URL Structure',
          status: 'danger',
          score: 85,
          details: 'Syntax is invalid or malformed.',
        },
      ],
      breakdown: brokenBreakdown,
      safetyAdvice: [
        'Do not paste this string into a browser address bar.',
        'Malformed URLs often attempt to exploit parser vulnerabilities in web gateways.',
      ],
      analyzedAt: new Date().toISOString(),
      isAiEnhanced: false,
    };
  }

  const breakdown = extractBreakdown(raw, parsed);
  const warningSigns: WarningSign[] = [];
  const checks: CharacteristicCheck[] = [];
  let calculatedScore = 0;

  // -------------------------------------------------------------
  // 1. HTTPS Check & Strict Rule: HTTPS does NOT equal safe!
  // -------------------------------------------------------------
  const isHttps = breakdown.protocol === 'https:';
  const isHttp = breakdown.protocol === 'http:';

  if (isHttp) {
    calculatedScore += 22;
    warningSigns.push({
      id: 'missing_https',
      severity: 'medium',
      title: 'Insecure Protocol (HTTP)',
      description: 'The URL uses plain unencrypted HTTP instead of HTTPS. All credentials and network packets can be intercepted in transit.',
      category: 'HTTPS',
    });
    checks.push({
      key: 'https',
      label: 'HTTPS Security',
      status: 'warning',
      score: 22,
      details: 'Insecure unencrypted HTTP protocol.',
      observedValue: 'http://',
    });
  } else if (isHttps) {
    // Crucial requirement: Do not claim that a URL is definitely safe just because it uses HTTPS.
    checks.push({
      key: 'https',
      label: 'HTTPS Security',
      status: 'safe',
      score: 0,
      details: 'HTTPS is present; traffic in transit is encrypted. Note: Over 80% of phishing sites use free HTTPS certificates, so this does not guarantee legitimacy.',
      observedValue: 'https://',
    });
  } else {
    calculatedScore += 35;
    warningSigns.push({
      id: 'unusual_protocol',
      severity: 'high',
      title: 'Suspicious Non-Web Protocol',
      description: `Protocol "${breakdown.protocol}" is not standard HTTP/HTTPS. It may trigger arbitrary client applications or scripts.`,
      category: 'HTTPS',
    });
    checks.push({
      key: 'https',
      label: 'HTTPS Security',
      status: 'danger',
      score: 35,
      details: `Non-standard web protocol: ${breakdown.protocol}`,
      observedValue: breakdown.protocol,
    });
  }

  // -------------------------------------------------------------
  // 2. IP Address Usage
  // -------------------------------------------------------------
  if (breakdown.isIpAddress) {
    calculatedScore += 45;
    warningSigns.push({
      id: 'ip_address_host',
      severity: 'high',
      title: 'Raw IP Address Instead of Domain',
      description: 'Legitimate services use registered domain names. Direct IP addresses are predominantly used by cyber attackers to bypass domain blacklists or host disposable command-and-control servers.',
      category: 'IP Address Usage',
    });
    checks.push({
      key: 'ip_address',
      label: 'IP Address Usage',
      status: 'danger',
      score: 45,
      details: `Raw IP address used as hostname: ${breakdown.hostname}`,
      observedValue: breakdown.hostname,
    });
  } else {
    // Check if hostname looks like hex/dword obfuscated IP
    const isHexOrDword = /^0x[0-9a-f]+$/i.test(breakdown.hostname) || /^\d{8,10}$/.test(breakdown.hostname);
    if (isHexOrDword) {
      calculatedScore += 50;
      warningSigns.push({
        id: 'obfuscated_ip_host',
        severity: 'high',
        title: 'Obfuscated Hex/Dword IP Address',
        description: 'The host appears to be a decimal or hexadecimal encoded IP address designed to circumvent security filters.',
        category: 'IP Address Usage',
      });
      checks.push({
        key: 'ip_address',
        label: 'IP Address Usage',
        status: 'danger',
        score: 50,
        details: 'Obfuscated numerical/hexadecimal host representation.',
        observedValue: breakdown.hostname,
      });
    } else {
      checks.push({
        key: 'ip_address',
        label: 'IP Address Usage',
        status: 'safe',
        score: 0,
        details: 'Uses standard alphanumeric domain name rather than a raw IP address.',
        observedValue: 'Standard Domain Name',
      });
    }
  }

  // -------------------------------------------------------------
  // 3. Unusual Characters & Homographs (Punycode, @, etc.)
  // -------------------------------------------------------------
  const hasAtSymbol = raw.includes('@') || parsed.username !== '' || parsed.password !== '';
  const isPunycode = breakdown.hostname.includes('xn--');
  const hasExcessiveHyphens = (breakdown.hostname.match(/-/g) || []).length >= 3;
  const hasMultipleDots = (breakdown.hostname.match(/\./g) || []).length >= 4;
  const hasEncodedChars = /%[0-9a-f]{2}/i.test(breakdown.hostname) || /%2e|%2f|%40/i.test(raw);

  let unusualScore = 0;
  const unusualNotes: string[] = [];

  if (hasAtSymbol) {
    unusualScore += 40;
    warningSigns.push({
      id: 'at_symbol_deception',
      severity: 'high',
      title: 'Deceptive "@" Authority Symbol',
      description: 'The URL contains an "@" symbol. Modern browsers treat text before "@" as basic authentication credentials and only connect to the domain following the "@", allowing attackers to disguise malicious destinations.',
      category: 'Unusual Characters',
    });
    unusualNotes.push('Contains deceptive "@" symbol in URL authority');
  }

  if (isPunycode) {
    unusualScore += 35;
    warningSigns.push({
      id: 'punycode_homograph',
      severity: 'high',
      title: 'Punycode / IDN Homograph Detected',
      description: 'Host contains "xn--" punycode prefix. Attackers frequently use Cyrillic or Greek homoglyphs that look visually identical to Latin characters (e.g. Cyrillic "а" mimicking Latin "a") to deceive victims.',
      category: 'Unusual Characters',
    });
    unusualNotes.push('Punycode ("xn--") domain detected');
  }

  if (hasExcessiveHyphens) {
    unusualScore += 20;
    warningSigns.push({
      id: 'excessive_hyphens',
      severity: 'medium',
      title: 'Excessive Hyphens in Domain',
      description: `Domain contains ${(breakdown.hostname.match(/-/g) || []).length} hyphens. Attackers chain brand keywords and security terms using hyphens (e.g. "paypal-security-login-portal").`,
      category: 'Unusual Characters',
    });
    unusualNotes.push('Abnormal hyphen density');
  }

  if (hasEncodedChars) {
    unusualScore += 18;
    warningSigns.push({
      id: 'percent_encoding_evasion',
      severity: 'medium',
      title: 'Hex/Percent Encoding in Critical URL Parts',
      description: 'Contains percent-encoded slashes, dots, or characters, frequently used in filter evasion and directory traversal attempts.',
      category: 'Unusual Characters',
    });
    unusualNotes.push('Percent-encoded critical characters');
  }

  calculatedScore += unusualScore;
  checks.push({
    key: 'unusual_characters',
    label: 'Unusual Characters',
    status: unusualScore >= 35 ? 'danger' : unusualScore > 0 ? 'warning' : 'safe',
    score: unusualScore,
    details: unusualNotes.length > 0 ? unusualNotes.join(', ') : 'No deceptive characters, punycode, or "@" symbols found.',
    observedValue: isPunycode ? 'xn-- (Punycode)' : hasAtSymbol ? 'Contains @' : 'Clean character set',
  });

  // -------------------------------------------------------------
  // 4. Suspicious Subdomains
  // -------------------------------------------------------------
  let subdomainScore = 0;
  const subdomainNotes: string[] = [];
  const subdomainCount = breakdown.subdomains.length;

  if (subdomainCount >= 3) {
    subdomainScore += 25;
    warningSigns.push({
      id: 'deep_subdomain_nesting',
      severity: 'medium',
      title: 'Excessive Subdomain Depth',
      description: `Domain contains ${subdomainCount} subdomain tiers (${breakdown.subdomains.join('.')}). Attackers nest subdomains to obscure the real domain on compact mobile browser viewports.`,
      category: 'Suspicious Subdomains',
    });
    subdomainNotes.push(`${subdomainCount} subdomain levels`);
  }

  // Check if a known brand is located inside a SUBDOMAIN rather than the root domain
  let brandInSubdomain: string | null = null;
  for (const brand of TARGETED_BRANDS) {
    const inSub = breakdown.subdomains.some(s => brand.regex.test(s));
    const isRealBrandRoot = breakdown.rootDomain === brand.root;
    if (inSub && !isRealBrandRoot) {
      brandInSubdomain = brand.name;
      break;
    }
  }

  if (brandInSubdomain) {
    subdomainScore += 45;
    warningSigns.push({
      id: 'brand_in_subdomain_spoof',
      severity: 'high',
      title: `Brand Name (${brandInSubdomain}) Spoofed in Subdomain`,
      description: `The subdomain references "${brandInSubdomain}", but the actual root domain is "${breakdown.rootDomain}". This is a classic phishing technique to fool users into believing they are visiting an official site.`,
      category: 'Suspicious Subdomains',
    });
    subdomainNotes.push(`Spoofed brand "${brandInSubdomain}" placed in subdomain`);
  }

  // Check for suspicious subdomain keywords like "login.bank", "update-account", etc.
  const joinedSubdomains = breakdown.subdomains.join('.');
  const hasLureInSubdomain = SUSPICIOUS_PATH_KEYWORDS.some(kw => joinedSubdomains.includes(kw));
  if (hasLureInSubdomain && !brandInSubdomain) {
    subdomainScore += 15;
    subdomainNotes.push('Subdomain contains credential/security lure keywords');
  }

  calculatedScore += subdomainScore;
  checks.push({
    key: 'suspicious_subdomains',
    label: 'Suspicious Subdomains',
    status: subdomainScore >= 40 ? 'danger' : subdomainScore > 0 ? 'warning' : 'safe',
    score: subdomainScore,
    details: subdomainNotes.length > 0 ? subdomainNotes.join('; ') : 'Subdomain hierarchy is standard and well-formed.',
    observedValue: breakdown.subdomains.length > 0 ? breakdown.subdomains.join('.') : '(none)',
  });

  // -------------------------------------------------------------
  // 5. Misleading or Look-Alike Domains (Typosquatting & Combosquatting)
  // -------------------------------------------------------------
  let lookalikeScore = 0;
  const lookalikeNotes: string[] = [];

  for (const brand of TARGETED_BRANDS) {
    const isAuthentic = breakdown.rootDomain === brand.root;
    if (isAuthentic) continue;

    // Check typosquatting in root domain
    const rootMatchesTypo = brand.typos.some(typo => typo.test(breakdown.rootDomain));
    const rootContainsBrand = brand.regex.test(breakdown.rootDomain);

    if (rootMatchesTypo && !isAuthentic) {
      lookalikeScore += 50;
      warningSigns.push({
        id: `typosquat_${brand.name.toLowerCase()}`,
        severity: 'high',
        title: `Look-Alike / Typosquatting of ${brand.name}`,
        description: `The domain "${breakdown.rootDomain}" closely mimics the legitimate brand "${brand.name}" (${brand.root}) with minor typographical substitutions.`,
        category: 'Look-Alike Domains',
      });
      lookalikeNotes.push(`Direct typosquat of ${brand.name}`);
      break;
    } else if (rootContainsBrand && !isAuthentic) {
      lookalikeScore += 45;
      warningSigns.push({
        id: `combosquat_${brand.name.toLowerCase()}`,
        severity: 'high',
        title: `Combosquatting Brand Impersonation (${brand.name})`,
        description: `Domain "${breakdown.rootDomain}" embeds the trademarked brand name "${brand.name}" alongside other words or hyphens to manufacture false credibility.`,
        category: 'Look-Alike Domains',
      });
      lookalikeNotes.push(`Combosquatting on brand "${brand.name}"`);
      break;
    }
  }

  // Levenshtein distance check against standard common domains if not already matched
  if (lookalikeScore === 0) {
    // Check general character substitutions (e.g. 0 for o, 1 for l, rn for m)
    if (/[a-z]0[a-z]/i.test(breakdown.rootDomain) && !/\.gov|\.edu/.test(breakdown.rootDomain)) {
      lookalikeScore += 15;
      lookalikeNotes.push('Contains potential digit-for-letter substitution (e.g., "0" instead of "o")');
    }
  }

  calculatedScore += lookalikeScore;
  checks.push({
    key: 'lookalike_domains',
    label: 'Misleading / Look-Alike Domain',
    status: lookalikeScore >= 40 ? 'danger' : lookalikeScore > 0 ? 'warning' : 'safe',
    score: lookalikeScore,
    details: lookalikeNotes.length > 0 ? lookalikeNotes.join('; ') : 'No known typosquatting or brand impersonation patterns detected in domain name.',
    observedValue: lookalikeNotes.length > 0 ? 'Suspicious match' : 'Legitimate format',
  });

  // -------------------------------------------------------------
  // 6. Domain Name & TLD Reputation
  // -------------------------------------------------------------
  let tldScore = 0;
  const tldNotes: string[] = [];

  if (SUSPICIOUS_TLDS.has(breakdown.tld.toLowerCase())) {
    tldScore += 25;
    warningSigns.push({
      id: 'high_risk_tld',
      severity: 'medium',
      title: `High-Risk Top-Level Domain (.${breakdown.tld})`,
      description: `The top-level domain ".${breakdown.tld}" is statistically associated with high rates of malicious phishing, spam, and botnet distribution due to low-cost or free registry policies.`,
      category: 'Domain Name',
    });
    tldNotes.push(`TLD ".${breakdown.tld}" has an unfavorable reputation score`);
  }

  // Check domain length & randomness (DGA entropy heuristics)
  const rootWithoutTld = breakdown.rootDomain.replace(new RegExp(`\\.${breakdown.tld}$`), '');
  const digitCount = (rootWithoutTld.match(/\d/g) || []).length;
  if (rootWithoutTld.length > 18 && digitCount >= 4) {
    tldScore += 20;
    warningSigns.push({
      id: 'dga_randomness',
      severity: 'medium',
      title: 'High Entropy / Random Domain Name',
      description: 'The root domain exhibits high randomness and numeric density, characteristic of automated Domain Generation Algorithms (DGA) utilized by malware.',
      category: 'Domain Name',
    });
    tldNotes.push('Appears algorithmically generated (DGA traits)');
  }

  calculatedScore += tldScore;
  checks.push({
    key: 'domain_name',
    label: 'Domain Name & TLD',
    status: tldScore >= 25 ? 'warning' : 'safe',
    score: tldScore,
    details: tldNotes.length > 0 ? tldNotes.join('; ') : `Domain "${breakdown.rootDomain}" has normal syntactic traits and standard TLD (.${breakdown.tld || 'none'}).`,
    observedValue: breakdown.rootDomain,
  });

  // -------------------------------------------------------------
  // 7. Excessive URL Length
  // -------------------------------------------------------------
  let lengthScore = 0;
  const length = breakdown.length;
  if (length > 140) {
    lengthScore += 20;
    warningSigns.push({
      id: 'excessive_url_length',
      severity: 'medium',
      title: 'Excessive URL Length (>140 chars)',
      description: `The URL is ${length} characters long. Long URLs are frequently generated by phishing toolkits to push misleading parts past the visible address bar boundaries.`,
      category: 'URL Length',
    });
  } else if (length > 85) {
    lengthScore += 10;
  }

  calculatedScore += lengthScore;
  checks.push({
    key: 'url_length',
    label: 'Excessive URL Length',
    status: lengthScore >= 20 ? 'warning' : 'safe',
    score: lengthScore,
    details: `${length} characters total. ${length > 140 ? 'Abnormally elongated.' : length > 85 ? 'Moderately long.' : 'Within standard bounds.'}`,
    observedValue: `${length} chars`,
  });

  // -------------------------------------------------------------
  // 8. Suspicious Parameters (Query String Analysis)
  // -------------------------------------------------------------
  let paramScore = 0;
  const paramNotes: string[] = [];

  if (breakdown.search) {
    const searchParams = parsed.searchParams;
    const foundSuspiciousKeys: string[] = [];
    const openRedirectCandidates: string[] = [];

    for (const [key, val] of searchParams.entries()) {
      const lowerKey = key.toLowerCase();
      if (SUSPICIOUS_PARAM_KEYS.includes(lowerKey)) {
        foundSuspiciousKeys.push(key);
      }

      // Check for nested URLs indicating open redirects
      if (/https?:\/\//i.test(val) || /^www\./i.test(val)) {
        openRedirectCandidates.push(key);
      }

      // Check for base64 encoded strings
      if (/^[a-zA-Z0-9+/]{20,}={0,2}$/.test(val) && val.length > 24) {
        paramScore += 15;
        paramNotes.push(`Parameter "${key}" contains long base64 payload`);
      }
    }

    if (openRedirectCandidates.length > 0) {
      paramScore += 30;
      warningSigns.push({
        id: 'open_redirect_parameter',
        severity: 'high',
        title: 'Potential Open Redirect Target',
        description: `Parameter(s) [${openRedirectCandidates.join(', ')}] contain a target URL payload. Attackers abuse open redirect vulnerabilities on trusted sites to forward victims to malicious credential-stealing pages.`,
        category: 'Suspicious Parameters',
      });
      paramNotes.push(`Open redirect vector in [${openRedirectCandidates.join(', ')}]`);
    }

    if (foundSuspiciousKeys.length > 0) {
      paramScore += 20;
      warningSigns.push({
        id: 'sensitive_query_parameters',
        severity: 'medium',
        title: 'Sensitive Credential / Auth Parameters in URL',
        description: `URL explicitly passes authentication or session identifiers in query parameters: [${foundSuspiciousKeys.join(', ')}]. Sensitive tokens in URL parameters are easily logged and leaked.`,
        category: 'Suspicious Parameters',
      });
      paramNotes.push(`Sensitive parameter keys: ${foundSuspiciousKeys.join(', ')}`);
    }
  }

  calculatedScore += paramScore;
  checks.push({
    key: 'suspicious_parameters',
    label: 'Suspicious Parameters',
    status: paramScore >= 25 ? 'danger' : paramScore > 0 ? 'warning' : 'safe',
    score: paramScore,
    details: paramNotes.length > 0 ? paramNotes.join('; ') : 'No suspicious redirect keys, credential fields, or base64 payloads detected in query parameters.',
    observedValue: breakdown.search ? `${breakdown.search.slice(0, 32)}${breakdown.search.length > 32 ? '...' : ''}` : '(no parameters)',
  });

  // -------------------------------------------------------------
  // 9. URL Structure & Path Checks
  // -------------------------------------------------------------
  let structureScore = 0;
  const structureNotes: string[] = [];

  // Non-standard port
  if (breakdown.port && breakdown.port !== '80' && breakdown.port !== '443') {
    structureScore += 25;
    warningSigns.push({
      id: 'non_standard_port',
      severity: 'medium',
      title: `Non-Standard Web Port (:${breakdown.port})`,
      description: `Target uses custom port ${breakdown.port} instead of standard 80 (HTTP) or 443 (HTTPS). Malicious proxies and compromised hosts frequently use non-standard ports.`,
      category: 'URL Structure',
    });
    structureNotes.push(`Custom port :${breakdown.port}`);
  }

  // Path inspection: double slashes in path
  if (/\/\//.test(breakdown.pathname.slice(1))) {
    structureScore += 15;
    warningSigns.push({
      id: 'double_slash_path',
      severity: 'medium',
      title: 'Path Traversal / Double Slash Anomaly',
      description: 'Path contains consecutive slashes ("//"), which is often used in reverse-proxy bypasses and web application firewall (WAF) evasions.',
      category: 'URL Structure',
    });
    structureNotes.push('Double slash anomaly in path');
  }

  // Path inspection: credential phishing keywords in path when combined with non-authentic domain
  const lowerPath = breakdown.pathname.toLowerCase();
  const matchedPathKeywords = SUSPICIOUS_PATH_KEYWORDS.filter(kw => lowerPath.includes(kw));
  if (matchedPathKeywords.length >= 2 && calculatedScore > 20) {
    structureScore += 15;
    warningSigns.push({
      id: 'phishing_path_lures',
      severity: 'medium',
      title: 'Phishing Lure Keywords in Path',
      description: `Path contains urgent action lure terms: [${matchedPathKeywords.join(', ')}], combined with other suspicious indicators.`,
      category: 'URL Structure',
    });
    structureNotes.push(`Lure keywords in path: ${matchedPathKeywords.join(', ')}`);
  }

  calculatedScore += structureScore;
  checks.push({
    key: 'url_structure',
    label: 'URL Structure & Path',
    status: structureScore >= 25 ? 'danger' : structureScore > 0 ? 'warning' : 'safe',
    score: structureScore,
    details: structureNotes.length > 0 ? structureNotes.join('; ') : 'URL path, port, and syntactic components adhere to RFC specifications without anomalies.',
    observedValue: breakdown.port ? `Port :${breakdown.port}` : 'Standard port & clean path',
  });

  // -------------------------------------------------------------
  // Final Score & Classification Calculation
  // -------------------------------------------------------------
  // Clamp risk score to [0, 100]
  const finalRiskScore = Math.min(100, Math.max(0, calculatedScore));

  let classification: Classification = 'SAFE';
  if (finalRiskScore >= 60 || warningSigns.some(w => w.severity === 'high')) {
    classification = 'HIGH RISK';
  } else if (finalRiskScore >= 25 || warningSigns.length > 0) {
    classification = 'SUSPICIOUS';
  } else {
    classification = 'SAFE';
  }

  // If score is safe, ensure it reflects low number
  const calibratedScore = classification === 'SAFE' ? Math.min(finalRiskScore, 18) : finalRiskScore;

  // Short explanation synthesis
  let shortExplanation = '';
  if (classification === 'HIGH RISK') {
    const topWarning = warningSigns.find(w => w.severity === 'high') || warningSigns[0];
    shortExplanation = `This URL poses a significant cybersecurity risk (${calibratedScore}/100) primarily due to ${topWarning ? topWarning.title.toLowerCase() : 'multiple severe deceptive indicators'}. It exhibits hallmark signatures of credential phishing or malware distribution.`;
  } else if (classification === 'SUSPICIOUS') {
    shortExplanation = `This URL contains questionable traits resulting in a caution rating (${calibratedScore}/100). While not definitively confirmed as malicious, anomalies such as ${warningSigns[0]?.title.toLowerCase() || 'unusual domain/structure patterns'} require scrutiny before opening.`;
  } else {
    shortExplanation = `This URL exhibits clean structural integrity (${calibratedScore}/100) with a standard domain format, recognized TLD, and no deceptive look-alikes or credential harvest signatures. As always, remember HTTPS encrypts transit but does not independently certify host intentions.`;
  }

  const safetyAdvice: string[] = [];
  if (classification === 'HIGH RISK') {
    safetyAdvice.push('Do NOT click or open this link in any browser.');
    safetyAdvice.push('Never input passwords, 2FA codes, or personal information on pages reached through this address.');
    safetyAdvice.push('If received via email or SMS, report the message as phishing to your security team or email provider.');
  } else if (classification === 'SUSPICIOUS') {
    safetyAdvice.push('Proceed with caution: verify the sender or origin before opening.');
    safetyAdvice.push('Double-check the top-level domain and verify spelling directly on known official bookmarks.');
    safetyAdvice.push('Ensure HTTPS padlock is present, but remember that HTTPS alone does NOT verify identity.');
  } else {
    safetyAdvice.push('The URL string shows no deceptive indicators.');
    safetyAdvice.push('Always confirm the domain matches the expected institution before providing credentials.');
    safetyAdvice.push('Keep browser and endpoint protection updated.');
  }

  return {
    url: rawInput,
    normalizedUrl: parsed.href,
    classification,
    riskScore: calibratedScore,
    shortExplanation,
    warningSigns,
    characteristics: checks,
    breakdown,
    safetyAdvice,
    analyzedAt: new Date().toISOString(),
    isAiEnhanced: false,
  };
}
