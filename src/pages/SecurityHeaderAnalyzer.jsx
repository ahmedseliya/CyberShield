import { useState, useRef } from 'react';
import { GoogleGenerativeAI } from '@google/generative-ai';

const SecurityHeaderAnalyzer = () => {
    const [url, setUrl] = useState('');
    const [loading, setLoading] = useState(false);
    const [generatingReport, setGeneratingReport] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState('');
    const [copiedHeader, setCopiedHeader] = useState('');
    const controllerRef = useRef(null);

    // --- CLOUDFLARE WORKER URL ---
    const WORKER_URL = "https://header-proxy.ahmedseliya07.workers.dev/";

    // --- GEMINI API CONFIGURATION ---
    const GEMINI_API_KEY = "AIzaSyASr8tHcapJnUJJm3Jfso7G8KgWNv4pUhk"; // Replace with your actual API key
    const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

    // Header analysis functions (keep all existing functions as they are)
    const checkCSP = (headers) => {
        const csp = headers['content-security-policy'] || headers['Content-Security-Policy'];
        if (!csp) return { 
            present: false, 
            score: 0, 
            severity: 'high', 
            fix: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
            owaspCategory: 'A03: Injection',
            owaspLink: 'https://owasp.org/Top10/A03_2021-Injection/'
        };
        
        const directives = csp.toLowerCase().split(';').map(d => d.trim());
        const hasDefaultSrc = directives.some(d => d.startsWith('default-src'));
        const hasScriptSrc = directives.some(d => d.startsWith('script-src'));
        const hasObjectSrc = directives.some(d => d.startsWith('object-src'));
        const hasDefaultSelf = hasDefaultSrc && directives.find(d => d.startsWith('default-src')).includes("'self'");
        const hasScriptSelf = hasScriptSrc && directives.find(d => d.startsWith('script-src')).includes("'self'");
        const hasObjectNone = hasObjectSrc && directives.find(d => d.startsWith('object-src')).includes("'none'");
        
        let score = 0;
        if (hasDefaultSelf) score += 40;
        else if (hasDefaultSrc) score += 30;
        
        if (hasScriptSelf) score += 35;
        else if (hasScriptSrc) score += 25;
        
        if (hasObjectNone) score += 25;
        else if (hasObjectSrc) score += 15;
        
        score = Math.min(score, 100);
        
        let missingParts = [];
        if (!hasDefaultSrc || !hasDefaultSelf) missingParts.push("default-src 'self'");
        if (!hasScriptSrc || !hasScriptSelf) missingParts.push("script-src 'self'");
        if (!hasObjectSrc || !hasObjectNone) missingParts.push("object-src 'none'");
        
        const fix = score < 100 ? 
            `Content-Security-Policy: ${missingParts.join('; ')};` : 
            undefined;
        
        return {
            present: true,
            value: csp,
            score: score,
            severity: score === 100 ? 'low' : score >= 80 ? 'low-medium' : score >= 60 ? 'medium' : score >= 40 ? 'medium-high' : 'high',
            directives: directives,
            fix: fix,
            owaspCategory: 'A03: Injection',
            owaspLink: 'https://owasp.org/Top10/A03_2021-Injection/'
        };
    };

    const checkHSTS = (headers, url) => {
        const hsts = headers['strict-transport-security'] || headers['Strict-Transport-Security'];
        const isHTTPS = url && url.startsWith('https://');
        
        if (!hsts) {
            return { 
                present: false, 
                score: 0, 
                severity: isHTTPS ? 'high' : 'medium',
                fix: isHTTPS ? 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' : 'First enable HTTPS on your site',
                owaspCategory: 'A02: Cryptographic Failures',
                owaspLink: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
                requiresHTTPS: true,
                isHTTPS: isHTTPS
            };
        }
        
        const includesMaxAge = hsts.includes('max-age=');
        const includesPreload = hsts.includes('preload');
        const includesIncludeSubDomains = hsts.includes('includeSubDomains');
        
        let maxAgeValid = false;
        if (includesMaxAge) {
            const maxAgeMatch = hsts.match(/max-age=(\d+)/);
            maxAgeValid = maxAgeMatch && parseInt(maxAgeMatch[1]) >= 31536000;
        }
        
        let score = 0;
        if (includesMaxAge) {
            if (maxAgeValid) score += 50;
            else score += 30;
        }
        if (includesIncludeSubDomains) score += 30;
        if (includesPreload) score += 20;
        
        score = Math.min(score, 100);
        
        let missingParts = [];
        if (!includesMaxAge) {
            missingParts.push("max-age=31536000");
        } else if (!maxAgeValid) {
            missingParts.push("max-age=31536000 (increase duration)");
        }
        if (!includesIncludeSubDomains) missingParts.push("includeSubDomains");
        if (!includesPreload) missingParts.push("preload");
        
        const fix = score < 100 ? 
            `Strict-Transport-Security: ${missingParts.join('; ')}` : 
            undefined;
        
        return {
            present: true,
            value: hsts,
            score: score,
            severity: score === 100 ? 'low' : score >= 80 ? 'low-medium' : score >= 60 ? 'medium' : score >= 40 ? 'medium-high' : 'high',
            maxAge: includesMaxAge,
            preload: includesPreload,
            includeSubDomains: includesIncludeSubDomains,
            fix: fix,
            owaspCategory: 'A02: Cryptographic Failures',
            owaspLink: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
            requiresHTTPS: true,
            isHTTPS: isHTTPS
        };
    };

    const checkXFrameOptions = (headers) => {
        const xfo = headers['x-frame-options'] || headers['X-Frame-Options'];
        
        if (!xfo) return { 
            present: false, 
            score: 0, 
            severity: 'high', 
            fix: 'X-Frame-Options: DENY',
            owaspCategory: 'A01: Broken Access Control',
            owaspLink: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
        };
        
        const value = xfo.toLowerCase();
        const isDeny = value === 'deny';
        const isSameOrigin = value === 'sameorigin';
        
        const score = isDeny ? 100 : isSameOrigin ? 90 : 0;
        
        const fix = score < 100 ? 'X-Frame-Options: DENY' : undefined;
        
        return {
            present: true,
            value: xfo,
            score: score,
            severity: score === 100 ? 'low' : score === 90 ? 'low-medium' : 'high',
            fix: fix,
            owaspCategory: 'A01: Broken Access Control',
            owaspLink: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
        };
    };

    const checkXContentTypeOptions = (headers) => {
        const xcto = headers['x-content-type-options'] || headers['X-Content-Type-Options'];
        const isPresent = xcto && xcto.toLowerCase() === 'nosniff';
        
        const score = isPresent ? 100 : 0;
        const fix = score < 100 ? 'X-Content-Type-Options: nosniff' : undefined;
        
        return {
            present: isPresent,
            value: xcto,
            score: score,
            severity: score === 100 ? 'low' : 'medium',
            fix: fix,
            owaspCategory: 'A05: Security Misconfiguration',
            owaspLink: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
        };
    };

    const checkReferrerPolicy = (headers) => {
        const rp = headers['referrer-policy'] || headers['Referrer-Policy'];
        const validPolicies = ['no-referrer', 'no-referrer-when-downgrade', 'origin', 
                              'origin-when-cross-origin', 'same-origin', 'strict-origin', 
                              'strict-origin-when-cross-origin'];
        
        const isPresent = rp && validPolicies.includes(rp.toLowerCase());
        
        let score = 0;
        if (isPresent) {
            score = rp.toLowerCase() === 'strict-origin-when-cross-origin' ? 100 : 90;
        }
        
        const fix = score < 100 ? 'Referrer-Policy: strict-origin-when-cross-origin' : undefined;
        
        return {
            present: isPresent,
            value: rp,
            score: score,
            severity: score === 100 ? 'low' : score === 90 ? 'low-medium' : 'low-medium',
            fix: fix,
            owaspCategory: 'A05: Security Misconfiguration',
            owaspLink: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
        };
    };

    const checkPermissionsPolicy = (headers) => {
        const pp = headers['permissions-policy'] || headers['Permissions-Policy'] || 
                   headers['feature-policy'] || headers['Feature-Policy'];
        
        if (!pp) return {
            present: false,
            score: 0,
            severity: 'medium',
            fix: 'Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()',
            owaspCategory: 'A05: Security Misconfiguration',
            owaspLink: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
        };
        
        const ppLower = pp.toLowerCase();
        const criticalFeatures = ['geolocation', 'camera', 'microphone', 'payment'];
        let restrictedCount = 0;
        let missingFeatures = [];
        
        criticalFeatures.forEach(feature => {
            if (ppLower.includes(`${feature}=()`)) {
                restrictedCount++;
            } else {
                missingFeatures.push(`${feature}=()`);
            }
        });
        
        const score = restrictedCount * 25;
        
        const fix = score < 100 ? 
            `Permissions-Policy: ${pp} ${missingFeatures.join(', ')}` : 
            undefined;
        
        return {
            present: true,
            value: pp,
            score: score,
            severity: score === 100 ? 'low' : score >= 75 ? 'low-medium' : score >= 50 ? 'medium' : score >= 25 ? 'medium-high' : 'high',
            fix: fix,
            owaspCategory: 'A05: Security Misconfiguration',
            owaspLink: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
        };
    };

    const checkXXSSProtection = (headers) => {
        const xss = headers['x-xss-protection'] || headers['X-XSS-Protection'];
        
        const isPresent = xss;
        const isDisabled = xss && xss.includes('0');
        
        let score = 0;
        if (isDisabled) {
            score = 100;
        } else if (!isPresent) {
            score = 90;
        }
        
        const fix = score < 100 ? 
            (isPresent ? 'X-XSS-Protection: 0 (disable) or remove entirely' : 'Consider implementing Content-Security-Policy for XSS protection') : 
            undefined;
        
        return {
            present: isPresent,
            value: xss,
            score: score,
            severity: score === 100 ? 'low' : score === 90 ? 'low-medium' : 'high',
            isDisabled: isDisabled,
            fix: fix,
            owaspCategory: 'A03: Injection',
            owaspLink: 'https://owasp.org/Top10/A03_2021-Injection/'
        };
    };

    const checkCORS = (headers) => {
        const allowOrigin = headers['access-control-allow-origin'];
        const allowCredentials = headers['access-control-allow-credentials'];
        
        if (!allowOrigin) return {
            present: false,
            score: 50,
            severity: 'medium',
            fix: 'Access-Control-Allow-Origin: https://your-domain.com',
            owaspCategory: 'A01: Broken Access Control',
            owaspLink: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
        };
        
        const isWildcard = allowOrigin === '*';
        const hasCredentialsWithWildcard = isWildcard && allowCredentials === 'true';
        
        let score = 0;
        if (hasCredentialsWithWildcard) {
            score = 0;
        } else if (isWildcard) {
            score = 30;
        } else {
            score = allowCredentials === 'true' ? 80 : 100;
        }
        
        const fix = score < 100 ? 
            (hasCredentialsWithWildcard ? 
                'Access-Control-Allow-Origin: https://your-domain.com OR Access-Control-Allow-Credentials: false' :
                isWildcard ? 
                'Access-Control-Allow-Origin: https://your-domain.com (instead of wildcard *)' :
                'Consider setting Access-Control-Allow-Credentials: false if not needed') : 
            undefined;
        
        return {
            present: true,
            value: allowOrigin,
            score: score,
            severity: score === 100 ? 'low' : score >= 80 ? 'low-medium' : score >= 30 ? 'medium' : 'high',
            isWildcard: isWildcard,
            hasCredentials: allowCredentials === 'true',
            hasCredentialsWithWildcard: hasCredentialsWithWildcard,
            fix: fix,
            owaspCategory: 'A01: Broken Access Control',
            owaspLink: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
        };
    };

    const checkAuthenticationHeaders = (headers, url) => {
        const wwwAuthenticate = headers['www-authenticate'];
        const authorization = headers['authorization'];
        const proxyAuthenticate = headers['proxy-authenticate'];
        const proxyAuthorization = headers['proxy-authorization'];
        
        const hasAuth = wwwAuthenticate || authorization || proxyAuthenticate || proxyAuthorization;
        
        if (!hasAuth) {
            return {
                present: false,
                value: 'No authentication headers detected',
                score: 0,
                severity: 'low-medium',
                findings: [],
                fix: 'If your site has authentication, add appropriate headers:\n' +
                     'For Basic Auth: WWW-Authenticate: Basic realm="Secure Area"\n' +
                     'For Bearer Tokens: Authorization: Bearer <token>\n' +
                     'For OAuth: Authorization: Bearer <access_token>',
                owaspCategory: 'A07: Identification & Authentication Failures',
                owaspLink: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
            };
        }
        
        let score = 100;
        let fix = '';
        let findings = [];
        
        if (wwwAuthenticate && wwwAuthenticate.toLowerCase().includes('basic') && 
            url && !url.startsWith('https://')) {
            score = 10;
            findings.push('Basic authentication without HTTPS');
            fix = 'Enable HTTPS or switch to token-based authentication:\n' +
                  'Authorization: Bearer <token> (with HTTPS)';
        }
        else if (wwwAuthenticate && wwwAuthenticate.toLowerCase().includes('basic')) {
            score = 60;
            findings.push('Basic authentication detected (weak scheme)');
            fix = 'Consider using stronger authentication:\n' +
                  'Authorization: Bearer <token> (OAuth/JWT)\n' +
                  'or implement multi-factor authentication';
        }
        
        return {
            present: true,
            value: wwwAuthenticate || authorization || proxyAuthenticate || proxyAuthorization,
            score: score,
            severity: score === 100 ? 'low' : score >= 60 ? 'medium' : 'high',
            findings: findings,
            fix: score < 100 ? fix : undefined,
            owaspCategory: 'A07: Identification & Authentication Failures',
            owaspLink: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
        };
    };

    const checkCookieSecurity = (headers, url) => {
        const setCookie = headers['set-cookie'];
        const isHTTPS = url && url.startsWith('https://');
        
        if (!setCookie) return {
            present: false,
            score: 0,
            severity: 'medium',
            fix: 'Set-Cookie: sessionId=abc123; Secure; HttpOnly; SameSite=Strict',
            category: 'Session Security',
            owaspCategory: 'A01: Broken Access Control',
            owaspLink: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
        };
        
        const cookieString = Array.isArray(setCookie) ? setCookie.join('; ') : setCookie;
        const hasSecure = cookieString.toLowerCase().includes('secure');
        const hasHttpOnly = cookieString.toLowerCase().includes('httponly');
        const hasSameSite = cookieString.toLowerCase().includes('samesite');
        const hasSameSiteStrict = cookieString.toLowerCase().includes('samesite=strict');
        
        let score = 0;
        if (hasHttpOnly) score += 40;
        if (hasSecure) score += 40;
        if (hasSameSite) {
            score += hasSameSiteStrict ? 20 : 15;
        }
        
        if (isHTTPS && !hasSecure) {
            score = Math.min(score, 40);
        }
        
        let missingAttributes = [];
        if (isHTTPS && !hasSecure) {
            missingAttributes.push('Secure');
        }
        if (!hasHttpOnly) {
            missingAttributes.push('HttpOnly');
        }
        if (!hasSameSite) {
            missingAttributes.push('SameSite=Strict');
        } else if (!hasSameSiteStrict) {
            missingAttributes.push('SameSite=Strict (instead of Lax)');
        }
        
        const fix = score < 100 ? 
            `Add to Set-Cookie: ${missingAttributes.join(', ')}` : 
            undefined;
        
        let owaspCategory = 'A01: Broken Access Control';
        if (!hasHttpOnly) owaspCategory = 'A03: Injection';
        else if (isHTTPS && !hasSecure) owaspCategory = 'A02: Cryptographic Failures';
        
        return {
            present: true,
            value: cookieString.length > 100 ? cookieString.substring(0, 100) + '...' : cookieString,
            score: score,
            severity: score === 100 ? 'low' : score >= 80 ? 'low-medium' : score >= 60 ? 'medium' : score >= 40 ? 'medium-high' : 'high',
            hasSecure: hasSecure,
            hasHttpOnly: hasHttpOnly,
            hasSameSite: hasSameSite,
            hasSameSiteStrict: hasSameSiteStrict,
            fix: fix,
            owaspCategory: owaspCategory,
            owaspLink: owaspCategory === 'A03: Injection' ? 
                'https://owasp.org/Top10/A03_2021-Injection/' :
                owaspCategory === 'A02: Cryptographic Failures' ?
                'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' :
                'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
        };
    };

    const checkInformationDisclosure = (headers) => {
        const riskyHeaders = [
            'server', 
            'x-powered-by', 
            'x-aspnet-version',
            'x-aspnetmvc-version', 
            'x-generator'
        ];
        
        const found = [];
        riskyHeaders.forEach(h => {
            if (headers[h]) {
                found.push({ name: h, value: headers[h] });
            }
        });
        
        const score = found.length === 0 ? 100 : Math.max(0, 100 - (found.length * 20));
        
        let fix = '';
        if (found.length > 0) {
            const headerNames = found.map(f => f.name).join(', ');
            fix = `Remove or obfuscate: ${headerNames}`;
        }
        
        return {
            present: found.length > 0,
            value: found.map(f => `${f.name}: ${f.value}`).join('; '),
            score: score,
            severity: score === 100 ? 'low' : 
                      score >= 80 ? 'low-medium' : 
                      score >= 60 ? 'medium' : 
                      score >= 40 ? 'medium-high' : 
                      'high',
            foundHeaders: found,
            fix: score < 100 ? fix : undefined,
            owaspCategory: 'A05: Security Misconfiguration',
            owaspLink: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
        };
    };

    const checkCacheControl = (headers) => {
        const cacheControl = headers['cache-control'];
        const pragma = headers['pragma'];
        
        let score = 0;
        let fix = '';
        let findings = [];
        
        if (cacheControl) {
            const cacheControlLower = cacheControl.toLowerCase();
            const hasNoStore = cacheControlLower.includes('no-store');
            const hasNoCache = cacheControlLower.includes('no-cache');
            const hasPrivate = cacheControlLower.includes('private');
            
            if (hasNoStore) {
                score = 100;
                findings.push('Cache properly disabled with no-store');
            } else if (hasNoCache) {
                score = 80;
                findings.push('Partial cache control with no-cache');
                fix = 'Consider using no-store instead of no-cache for sensitive data';
            } else if (hasPrivate) {
                score = 60;
                findings.push('Basic cache control with private');
                fix = 'Add no-store or no-cache for sensitive data';
            } else {
                score = 30;
                findings.push('Inadequate cache control for sensitive data');
                fix = 'Add Cache-Control: no-store';
            }
        } else {
            score = 20;
            findings.push('Missing Cache-Control header');
            fix = 'Add Cache-Control: no-store for sensitive data';
        }
        
        if (pragma && pragma.toLowerCase().includes('no-cache') && !cacheControl) {
            score = Math.min(score, 40);
            fix = 'Replace Pragma: no-cache with Cache-Control: no-store';
        }
        
        return {
            present: !!cacheControl || !!pragma,
            value: cacheControl || pragma || 'No cache control headers',
            score: score,
            severity: score === 100 ? 'low' : score >= 80 ? 'low-medium' : score >= 60 ? 'medium' : score >= 30 ? 'medium-high' : 'high',
            findings: findings,
            fix: score < 100 ? fix : undefined,
            owaspCategory: 'A08: Software & Data Integrity Failures',
            owaspLink: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/'
        };
    };

    const checkSecurityReporting = (headers) => {
        const reportTo = headers['report-to'];
        const reportingEndpoints = headers['reporting-endpoints'];
        const contentSecurityPolicyReportOnly = headers['content-security-policy-report-only'] || 
                                               headers['Content-Security-Policy-Report-Only'];
        
        const isPresent = !!(reportTo || reportingEndpoints || contentSecurityPolicyReportOnly);
        
        let score = 0;
        let fix = '';
        let findings = [];
        
        if (reportTo) {
            try {
                JSON.parse(reportTo);
                score = 100;
                findings.push('Valid Report-To header present');
            } catch (e) {
                score = 50;
                findings.push('Report-To header has invalid JSON format');
                fix = 'Fix Report-To JSON format. Should be valid JSON like:\n' +
                      'Report-To: {"group":"default","max_age":31536000,"endpoints":[{"url":"https://example.com/reports"}]}';
            }
        } else if (reportingEndpoints) {
            score = 90;
            findings.push('Reporting-Endpoints header present');
            fix = 'Consider adding Report-To for broader browser support';
        } else if (contentSecurityPolicyReportOnly) {
            score = 80;
            findings.push('CSP Report-Only header present');
            fix = 'Consider implementing Report-To header for comprehensive reporting';
        } else {
            score = 70;
            findings.push('No security reporting headers');
            fix = 'Consider implementing security reporting:\n' +
                  'Content-Security-Policy-Report-Only: default-src \'self\'; report-uri /csp-report\n' +
                  'or\n' +
                  'Report-To: {"group":"default","max_age":31536000,"endpoints":[{"url":"https://example.com/reports"}]}';
        }
        
        return {
            present: isPresent,
            value: reportTo || reportingEndpoints || contentSecurityPolicyReportOnly || 'No security reporting headers',
            score: score,
            severity: score === 100 ? 'low' : score >= 80 ? 'low-medium' : score >= 60 ? 'medium' : 'medium-high',
            findings: findings,
            fix: score < 100 ? fix : undefined,
            owaspCategory: 'A09: Security Logging & Monitoring Failures',
            owaspLink: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
        };
    };

    const checkPerformanceHeaders = (headers) => {
        const xDnsPrefetchControl = headers['x-dns-prefetch-control'];
        const xPermittedCrossDomainPolicies = headers['x-permitted-cross-domain-policies'];
        
        let score = 100;
        let missing = [];
        
        if (!xDnsPrefetchControl || xDnsPrefetchControl.toLowerCase() !== 'off') {
            missing.push('X-DNS-Prefetch-Control: off');
            score -= 50;
        }
        
        if (!xPermittedCrossDomainPolicies || xPermittedCrossDomainPolicies.toLowerCase() !== 'none') {
            missing.push('X-Permitted-Cross-Domain-Policies: none');
            score -= 50;
        }
        
        const fix = score < 100 ? missing.join('\n') : undefined;
        
        return {
            present: !!(xDnsPrefetchControl || xPermittedCrossDomainPolicies),
            value: xDnsPrefetchControl || xPermittedCrossDomainPolicies || 'No performance headers',
            score: score,
            severity: 'low',
            fix: fix,
            category: 'Performance & Optimization'
        };
    };

    const checkModernWebStandards = (headers) => {
        const clearSiteData = headers['clear-site-data'];
        const crossOriginOpenerPolicy = headers['cross-origin-opener-policy'] || headers['Cross-Origin-Opener-Policy'];
        const crossOriginEmbedderPolicy = headers['cross-origin-embedder-policy'] || headers['Cross-Origin-Embedder-Policy'];
        
        let score = 100;
        let missing = [];
        
        if (!crossOriginOpenerPolicy || crossOriginOpenerPolicy.toLowerCase() !== 'same-origin') {
            missing.push('Cross-Origin-Opener-Policy: same-origin');
            score -= 40;
        }
        
        if (!clearSiteData) {
            missing.push('Clear-Site-Data: "cache", "cookies", "storage"');
            score -= 40;
        }
        
        if (!crossOriginEmbedderPolicy) {
            score -= 20;
            missing.push('Cross-Origin-Embedder-Policy: require-corp');
        }
        
        score = Math.max(0, Math.min(score, 100));
        
        const fix = score < 100 ? missing.join('\n') : undefined;
        
        return {
            present: !!(clearSiteData || crossOriginOpenerPolicy || crossOriginEmbedderPolicy),
            value: clearSiteData || crossOriginOpenerPolicy || crossOriginEmbedderPolicy || 'No modern headers',
            score: score,
            severity: score === 100 ? 'low' : score >= 80 ? 'low-medium' : score >= 60 ? 'medium' : 'medium-high',
            fix: fix,
            category: 'Modern Web Standards'
        };
    };

    const calculateSecurityScore = (headers, currentUrl) => {
        const checks = [
            checkCSP(headers),
            checkHSTS(headers, currentUrl),
            checkXFrameOptions(headers),
            checkXContentTypeOptions(headers),
            checkReferrerPolicy(headers),
            checkPermissionsPolicy(headers),
            checkXXSSProtection(headers),
            checkCORS(headers),
            checkAuthenticationHeaders(headers, currentUrl),
            checkCookieSecurity(headers, currentUrl),
            checkInformationDisclosure(headers),
            checkCacheControl(headers),
            checkSecurityReporting(headers)
        ];
        
        const totalScore = checks.reduce((sum, check) => sum + check.score, 0);
        return Math.round(totalScore / checks.length);
    };

    const generateRecommendations = (headers, currentUrl) => {
        const recommendations = [];
        
        const cspResult = checkCSP(headers);
        const hstsResult = checkHSTS(headers, currentUrl);
        const xFrameResult = checkXFrameOptions(headers);
        const xContentResult = checkXContentTypeOptions(headers);
        const referrerResult = checkReferrerPolicy(headers);
        const permissionsResult = checkPermissionsPolicy(headers);
        const xssResult = checkXXSSProtection(headers);
        const corsResult = checkCORS(headers);
        const authResult = checkAuthenticationHeaders(headers, currentUrl);
        const cookieResult = checkCookieSecurity(headers, currentUrl);
        const infoResult = checkInformationDisclosure(headers);
        const cacheResult = checkCacheControl(headers);
        const reportingResult = checkSecurityReporting(headers);
        const performanceResult = checkPerformanceHeaders(headers);
        const modernResult = checkModernWebStandards(headers);
        
        if (cspResult.score < 100) {
            recommendations.push({
                header: 'Content-Security-Policy',
                severity: cspResult.severity,
                description: cspResult.present ? 'CSP needs improvement' : 'Missing CSP header leaves site vulnerable to XSS attacks',
                fix: cspResult.fix,
                owaspCategory: cspResult.owaspCategory
            });
        }
        
        if (hstsResult.score < 100) {
            const description = hstsResult.isHTTPS 
                ? 'Missing or weak HSTS header allows SSL stripping attacks' 
                : 'HSTS only works on HTTPS sites. First enable SSL/TLS.';
                
            recommendations.push({
                header: 'Strict-Transport-Security',
                severity: hstsResult.severity,
                description: description,
                fix: hstsResult.fix,
                owaspCategory: hstsResult.owaspCategory
            });
        }
        
        if (xFrameResult.score < 100) {
            recommendations.push({
                header: 'X-Frame-Options',
                severity: xFrameResult.severity,
                description: 'Weak or missing X-Frame-Options allows clickjacking attacks',
                fix: xFrameResult.fix,
                owaspCategory: xFrameResult.owaspCategory
            });
        }
        
        if (xContentResult.score < 100) {
            recommendations.push({
                header: 'X-Content-Type-Options',
                severity: xContentResult.severity,
                description: 'Missing header allows MIME sniffing attacks',
                fix: xContentResult.fix,
                owaspCategory: xContentResult.owaspCategory
            });
        }
        
        if (referrerResult.score < 100) {
            recommendations.push({
                header: 'Referrer-Policy',
                severity: referrerResult.severity,
                description: 'Missing or weak Referrer-Policy can leak sensitive URL information',
                fix: referrerResult.fix,
                owaspCategory: referrerResult.owaspCategory
            });
        }
        
        if (permissionsResult.score < 100) {
            recommendations.push({
                header: 'Permissions-Policy',
                severity: permissionsResult.severity,
                description: 'Missing or weak Permissions-Policy allows unrestricted access to browser features',
                fix: permissionsResult.fix,
                owaspCategory: permissionsResult.owaspCategory
            });
        }
        
        if (xssResult.score < 100) {
            recommendations.push({
                header: 'X-XSS-Protection',
                severity: xssResult.severity,
                description: xssResult.present ? 'X-XSS-Protection may cause issues in modern browsers' : 'Consider implementing CSP for XSS protection',
                fix: xssResult.fix,
                owaspCategory: xssResult.owaspCategory
            });
        }
        
        if (corsResult.score < 100) {
            const description = corsResult.hasCredentialsWithWildcard 
                ? 'CORS allows wildcard origin with credentials - CRITICAL SECURITY RISK' 
                : corsResult.isWildcard 
                ? 'CORS allows wildcard origin - sensitive data may be exposed'
                : 'CORS credentials may not be needed';
                
            recommendations.push({
                header: 'CORS Headers',
                severity: corsResult.severity,
                description: description,
                fix: corsResult.fix,
                owaspCategory: corsResult.owaspCategory
            });
        }
        
        if (authResult.score < 100 && authResult.fix) {
            recommendations.push({
                header: 'Authentication Headers',
                severity: authResult.severity,
                description: 'Weak authentication detected',
                fix: authResult.fix,
                owaspCategory: authResult.owaspCategory
            });
        }
        
        if (cookieResult.score < 100) {
            recommendations.push({
                header: 'Cookie Security',
                severity: cookieResult.severity,
                description: cookieResult.present ? 'Cookies missing security attributes' : 'No cookies detected',
                fix: cookieResult.fix,
                owaspCategory: cookieResult.owaspCategory
            });
        }
        
        if (infoResult.score < 100) {
            recommendations.push({
                header: 'Information Disclosure',
                severity: infoResult.severity,
                description: `Server exposes ${infoResult.foundHeaders.length} information disclosure header(s)`,
                fix: infoResult.fix,
                owaspCategory: infoResult.owaspCategory
            });
        }
        
        if (cacheResult.score < 100) {
            recommendations.push({
                header: 'Cache Control',
                severity: cacheResult.severity,
                description: 'Inadequate cache control for sensitive data',
                fix: cacheResult.fix,
                owaspCategory: cacheResult.owaspCategory
            });
        }
        
        if (reportingResult.score < 100) {
            recommendations.push({
                header: 'Security Reporting',
                severity: reportingResult.severity,
                description: 'No security reporting mechanisms detected',
                fix: reportingResult.fix,
                owaspCategory: reportingResult.owaspCategory
            });
        }
        
        if (performanceResult.score < 100) {
            recommendations.push({
                header: 'Performance Headers',
                severity: performanceResult.severity,
                description: 'Missing performance optimization headers',
                fix: performanceResult.fix,
                category: performanceResult.category
            });
        }
        
        if (modernResult.score < 100) {
            recommendations.push({
                header: 'Modern Web Standards',
                severity: modernResult.severity,
                description: 'Missing modern web security headers',
                fix: modernResult.fix,
                category: modernResult.category
            });
        }
        
        return recommendations;
    };

    const analyzeSecurityHeaders = (headers, url) => {
        const csp = checkCSP(headers);
        const hsts = checkHSTS(headers, url);
        const xFrameOptions = checkXFrameOptions(headers);
        const xContentTypeOptions = checkXContentTypeOptions(headers);
        const referrerPolicy = checkReferrerPolicy(headers);
        const permissionsPolicy = checkPermissionsPolicy(headers);
        const xXSSProtection = checkXXSSProtection(headers);
        const cors = checkCORS(headers);
        const authentication = checkAuthenticationHeaders(headers, url);
        const cookieSecurity = checkCookieSecurity(headers, url);
        const informationDisclosure = checkInformationDisclosure(headers);
        const cacheControl = checkCacheControl(headers);
        const securityReporting = checkSecurityReporting(headers);
        const performanceHeaders = checkPerformanceHeaders(headers);
        const modernWebStandards = checkModernWebStandards(headers);
        
        return {
            csp,
            hsts,
            xFrameOptions,
            xContentTypeOptions,
            referrerPolicy,
            permissionsPolicy,
            xXSSProtection,
            cors,
            authentication,
            cookieSecurity,
            informationDisclosure,
            cacheControl,
            securityReporting,
            performanceHeaders,
            modernWebStandards,
            securityScore: calculateSecurityScore(headers, url),
            recommendations: generateRecommendations(headers, url)
        };
    };

    
    // NEW FUNCTION: Generate AI Report using Gemini with Fixed Template
const generateAIReport = async () => {
    if (!results) {
        setError('No analysis results available');
        return;
    }

    setGeneratingReport(true);
    try {
        // Prepare data for Gemini
        const analysisData = {
            url: results.url,
            timestamp: results.timestamp,
            statusCode: results.statusCode,
            overallScore: results.analysis.securityScore,
            headersAnalysis: results.analysis,
            recommendations: results.analysis.recommendations,
            rawHeaders: results.headers
        };

        // Get current date in IST timezone
        const now = new Date();
        const istDate = new Date(now.toLocaleString('en-US', { timeZone: 'Asia/Kolkata' }));
        
        // Format date for display: "January 15, 2026"
        const formattedDate = istDate.toLocaleDateString('en-US', { 
            year: 'numeric', 
            month: 'long', 
            day: 'numeric' 
        });
        
        // Format time for display: "10:50:54 IST"
        const formattedTime = istDate.toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });

        // Create detailed prompt with strict template instructions
        const prompt = `
You are a security expert analyzing HTTP security headers. You MUST use the EXACT HTML template structure provided below. DO NOT change the styling, layout, or structure. ONLY replace the content placeholders with the actual analysis data.

SCAN RESULTS:
${JSON.stringify(analysisData, null, 2)}

TEMPLATE TO USE (copy this EXACT structure, only replace content):

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTTP Security Header Assessment Report</title>
    <style>
        /* CRITICAL: Add !important to ALL styles to prevent theme interference */
        /* ALL STYLING FROM THE TEMPLATE - KEEP EXACTLY THE SAME */
        /* General document styling */
        body {
            font-family: 'Segoe UI', Arial, sans-serif !important;
            background-color: #ffffff !important; /* Force white background */
            line-height: 1.6 !important;
            margin: 0 !important;
            padding: 0 !important;
            display: flex !important;
            justify-content: center !important;
            align-items: flex-start !important;
            min-height: 100vh !important;
        }

        * {
            box-sizing: border-box !important;
        }

        .report-container {
            width: 210mm !important; /* A4 width */
            min-height: 297mm !important; /* A4 height */
            background-color: #ffffff !important;
            padding: 20mm !important;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1) !important;
            position: relative !important;
        }

        /* Headers and accents */
        h1, h2, h3, h4 {
            color: #1e40af !important; /* Professional blue for headers */
            font-weight: bold !important;
            margin-top: 1.5em !important;
            margin-bottom: 0.8em !important;
        }

        h1 {
            font-size: 24px !important;
            text-align: center !important;
            margin-top: 0 !important;
            padding-bottom: 10px !important;
            border-bottom: 2px solid #1e40af !important;
        }

        h2 {
            font-size: 20px !important;
            border-bottom: 1px solid #1e40af !important;
            padding-bottom: 5px !important;
            margin-bottom: 1em !important;
        }

        h3 {
            font-size: 18px !important;
            margin-bottom: 0.5em !important;
        }

        h4 {
            font-size: 16px !important;
            margin-bottom: 0.6em !important;
        }

        p, ul, ol {
            font-size: 14px !important;
            margin-bottom: 0.8em !important;
            word-wrap: break-word !important;
            color: #4b5563 !important;
        }

        li {
            margin-bottom: 0.3em !important;
            word-wrap: break-word !important;
            color: #4b5563 !important;
        }

        /* Tables */
        table {
            width: 100% !important;
            border-collapse: collapse !important;
            margin-bottom: 1em !important;
            max-width: 100% !important;
            overflow-x: auto !important;
        }

        th, td {
            border: 1px solid #d1d5db !important;
            padding: 8px 12px !important;
            text-align: left !important;
            vertical-align: top !important;
            font-size: 14px !important;
            color: #4b5563 !important;
        }

        th {
            background-color: #e5e7eb !important;
            font-weight: bold !important;
            color: #374151 !important;
        }

        /* Severity colors */
        .severity {
            font-weight: bold !important;
            padding: 2px 8px !important;
            border-radius: 4px !important;
            display: inline-block !important;
            white-space: nowrap !important;
        }

        .severity.critical { background-color: #fee2e2 !important; color: #dc2626 !important; }
        .severity.high { background-color: #fee2e2 !important; color: #ef4444 !important; }
        .severity.medium-high { background-color: #fffbeb !important; color: #f59e0b !important; }
        .severity.medium { background-color: #fffbeb !important; color: #f59e0b !important; }
        .severity.low-medium { background-color: #ecfdf5 !important; color: #10b981 !important; }
        .severity.low { background-color: #ecfdf5 !important; color: #10b981 !important; }
        .severity.info { background-color: #e0f2fe !important; color: #3b82f6 !important; }

        /* Card styling */
        .card {
            background-color: #f9fafb !important;
            border-radius: 8px !important;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1) !important;
            padding: 12px !important;
            margin-bottom: 1em !important;
            border: 1px solid #e5e7eb !important;
        }

        .card h4 {
            margin-top: 0 !important;
            border-bottom: 1px dashed #d1d5db !important;
            padding-bottom: 5px !important;
        }

        /* Code blocks */
        pre {
            background-color: #eef2ff !important;
            border: 1px solid #c7d2fe !important;
            padding: 12px !important;
            border-radius: 6px !important;
            overflow-x: auto !important;
            font-family: 'Consolas', 'Monaco', monospace !important;
            font-size: 13px !important;
            color: #1e40af !important;
        }

        code {
            font-family: 'Consolas', 'Monaco', monospace !important;
            font-size: 13px !important;
            background-color: #f3f4f6 !important;
            padding: 2px 4px !important;
            border-radius: 4px !important;
            color: #1e40af !important;
        }

        /* Critical Notice Box */
        .critical-notice {
            background-color: #fef3c7 !important;
            border: 2px solid #f59e0b !important;
            padding: 16px !important;
            border-radius: 8px !important;
            font-size: 14px !important;
            color: #92400e !important;
            margin-bottom: 1.5em !important;
            display: flex !important;
            align-items: center !important;
        }

        .critical-notice .icon {
            font-size: 20px !important;
            margin-right: 10px !important;
        }

        /* Page breaks for PDF generation */
        .page-break {
            page-break-after: always !important;
            margin-top: 30px !important;
        }

        /* Utility classes */
        .flex-container {
            display: flex !important;
            gap: 20px !important;
            flex-wrap: wrap !important;
        }
        .flex-item {
            flex: 1 !important;
            min-width: 300px !important;
        }
        .meta-info {
            font-size: 12px !important;
            color: #6b7280 !important;
            margin-bottom: 0.5em !important;
        }
        .score-box {
            background-color: #eff6ff !important;
            border: 1px solid #bfdbfe !important;
            padding: 10px 15px !important;
            border-radius: 6px !important;
            display: inline-block !important;
            margin-top: 8px !important;
            font-size: 16px !important;
            font-weight: bold !important;
            color: #1e40af !important;
        }
        .score-box span {
            font-size: 20px !important;
            margin-left: 5px !important;
        }
        .owasp-link {
            font-size: 12px !important;
            color: #3b82f6 !important;
            text-decoration: none !important;
            word-break: break-all !important;
        }
        .owasp-link:hover {
            text-decoration: underline !important;
        }
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Professional Header -->
        <header style="text-align: center !important; margin-bottom: 1.5em !important;">
            <!-- CyberShield Security with red color -->
            <div style="font-size: 24px !important; font-weight: bold !important; color: #dc2626 !important; margin-bottom: 8px !important;">
                🔒 CyberShield Security
            </div>
            <h1>HTTP Security Header Assessment Report</h1>
            <p style="font-size: 16px !important; color: #1e40af !important; margin-bottom: 0.5em !important;">Comprehensive Analysis for Enhanced Web Security</p>
        </header>

        <!-- Critical Notice Box -->
        <div class="critical-notice">
            <span class="icon">⚠️</span>
            <p>This is an automated security analysis report. Please review all findings with your security team and validate recommendations before implementation.</p>
        </div>

        <!-- Executive Summary -->
        <section class="page-break">
            <h2>1. Executive Summary</h2>
            <div class="card">
                <h3>Overview</h3>
                <p>This report provides a comprehensive security assessment of the HTTP headers for the target URL: <code style="background-color: #e0f2fe !important; padding: 2px 6px !important; border-radius: 3px !important; color: #1e40af !important; font-weight: bold !important;">[INSERT_URL_HERE]</code>. The analysis was conducted on ${formattedDate} at ${formattedTime} IST.</p>
                <p class="meta-info"><strong>Target URL:</strong> <code style="background-color: #e0f2fe !important; padding: 2px 6px !important; border-radius: 3px !important; color: #1e40af !important; font-weight: bold !important;">[INSERT_URL_HERE]</code><br>
                <strong>Scan Timestamp:</strong> ${formattedDate} ${formattedTime} IST<br>
                <strong>HTTP Status Code:</strong> [INSERT_STATUS_CODE_HERE]</p>

                <h3>Overall Security Score Analysis</h3>
                <p>The overall security score for the target is <strong class="severity [INSERT_SEVERITY_CLASS_HERE]">[INSERT_SCORE_HERE]</strong> out of a potential 100. [INSERT_SCORE_ANALYSIS_HERE]</p>
               <div class="score-display" style="
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
    color: white !important;
    padding: 15px 20px !important;
    border-radius: 10px !important;
    text-align: center !important;
    margin: 15px 0 !important;
    box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3) !important;
    border: 3px solid white !important;
    position: relative !important;
    overflow: hidden !important;
">
    <div style="
        position: absolute !important;
        top: -50px !important;
        right: -50px !important;
        width: 100px !important;
        height: 100px !important;
        background: rgba(255, 255, 255, 0.1) !important;
        border-radius: 50% !important;
    "></div>
    <div style="
        position: absolute !important;
        bottom: -30px !important;
        left: -30px !important;
        width: 80px !important;
        height: 80px !important;
        background: rgba(255, 255, 255, 0.1) !important;
        border-radius: 50% !important;
    "></div>
    <div style="font-size: 14px !important; opacity: 0.9 !important; margin-bottom: 5px !important;">
        ⭐ Overall Security Score
    </div>
    <div style="font-size: 42px !important; font-weight: bold !important; margin: 10px 0 !important;">
        [INSERT_SCORE_HERE]<span style="font-size: 24px !important;">/100</span>
    </div>
    <div style="
        display: flex !important;
        justify-content: center !important;
        gap: 10px !important;
        margin-top: 10px !important;
    ">
        <span style="
            background: rgba(255, 255, 255, 0.2) !important;
            padding: 4px 12px !important;
            border-radius: 20px !important;
            font-size: 12px !important;
        ">🛡️ OWASP Based</span>
        <span style="
            background: rgba(255, 255, 255, 0.2) !important;
            padding: 4px 12px !important;
            border-radius: 20px !important;
            font-size: 12px !important;
        ">🔒 Real-time Scan</span>
    </div>
</div>
                <h3>Risk Level Assessment</h3>
                <p>Based on the overall score and findings, the current risk level is assessed as <strong class="severity [INSERT_RISK_SEVERITY_HERE]">[INSERT_RISK_LEVEL_HERE]</strong>. [INSERT_RISK_ANALYSIS_HERE]</p>

                <h3>Key Findings Summary</h3>
                <p>The most critical findings include:</p>
                <ul>
                    [INSERT_KEY_FINDINGS_HERE]
                </ul>
                <p>[INSERT_SUMMARY_ANALYSIS_HERE]</p>
            </div>
        </section>

        <!-- Detailed Analysis -->
        <section class="page-break">
            <h2>2. Detailed Analysis</h2>
            <p>This section provides an in-depth analysis of each HTTP security header, outlining its current status, associated risks, and potential impact.</p>

            [INSERT_DETAILED_ANALYSIS_CARDS_HERE]
        </section>

        <!-- Risk Assessment -->
        <section class="page-break">
            <h2>3. Risk Assessment</h2>
            <p>A structured risk assessment identifies and categorizes vulnerabilities based on their potential impact and likelihood, referencing the OWASP Top 10 2021 categories.</p>

            <h3>Categorization by OWASP Top 10 (2021)</h3>
            <table>
                <thead>
                    <tr>
                        <th>OWASP Category</th>
                        <th>Associated Headers/Vulnerabilities</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    [INSERT_OWASP_TABLE_ROWS_HERE]
                </tbody>
            </table>

            <h3>Probability and Impact Analysis</h3>
            <ul>
                <li><strong>Probability: <span class="severity [PROBABILITY_SEVERITY]">[PROBABILITY_TEXT]</span></strong> - [PROBABILITY_ANALYSIS]</li>
                <li><strong>Impact: <span class="severity [IMPACT_SEVERITY]">[IMPACT_TEXT]</span></strong> - [IMPACT_ANALYSIS]</li>
            </ul>

            <h3>Business Impact Assessment</h3>
            <p>The identified security weaknesses pose several significant business risks:</p>
            <ul>
                [INSERT_BUSINESS_IMPACTS_HERE]
            </ul>
        </section>

        <!-- Recommendations -->
        <section class="page-break">
            <h2>4. Recommendations</h2>
            <p>To significantly enhance the security posture, the following recommendations are provided, categorized by priority.</p>

            <h3>Priority-Based Recommendations</h3>
            [INSERT_RECOMMENDATIONS_HERE]
        </section>

        <!-- Remediation Timeline -->
        <section class="page-break">
            <h2>5. Remediation Timeline</h2>
            <p>A phased approach for addressing the identified vulnerabilities, prioritizing critical risks for immediate attention.</p>

            <h3>Immediate Actions (Within 24-72 hours)</h3>
            <ul>
                [INSERT_IMMEDIATE_ACTIONS_HERE]
            </ul>

            <h3>Short-Term Fixes (Within 1 week)</h3>
            <ul>
                [INSERT_SHORT_TERM_FIXES_HERE]
            </ul>

            <h3>Long-Term Improvements (Within 1 month)</h3>
            <ul>
                [INSERT_LONG_TERM_IMPROVEMENTS_HERE]
            </ul>
        </section>

        <!-- Compliance Check -->
        <section class="page-break">
            <h2>6. Compliance Check</h2>
            <p>Assessment of the application's alignment with recognized security standards and best practices.</p>

            <h3>OWASP Top 10 Compliance Status</h3>
            <p>[INSERT_COMPLIANCE_ANALYSIS_HERE]</p>

            <h3>Industry Standards Alignment</h3>
            <p>[INSERT_INDUSTRY_STANDARDS_ANALYSIS_HERE]</p>

            <h3>Best Practices Gap Analysis</h3>
            <ul>
                [INSERT_GAP_ANALYSIS_HERE]
            </ul>
        </section>

        <!-- Technical Details -->
        <section class="page-break">
            <h2>7. Technical Details</h2>
            <p>This section provides raw technical information and an assessment of technical and security debt.</p>

            <h3>Raw Headers Summary</h3>
            <p>Below are the raw HTTP response headers observed during the scan:</p>
            <pre><code>[INSERT_RAW_HEADERS_HERE]</code></pre>

            <h3>Technical Debt Assessment</h3>
            <p>[INSERT_TECHNICAL_DEBT_ANALYSIS_HERE]</p>

            <h3>Security Debt Calculation</h3>
            <p>[INSERT_SECURITY_DEBT_ANALYSIS_HERE]</p>
        </section>

        <!-- FOOTER SECTION -->
        <footer style="margin-top: 30px !important; padding-top: 15px !important; border-top: 1px solid #e5e7eb !important; text-align: center !important; color: #6b7280 !important; font-size: 12px !important;">
            <p>Report Generated by CyberShield Security | ${formattedDate} at ${formattedTime} IST</p>
            <p>© ${new Date().getFullYear()} CyberShield Security. All rights reserved.</p>
        </footer>

    </div>
</body>
</html>

INSTRUCTIONS:
1. Keep ALL HTML structure exactly as shown above
2. Replace ALL [PLACEHOLDER] text with actual analysis data from SCAN RESULTS
3. Use proper severity classes: critical, high, medium-high, medium, low-medium, low, info
4. Format dates as: ${formattedDate} at ${formattedTime} IST (use exact timestamp shown above)
5. For severity determination:
   - 0-20: critical
   - 21-40: high
   - 41-60: medium-high
   - 61-70: medium
   - 71-85: low-medium
   - 86-100: low
6. Generate compelling analysis text based on the scan results
7. Include OWASP references where appropriate
8. Make recommendations specific to the vulnerabilities found

SPECIAL INSTRUCTIONS:
- "CyberShield Security" should be in #dc2626 (red color) with a lock emoji
- The target URL should be highlighted with light blue background (#e0f2fe) and bold text
- All time references should show: "${formattedDate} at ${formattedTime} IST"
- Reduce gaps between sections for better spacing
- Make sure the URL is properly highlighted wherever it appears in the report

GENERATE THE COMPLETE HTML REPORT NOW, FOLLOWING THE TEMPLATE EXACTLY:`;

        const result = await model.generateContent(prompt);
        const response = await result.response;
        let aiReport = response.text();
        
        // Clean up the response
        aiReport = aiReport.replace(/```html/g, '').replace(/```/g, '').trim();
        
        // Create downloadable report
        downloadReport(aiReport);
        
    } catch (error) {
        console.error('Error generating AI report:', error);
        setError('Failed to generate AI report. Please try again.');
    } finally {
        setGeneratingReport(false);
    }
};

// Function to download the report as HTML
const downloadReport = (htmlContent) => {
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const date = new Date().toISOString().split('T')[0];
    const urlSlug = results.url.replace(/[^a-z0-9]/gi, '-').replace(/^https?-/, '');
    a.download = `security-report-${urlSlug}-${date}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};
    // Main function to check headers using Cloudflare Worker
    const checkHeaders = async () => {
        if (!url.trim()) {
            setError('Please enter a URL');
            return;
        }

        setLoading(true);
        setError('');
        setResults(null);

        // Abort any previous request
        if (controllerRef.current) {
            controllerRef.current.abort();
        }
        controllerRef.current = new AbortController();

        try {
            let targetUrl = url.trim();
            
            // Add https:// if missing
            if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
                targetUrl = 'https://' + targetUrl;
            }

            console.log(`Checking headers for: ${targetUrl}`);
            console.log(`Using Cloudflare Worker: ${WORKER_URL}`);

            // Using Cloudflare Worker to bypass CORS
            const response = await fetch(`${WORKER_URL}?url=${encodeURIComponent(targetUrl)}`, {
                method: 'GET',
                signal: controllerRef.current.signal,
                headers: {
                    'Accept': '*/*',
                    'User-Agent': 'SecurityHeaderAnalyzer/1.0'
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
            }

            // Extract headers from response
            const headers = {};
            response.headers.forEach((value, key) => {
                headers[key.toLowerCase()] = value;
            });

            console.log('Headers received:', headers);

            const analysis = analyzeSecurityHeaders(headers, targetUrl);
            
            setResults({
                url: targetUrl,
                statusCode: response.status,
                headers: headers,
                analysis: analysis,
                timestamp: new Date().toISOString(),
                note: 'Using Cloudflare Worker for CORS bypass. Real headers analysis.',
                proxyUsed: 'Cloudflare Worker'
            });

        } catch (err) {
            console.error('Error:', err);
            
            // Check if it's an abort error
            if (err.name === 'AbortError') {
                setError('Request was cancelled');
                return;
            }

            // Provide user-friendly error messages
            if (err.message.includes('403') || err.message.includes('Forbidden')) {
                setError('The website is blocking requests (403 Forbidden). Try a different website.');
            } else if (err.message.includes('500') || err.message.includes('Internal Server Error')) {
                setError('Cloudflare Worker encountered an error. Please check if your worker is deployed correctly.');
            } else if (err.message.includes('Failed to fetch')) {
                setError('Network error. Please check your internet connection and Cloudflare Worker URL.');
            } else {
                setError(`Error: ${err.message}`);
            }
            
        } finally {
            setLoading(false);
        }
    };

    const copyToClipboard = (text, headerName) => {
        navigator.clipboard.writeText(text).then(() => {
            setCopiedHeader(headerName);
            setTimeout(() => setCopiedHeader(''), 2000);
        });
    };

    const resetAnalysis = () => {
        setResults(null);
        setUrl('');
        setError('');
    };

    const getSeverityColor = (severity) => {
        switch(severity) {
            case 'critical': return '#dc2626';
            case 'high': return '#ef4444';
            case 'medium-high': return '#f97316';
            case 'medium': return '#f59e0b';
            case 'low-medium': return '#3b82f6';
            case 'low': return '#10b981';
            default: return '#6b7280';
        }
    };

    const renderHeaderCard = (title, data, headerName) => {
        if (!results) return null;

        const isPresent = data.present;
        const severity = data.severity || 'medium';
        const score = data.score || 0;
        
        const shouldShowFix = score < 100 && data.fix;
        const shouldShowCurrentHeaderValue = isPresent && score > 0 && score < 100 && !shouldShowFix;
        const shouldShowPerfectHeaderValue = isPresent && score === 100;
        
        return (
            <div className={`header-card ${isPresent ? 'present' : 'missing'}`}>
                <div className="header-card-top">
                    <div className="header-title">
                        <h3>{title}</h3>
                        <span className="owasp-badge">{data.owaspCategory || data.category || 'Security'}</span>
                    </div>
                    <div className="status-indicator">
                        <div 
                            className={`status-dot ${isPresent ? 'present' : 'missing'}`}
                            style={{
                                boxShadow: isPresent 
                                    ? `0 0 20px ${getSeverityColor(severity)}40`
                                    : 'none',
                                animation: isPresent 
                                    ? 'glow 2s infinite alternate'
                                    : 'pulse 2s infinite'
                            }}
                        />
                        <span className="status-text">
                            {isPresent ? 'PRESENT ✅' : 'MISSING ❌'}
                        </span>
                    </div>
                </div>
                
                <div className="score-bar">
                    <div className="score-label">Security Score:</div>
                    <div className="score-container">
                        <div 
                            className="score-fill"
                            style={{
                                width: `${score}%`,
                                backgroundColor: getSeverityColor(severity)
                            }}
                        />
                        <span className="score-value">{score}/100</span>
                    </div>
                </div>
                
                {shouldShowPerfectHeaderValue && (
                    <>
                        <div className="header-value perfect">
                            <code>{data.value}</code>
                        </div>
                        <div className="secure-status">
                            <div className="secure-message">
                                This header is fully secured according to best practices
                            </div>
                        </div>
                    </>
                )}
                
                {shouldShowCurrentHeaderValue && data.value && (
                    <div className="header-value">
                        <code>{data.value}</code>
                        <button 
                            className="copy-btn"
                            onClick={() => copyToClipboard(data.value, headerName)}
                            title="Copy header value"
                        >
                            {copiedHeader === headerName ? 'Copied!' : '📋'}
                        </button>
                    </div>
                )}
                
                {shouldShowFix && (
                    <div className="fix-section">
                        <div className="fix-label">
                            {score > 0 ? '⚠️ Improvement Needed:' : '🚨 Recommended Fix:'}
                        </div>
                        <div className="fix-code">
                            <code>{data.fix}</code>
                            <button 
                                className="copy-btn"
                                onClick={() => copyToClipboard(data.fix, `${headerName}-fix`)}
                                title="Copy fix"
                            >
                                {copiedHeader === `${headerName}-fix` ? 'Copied!' : '📋'}
                            </button>
                        </div>
                    </div>
                )}
            </div>
        );
    };

    return (
        <div className="security-analyzer-container">
            <div className="analyzer-header">
                <h1>🔒 OWASP Security Header Analyzer</h1>
                <p className="subtitle">Check your website's security headers against OWASP best practices</p>
            </div>

<div className="input-section">
    <div className="url-input-group">
        <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter website URL (e.g., https://example.com)"
            className="url-input"
            disabled={loading}
        />
        <button
            onClick={checkHeaders}
            disabled={loading}
            className="analyze-btn"
        >
            {loading ? (
                <>
                    <span className="spinner"></span>
                    Analyzing...
                </>
            ) : '🔍 Analyze Real Headers'}
        </button>
    </div>
    
    {/* Fixed error message - positioned absolutely */}
    <div className="error-container" style={{ position: 'relative', minHeight: '0px' }}>
       {error && (
    <div className="error-message-overlay">
        <div className="error-popup">
            <div className="error-header">
                <span className="error-icon">⚠️</span>
                <h4>Error</h4>
                <button 
                    className="error-close" 
                    onClick={() => setError('')}
                    aria-label="Close error"
                >
                    ×
                </button>
            </div>
            <div className="error-content">
                <p>{error}</p>
            </div>
        </div>
    </div>
)}
    </div>
</div>
            {loading && (
                <div className="loading-section">
                    <div className="scanning-animation">
                        <div className="radar"></div>
                        <p>Fetching and analyzing security headers via Cloudflare Worker...</p>
                        <p className="loading-note">
                            <small>This may take a few seconds.</small>
                        </p>
                    </div>
                </div>
            )}

            {results && (
                <div className="results-section">
                    <div className="results-header">
                        <h2>Analysis Results for <span className="result-url">{results.url}</span></h2>
                        <div className="action-buttons">
                            <button onClick={resetAnalysis} className="reset-btn">🔄 New Analysis</button>
                            <button 
                                onClick={generateAIReport} 
                                disabled={generatingReport}
                                className="download-report-btn"
                            >
                                {generatingReport ? (
                                    <>
                                        <span className="spinner"></span>
                                        Generating AI Report...
                                    </>
                                ) : '📊 Download AI Report'}
                            </button>
                        </div>
                    </div>

                    <div className="overall-score">
                        <div className="score-circle">
                            <svg width="120" height="120" viewBox="0 0 120 120" style={{ overflow: 'visible' }}>
                                <circle 
                                    cx="60" 
                                    cy="60" 
                                    r="54" 
                                    fill="none" 
                                    stroke={results.analysis.securityScore >= 70 ? '#10b981' : 
                                           results.analysis.securityScore >= 40 ? '#f59e0b' : '#ef4444'} 
                                    strokeWidth="10"
                                    strokeLinecap="round"
                                    strokeDasharray={`${(results.analysis.securityScore / 100) * 339.29} 339.29`}
                                    transform="rotate(-90 60 60)"
                                    style={{ transition: 'stroke-dasharray 0.5s ease' }}
                                />
                            </svg>
                            <div className="score-text">
                                <span className="score-number">{results.analysis.securityScore}</span>
                                <span className="score-label">Security Score</span>
                            </div>
                        </div>
                       <div className="analysis-summary">
    <div className="summary-header">
        <h3>Security Analysis Summary</h3>
        <div className="timestamp">
            <span className="time-icon">🕐</span>
            {new Date(results.timestamp).toLocaleString()}
        </div>
    </div>
    
    <div className="summary-grid">
    <div className="summary-item status-code">
        <div className="item-label">HTTP Status</div>
        <div className="item-value">{results.statusCode}</div>
        <div className="item-badge active">
            <span style={{marginRight: "5px"}}>🌐</span>
            {results.statusCode === 200 ? 'OK' : 
             results.statusCode < 300 ? 'Success' : 'Check Status'}
        </div>
    </div>
        
<div className="summary-item scan-method">
    <div className="item-label">Data</div>
    <div className="item-value">Real-Time Analytics</div>
    <div className="item-status active">📈 Insights</div>
</div>
        <div className="summary-item vulnerabilities">
            <div className="item-label">Vulnerabilities Found</div>
            <div className="item-value">
                {results.analysis.recommendations ? results.analysis.recommendations.length : 0}
            </div>
            <div className="item-subtext active">⚠️ Critical Issues</div>
        </div>
        
        <div className="summary-item ai-report">
            <div className="item-label">AI Report</div>
            <div className="item-value">Ready</div>
            <div className="item-status active">📊 Available</div>
        </div>
    </div>
    
    <div className="owasp-pillars">
        <h4>OWASP Top 10 Coverage</h4>
        <div className="pillars-container">
            <div className="pillar" style={{'--pillar-color': '#dc2626'}}>
                <span className="pillar-number">A02</span>
                <span className="pillar-name">Cryptographic<br/>Failures</span>
            </div>
            <div className="pillar" style={{'--pillar-color': '#7c3aed'}}>
                <span className="pillar-number">A03</span>
                <span className="pillar-name">Injection</span>
            </div>
            <div className="pillar" style={{'--pillar-color': '#0891b2'}}>
                <span className="pillar-number">A01</span>
                <span className="pillar-name">Broken Access<br/>Control</span>
            </div>
            <div className="pillar" style={{'--pillar-color': '#059669'}}>
                <span className="pillar-number">A07</span>
                <span className="pillar-name">Authentication<br/>Failures</span>
            </div>
            <div className="pillar" style={{'--pillar-color': '#d97706'}}>
                <span className="pillar-number">A05</span>
                <span className="pillar-name">Security<br/>Misconfiguration</span>
            </div>
        </div>
    </div>
</div>
                    </div>

                    <div className="headers-grid">
                        {renderHeaderCard('Content Security Policy', results.analysis.csp, 'CSP')}
                        {renderHeaderCard('HTTP Strict Transport Security', results.analysis.hsts, 'HSTS')}
                        {renderHeaderCard('X-Frame-Options', results.analysis.xFrameOptions, 'XFO')}
                        {renderHeaderCard('X-Content-Type-Options', results.analysis.xContentTypeOptions, 'XCTO')}
                        {renderHeaderCard('Referrer Policy', results.analysis.referrerPolicy, 'RP')}
                        {renderHeaderCard('Permissions Policy', results.analysis.permissionsPolicy, 'PP')}
                        {renderHeaderCard('X-XSS-Protection', results.analysis.xXSSProtection, 'XXSS')}
                        {renderHeaderCard('CORS Headers', results.analysis.cors, 'CORS')}
                        {renderHeaderCard('Authentication Headers', results.analysis.authentication, 'AUTH')}
                        {renderHeaderCard('Cookie Security', results.analysis.cookieSecurity, 'COOKIES')}
                        {renderHeaderCard('Information Disclosure', results.analysis.informationDisclosure, 'INFO')}
                        {renderHeaderCard('Cache Control', results.analysis.cacheControl, 'CACHE')}
                        {renderHeaderCard('Security Reporting', results.analysis.securityReporting, 'REPORT')}
                        {renderHeaderCard('Performance Headers', results.analysis.performanceHeaders, 'PERF')}
                        {renderHeaderCard('Modern Web Standards', results.analysis.modernWebStandards, 'MODERN')}
                    </div>

                    {results.analysis.recommendations && results.analysis.recommendations.length > 0 && (
                        <div className="recommendations">
                            <h3>🔧 Security Recommendations</h3>
                            {results.analysis.recommendations.map((rec, index) => (
                                <div key={index} className="recommendation-card">
                                    <div className="rec-header">
                                        <span className="rec-severity" style={{backgroundColor: getSeverityColor(rec.severity)}}>
                                            {rec.severity.toUpperCase()}
                                        </span>
                                        <span className="rec-owasp">{rec.owaspCategory || rec.category || 'Security'}</span>
                                    </div>
                                    <h4>{rec.header}</h4>
                                    <p>{rec.description}</p>
                                    <div className="rec-fix">
                                        <code>{rec.fix}</code>
                                        <button 
                                            className="copy-btn"
                                            onClick={() => copyToClipboard(rec.fix, `rec-${index}`)}
                                        >
                                            {copiedHeader === `rec-${index}` ? 'Copied!' : '📋'}
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}

                    <div className="raw-headers">
                        <details>
                            <summary>📋 View Raw Headers</summary>
                            <pre className="headers-raw">
                                {JSON.stringify(results.headers, null, 2)}
                            </pre>
                        </details>
                    </div>
                </div>
            )}

            {!results && !loading && (
                <div className="info-section">
                    <div className="info-card">
                        <h3>What This Tool Checks</h3>
                        <ul>
                            <li><strong>CSP</strong> - Prevents XSS attacks by controlling resources</li>
                            <li><strong>HSTS</strong> - Forces HTTPS connections only</li>
                            <li><strong>X-Frame-Options</strong> - Prevents clickjacking attacks</li>
                            <li><strong>X-Content-Type-Options</strong> - Stops MIME type sniffing</li>
                            <li><strong>Referrer-Policy</strong> - Controls referrer information</li>
                            <li><strong>Permissions-Policy</strong> - Controls browser features access</li>
                            <li><strong>X-XSS-Protection</strong> - Legacy XSS protection</li>
                            <li><strong>CORS Headers</strong> - Cross-origin resource sharing security</li>
                            <li><strong>Authentication Headers</strong> - Checks for weak authentication schemes</li>
                            <li><strong>Cookie Security</strong> - Session and authentication protection</li>
                            <li><strong>Information Disclosure</strong> - Server version and info leaks</li>
                            <li><strong>Cache Control</strong> - Prevents sensitive data caching</li>
                            <li><strong>Security Reporting</strong> - Security logging and monitoring</li>
                            <li><strong>Performance Headers</strong> - Performance and optimization</li>
                            <li><strong>Modern Web Standards</strong> - Latest web security headers</li>
                        </ul>
                        <div className="demo-instructions">
                            <h4>💡 How to Use:</h4>
                            <p>1. Enter a URL and click "Analyze Real Headers"</p>
                            <p>2. The tool uses your Cloudflare Worker to fetch headers</p>
                            <p>3. Results show actual security headers from the live website</p>
                            <p>4. Download comprehensive AI-powered security report</p>
                            <p>5. 🤖 AI Report: Click "Download AI Report" for comprehensive security analysis using AI</p>
                            <p><strong>Test with these working sites:</strong></p>
                            <ul>
                                <li style={{cursor: 'pointer', color: '#3b82f6', textDecoration: 'underline'}} onClick={() => setUrl('https://api.github.com')}>
                                    https://api.github.com
                                </li>
                                <li style={{cursor: 'pointer', color: '#3b82f6', textDecoration: 'underline'}} onClick={() => setUrl('https://jsonplaceholder.typicode.com')}>
                                    https://jsonplaceholder.typicode.com
                                </li>
                                <li style={{cursor: 'pointer', color: '#3b82f6', textDecoration: 'underline'}} onClick={() => setUrl('https://example.com')}>
                                    https://example.com
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default SecurityHeaderAnalyzer;