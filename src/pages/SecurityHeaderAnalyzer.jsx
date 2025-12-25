import { useState, useRef } from 'react';

const SecurityHeaderAnalyzer = () => {
    const [url, setUrl] = useState('');
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState('');
    const [copiedHeader, setCopiedHeader] = useState('');
    const controllerRef = useRef(null);

    // --- CLOUDFLARE WORKER URL ---
    const WORKER_URL = "https://header-proxy.ahmedseliya07.workers.dev/";

    // Header analysis functions
    const checkCSP = (headers) => {
        const csp = headers['content-security-policy'] || headers['Content-Security-Policy'];
        if (!csp) return { present: false, score: 0, severity: 'high', fix: "Content-Security-Policy: default-src 'self'; script-src 'self'" };
        
        const directives = csp.toLowerCase().split(';').map(d => d.trim());
        const hasDefaultSrc = directives.some(d => d.startsWith('default-src'));
        const hasScriptSrc = directives.some(d => d.startsWith('script-src'));
        
        return {
            present: true,
            value: csp,
            score: hasDefaultSrc && hasScriptSrc ? 100 : 70,
            severity: hasDefaultSrc && hasScriptSrc ? 'low' : 'medium',
            directives: directives
        };
    };

    const checkHSTS = (headers, url) => {
        const hsts = headers['strict-transport-security'] || headers['Strict-Transport-Security'];
        const fix = 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload';
        
        if (!hsts) return { 
            present: false, 
            score: 0, 
            severity: url.startsWith('https') ? 'high' : 'medium',
            fix: fix
        };
        
        const includesMaxAge = hsts.includes('max-age=');
        const includesPreload = hsts.includes('preload');
        const includesIncludeSubDomains = hsts.includes('includeSubDomains');
        
        let score = 60;
        if (includesMaxAge) score += 20;
        if (includesIncludeSubDomains) score += 10;
        if (includesPreload) score += 10;
        
        return {
            present: true,
            value: hsts,
            score: score,
            severity: score >= 90 ? 'low' : 'medium',
            maxAge: includesMaxAge,
            preload: includesPreload,
            includeSubDomains: includesIncludeSubDomains
        };
    };

    const checkXFrameOptions = (headers) => {
        const xfo = headers['x-frame-options'] || headers['X-Frame-Options'];
        const fix = 'X-Frame-Options: DENY';
        
        if (!xfo) return { present: false, score: 0, severity: 'medium', fix: fix };
        
        const value = xfo.toLowerCase();
        const isDeny = value === 'deny';
        const isSameOrigin = value === 'sameorigin';
        
        return {
            present: true,
            value: xfo,
            score: isDeny || isSameOrigin ? 100 : 50,
            severity: isDeny || isSameOrigin ? 'low' : 'medium'
        };
    };

    const checkXContentTypeOptions = (headers) => {
        const xcto = headers['x-content-type-options'] || headers['X-Content-Type-Options'];
        const isPresent = xcto && xcto.toLowerCase() === 'nosniff';
        const fix = 'X-Content-Type-Options: nosniff';
        
        return {
            present: isPresent,
            value: xcto,
            score: isPresent ? 100 : 0,
            severity: isPresent ? 'low' : 'medium',
            fix: isPresent ? undefined : fix
        };
    };

    const checkReferrerPolicy = (headers) => {
        const rp = headers['referrer-policy'] || headers['Referrer-Policy'];
        const validPolicies = ['no-referrer', 'no-referrer-when-downgrade', 'origin', 
                              'origin-when-cross-origin', 'same-origin', 'strict-origin', 
                              'strict-origin-when-cross-origin'];
        const fix = 'Referrer-Policy: strict-origin-when-cross-origin';
        
        const isPresent = rp && validPolicies.includes(rp.toLowerCase());
        
        return {
            present: isPresent,
            value: rp,
            score: isPresent ? 100 : 0,
            severity: isPresent ? 'low' : 'low-medium',
            fix: isPresent ? undefined : fix
        };
    };

    const checkPermissionsPolicy = (headers) => {
        const pp = headers['permissions-policy'] || headers['Permissions-Policy'] || 
                   headers['feature-policy'] || headers['Feature-Policy'];
        const fix = 'Permissions-Policy: geolocation=(), microphone=(), camera=()';
        
        return {
            present: !!pp,
            value: pp,
            score: pp ? 100 : 0,
            severity: pp ? 'low' : 'low-medium',
            fix: pp ? undefined : fix
        };
    };

    const checkXXSSProtection = (headers) => {
        const xss = headers['x-xss-protection'] || headers['X-XSS-Protection'];
        const isPresent = xss && (xss.includes('1; mode=block') || xss.includes('1'));
        const fix = 'X-XSS-Protection: 1; mode=block';
        
        return {
            present: !!xss,
            value: xss,
            score: isPresent ? 100 : 50,
            severity: isPresent ? 'low' : 'medium',
            hasModeBlock: xss && xss.includes('mode=block'),
            fix: isPresent ? undefined : fix
        };
    };

    const calculateSecurityScore = (headers) => {
        const checks = [
            checkCSP(headers),
            checkHSTS(headers, ''),
            checkXFrameOptions(headers),
            checkXContentTypeOptions(headers),
            checkReferrerPolicy(headers),
            checkPermissionsPolicy(headers),
            checkXXSSProtection(headers)
        ];
        
        const totalScore = checks.reduce((sum, check) => sum + check.score, 0);
        return Math.round(totalScore / checks.length);
    };

    const generateRecommendations = (headers) => {
        const recommendations = [];
        
        const cspResult = checkCSP(headers);
        const hstsResult = checkHSTS(headers, '');
        const xFrameResult = checkXFrameOptions(headers);
        const xContentResult = checkXContentTypeOptions(headers);
        const referrerResult = checkReferrerPolicy(headers);
        const permissionsResult = checkPermissionsPolicy(headers);
        const xssResult = checkXXSSProtection(headers);
        
        if (!cspResult.present) {
            recommendations.push({
                header: 'Content-Security-Policy',
                severity: 'high',
                description: 'Missing CSP header leaves site vulnerable to XSS attacks',
                fix: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';`,
                owaspCategory: 'A03: Injection'
            });
        }
        
        if (!hstsResult.present) {
            recommendations.push({
                header: 'Strict-Transport-Security',
                severity: 'high',
                description: 'Missing HSTS header allows SSL stripping attacks',
                fix: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                owaspCategory: 'A05: Security Misconfiguration'
            });
        }
        
        if (!xFrameResult.present) {
            recommendations.push({
                header: 'X-Frame-Options',
                severity: 'medium',
                description: 'Missing X-Frame-Options allows clickjacking attacks',
                fix: 'X-Frame-Options: DENY (or SAMEORIGIN if needed)',
                owaspCategory: 'A05: Security Misconfiguration'
            });
        }
        
        if (!xContentResult.present) {
            recommendations.push({
                header: 'X-Content-Type-Options',
                severity: 'medium',
                description: 'Missing header allows MIME sniffing attacks',
                fix: 'X-Content-Type-Options: nosniff',
                owaspCategory: 'A05: Security Misconfiguration'
            });
        }
        
        if (!referrerResult.present) {
            recommendations.push({
                header: 'Referrer-Policy',
                severity: 'low-medium',
                description: 'Missing Referrer-Policy can leak sensitive URL information',
                fix: 'Referrer-Policy: strict-origin-when-cross-origin',
                owaspCategory: 'A05: Security Misconfiguration'
            });
        }
        
        if (!permissionsResult.present) {
            recommendations.push({
                header: 'Permissions-Policy',
                severity: 'low-medium',
                description: 'Missing Permissions-Policy allows unrestricted access to sensitive browser features',
                fix: 'Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()',
                owaspCategory: 'A05: Security Misconfiguration'
            });
        }
        
        if (!xssResult.present || !xssResult.hasModeBlock) {
            recommendations.push({
                header: 'X-XSS-Protection',
                severity: 'medium',
                description: 'Missing or weak X-XSS-Protection header',
                fix: 'X-XSS-Protection: 1; mode=block',
                owaspCategory: 'A03: Injection'
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
        
        return {
            csp,
            hsts,
            xFrameOptions,
            xContentTypeOptions,
            referrerPolicy,
            permissionsPolicy,
            xXSSProtection,
            securityScore: calculateSecurityScore(headers),
            recommendations: generateRecommendations(headers)
        };
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
                // Convert header keys to lowercase for consistency
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
            case 'high': return '#ef4444';
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
        
        return (
            <div className={`header-card ${isPresent ? 'present' : 'missing'}`}>
                <div className="header-card-top">
                    <div className="header-title">
                        <h3>{title}</h3>
                        <span className="owasp-badge">{headerName}</span>
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
                
                {data.value && (
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
                
                {!isPresent && data.fix && (
                    <div className="fix-section">
                        <div className="fix-label">Recommended Fix:</div>
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
                <p className="demo-note">
                    <small>
                        ⚠️ Using Cloudflare Worker for reliable CORS bypass.
                    </small>
                </p>
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
                {error && <div className="error-message">{error}</div>}
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
                        <button onClick={resetAnalysis} className="reset-btn">🔄 New Analysis</button>
                    </div>

                    {results.note && (
                        <div className="analysis-note">
                            <p>ℹ️ {results.note}</p>
                        </div>
                    )}

                    <div className="overall-score">
                        <div className="score-circle">
                            <svg width="120" height="120" viewBox="0 0 120 120">
                                <circle 
                                    cx="60" 
                                    cy="60" 
                                    r="54" 
                                    fill="none" 
                                    stroke="var(--border-color)" 
                                    strokeWidth="8"
                                />
                                <circle 
                                    cx="60" 
                                    cy="60" 
                                    r="54" 
                                    fill="none" 
                                    stroke={results.analysis.securityScore >= 70 ? '#10b981' : 
                                           results.analysis.securityScore >= 40 ? '#f59e0b' : '#ef4444'} 
                                    strokeWidth="8"
                                    strokeLinecap="round"
                                    strokeDasharray={`${(results.analysis.securityScore / 100) * 339} 339`}
                                    transform="rotate(-90 60 60)"
                                />
                            </svg>
                            <div className="score-text">
                                <span className="score-number">{results.analysis.securityScore}</span>
                                <span className="score-label">Security Score</span>
                            </div>
                        </div>
                        <div className="score-breakdown">
                            <h3>Analysis Details</h3>
                            <ul>
                                <li>🎯 <strong>A05:</strong> Security Misconfiguration</li>
                                <li>🎯 <strong>A03:</strong> Injection (CSP impact)</li>
                                <li>🛡️ <strong>Status Code:</strong> {results.statusCode}</li>
                                <li>⏰ <strong>Checked:</strong> {new Date(results.timestamp).toLocaleTimeString()}</li>
                                <li>🔗 <strong>Method:</strong> Cloudflare Worker CORS bypass</li>
                            </ul>
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
                                        <span className="rec-owasp">{rec.owaspCategory}</span>
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
                        </ul>
                        <div className="demo-instructions">
                            <h4>💡 How to Use:</h4>
                            <p>1. Enter a URL and click "Analyze Real Headers"</p>
                            <p>2. The tool uses your Cloudflare Worker to fetch headers</p>
                            <p>3. Results show actual security headers from the live website</p>
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