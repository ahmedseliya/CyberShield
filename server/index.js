import express from 'express';
import cors from 'cors';
import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { GoogleGenerativeAI } from '@google/generative-ai';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const execAsync = promisify(exec);
const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ==================== AFFECTED ASSETS DATABASE ====================
const affectedAssetsDatabase = {
  'sql': [
    ['User Database', 'Application Data', 'Admin Credentials', 'Customer PII', 'Transaction Records'],
    ['Database Server', 'Application Server', 'User Accounts', 'Payment Information'],
    ['SQL Database', 'Application Tables', 'Authentication Data', 'Session Data']
  ],
  'xss': [
    ['User Sessions', 'Browser Cookies', 'Frontend Application', 'Authentication Tokens'],
    ['User Data', 'DOM Elements', 'Local Storage', 'Session Storage'],
    ['Web Application', 'User Profiles', 'Comment Sections', 'Chat Messages']
  ],
  'jwt': [
    ['User Accounts', 'Admin Panel', 'Protected Resources', 'API Endpoints'],
    ['Authentication System', 'Token Store', 'User Permissions', 'Access Control'],
    ['JWT Tokens', 'User Sessions', 'Authorization System', 'Account Data']
  ],
  'path': [
    ['File System', 'Server Files', 'Configuration Files', 'Source Code'],
    ['Application Server', 'File Storage', 'Backend System', 'Sensitive Documents'],
    ['Directory Structure', 'Static Assets', 'Upload Directory', 'System Files']
  ],
  'command': [
    ['Server', 'Operating System', 'Application Host', 'Process Manager'],
    ['Command Execution', 'System Shell', 'Background Processes', 'Server Resources'],
    ['Host Machine', 'Application Server', 'System Commands', 'Process Environment']
  ],
  'crypto': [
    ['Encryption Keys', 'Sensitive Data', 'Secrets Manager', 'Configuration'],
    ['Password Store', 'API Keys', 'Certificates', 'Security Module'],
    ['Cryptographic System', 'Key Storage', 'Secure Memory', 'Encryption Module']
  ],
  'prototype': [
    ['JavaScript Objects', 'Application State', 'Prototype Chain', 'Object Properties'],
    ['Client-side Memory', 'Browser Environment', 'Application Logic', 'Data Structures'],
    ['JavaScript Runtime', 'Object Inheritance', 'Application Code', 'Memory Space']
  ],
  'default': [
    ['Application Code', 'User Data', 'System Resources', 'Network Services'],
    ['Application Logic', 'Data Processing', 'User Input', 'Backend Services'],
    ['Application Components', 'Data Flow', 'Security Controls', 'Access Points']
  ],
  'osv': [
    ['Dependencies', 'Package Manager', 'Third-party Libraries', 'Application Runtime'],
    ['Node Modules', 'Python Packages', 'Java Libraries', 'Ruby Gems'],
    ['Vulnerable Component', 'Dependency Tree', 'Package Registry', 'Application Build']
  ]
};

const getRandomAffectedAssets = (ruleId, source) => {
  const ruleStr = ruleId?.toLowerCase() || '';
  let assetSet = 'default';
  
  if (source && source.includes('OSV')) {
    assetSet = 'osv';
  } else if (ruleStr.includes('sql')) {
    assetSet = 'sql';
  } else if (ruleStr.includes('xss')) {
    assetSet = 'xss';
  } else if (ruleStr.includes('jwt') || ruleStr.includes('auth')) {
    assetSet = 'jwt';
  } else if (ruleStr.includes('path') || ruleStr.includes('file') || ruleStr.includes('traversal')) {
    assetSet = 'path';
  } else if (ruleStr.includes('command') || ruleStr.includes('exec')) {
    assetSet = 'command';
  } else if (ruleStr.includes('crypto') || ruleStr.includes('encrypt') || ruleStr.includes('secret')) {
    assetSet = 'crypto';
  } else if (ruleStr.includes('prototype')) {
    assetSet = 'prototype';
  }
  
  const options = affectedAssetsDatabase[assetSet] || affectedAssetsDatabase.default;
  const randomIndex = Math.floor(Math.random() * options.length);
  return options[randomIndex];
};

// ==================== JSON SANITIZER HELPER ====================
const sanitizeJSONString = (jsonString) => {
  if (!jsonString) return jsonString;
  
  let cleaned = jsonString.replace(/```json\s*/g, '').replace(/```\s*$/g, '').trim();
  
  const jsonMatch = cleaned.match(/(\[[\s\S]*\]|\{[\s\S]*\})/);
  if (!jsonMatch) {
    return jsonString;
  }
  
  let jsonContent = jsonMatch[0];
  jsonContent = jsonContent.replace(/\\(?!["\\/bfnrt])/g, '\\\\');
  
  let inString = false;
  let escaped = false;
  let result = '';
  
  for (let i = 0; i < jsonContent.length; i++) {
    const char = jsonContent[i];
    
    if (char === '\\' && !escaped) {
      escaped = true;
      result += char;
      continue;
    }
    
    if (char === '"' && !escaped) {
      inString = !inString;
      result += char;
    } else if (char === '\n' && inString) {
      result += '\\n';
    } else if (char === '\r' && inString) {
      result += '\\r';
    } else if (char === '\t' && inString) {
      result += '\\t';
    } else {
      result += char;
    }
    
    escaped = false;
  }
  
  return result;
};

// ==================== SEMGREP ANALYSIS ====================
const analyzeWithSemgrep = async (gitUrl) => {
  console.log('🔄 Starting Semgrep analysis...');
  console.log('📌 Repository:', gitUrl);
  
  const tempDir = path.join(os.tmpdir(), `semgrep-scan-${Date.now()}`);
  
  try {
    await execAsync(`git clone --depth 1 ${gitUrl} "${tempDir}"`);
    console.log('✅ Repository cloned successfully');
    
    let semgrepPath = 'semgrep';
    try {
      const { stdout } = await execAsync('where semgrep', { shell: true });
      const paths = stdout.split('\n').filter(p => p.trim().length > 0);
      if (paths.length > 0) {
        semgrepPath = paths[0].trim();
        console.log(`✅ Found semgrep at: ${semgrepPath}`);
      }
    } catch (error) {
      console.log('⚠️ Using semgrep from PATH');
    }
    
    const env = {
      ...process.env,
      PYTHONIOENCODING: 'utf-8',
      PYTHONUTF8: '1',
      LC_ALL: 'en_US.UTF-8',
      LANG: 'en_US.UTF-8'
    };
    
    const configs = ['auto', 'p/security-audit', 'p/owasp-top-ten', 'p/r2c-security-audit'];
    let findings = [];
    let usedConfig = '';
    
    for (const config of configs) {
      try {
        console.log(`   Testing config: ${config}`);
        const cmd = `"${semgrepPath}" scan --config ${config} --json "${tempDir}"`;
        
        const result = await execAsync(cmd, { 
          maxBuffer: 100 * 1024 * 1024,
          timeout: 300000,
          shell: true,
          windowsHide: true,
          encoding: 'utf8',
          env: env
        });
        
        if (result.stdout && result.stdout.trim()) {
          const jsonMatch = result.stdout.match(/\{[\s\S]*\}/);
          if (jsonMatch) {
            const semgrepResults = JSON.parse(jsonMatch[0]);
            const newFindings = semgrepResults.results || [];
            
            if (newFindings.length > 0) {
              console.log(`   ✅ Found ${newFindings.length} findings with ${config}`);
              findings = newFindings;
              usedConfig = config;
              
              findings.slice(0, 3).forEach((f, i) => {
                const sev = f.extra?.severity || 'unknown';
                console.log(`      ${i+1}. [${sev}] ${f.check_id} in ${path.basename(f.path)}:${f.start?.line}`);
              });
              
              break;
            }
          }
        }
      } catch (error) {
        if (error.stdout && error.stdout.trim()) {
          const jsonMatch = error.stdout.match(/\{[\s\S]*\}/);
          if (jsonMatch) {
            try {
              const semgrepResults = JSON.parse(jsonMatch[0]);
              const newFindings = semgrepResults.results || [];
              if (newFindings.length > 0) {
                console.log(`   ✅ Found ${newFindings.length} findings from ${config} (from error output)`);
                findings = newFindings;
                usedConfig = config;
                break;
              }
            } catch (e) {}
          }
        }
      }
    }
    
    if (findings.length > 0) {
      console.log(`📊 TOTAL REAL FINDINGS: ${findings.length} (using ${usedConfig})`);
      
      const errors = findings.filter(f => f.extra?.severity === 'ERROR').length;
      const warnings = findings.filter(f => f.extra?.severity === 'WARNING').length;
      const infos = findings.filter(f => f.extra?.severity === 'INFO').length;
      console.log(`   Errors: ${errors}, Warnings: ${warnings}, Info: ${infos}`);
    } else {
      console.log('⚠️ No vulnerabilities found by semgrep in this repository');
    }
    
    const dependencies = await extractDependencies(tempDir);
    
    try {
      if (process.platform === 'win32') {
        await execAsync(`rmdir /s /q "${tempDir}"`);
      } else {
        await execAsync(`rm -rf "${tempDir}"`);
      }
    } catch (e) {
      console.warn('Cleanup failed:', e.message);
    }
    
    return {
      findings,
      dependencies,
      fileCount: findings.length,
      summary: `Found ${findings.length} real vulnerabilities`
    };
    
  } catch (error) {
    console.error('❌ Semgrep analysis failed:', error);
    
    try {
      if (fs.existsSync(tempDir)) {
        if (process.platform === 'win32') {
          await execAsync(`rmdir /s /q "${tempDir}"`);
        } else {
          await execAsync(`rm -rf "${tempDir}"`);
        }
      }
    } catch (e) {}
    
    return {
      findings: [],
      dependencies: [],
      fileCount: 0,
      summary: `Semgrep analysis failed: ${error.message}`
    };
  }
};

// ==================== EXTRACT DEPENDENCIES ====================
const extractDependencies = async (repoPath) => {
  const dependencies = [];
  
  try {
    const packageJsonPath = path.join(repoPath, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      const content = fs.readFileSync(packageJsonPath, 'utf8');
      const packageJson = JSON.parse(content);
      
      if (packageJson.dependencies) {
        Object.entries(packageJson.dependencies).forEach(([name, version]) => {
          dependencies.push({
            ecosystem: 'npm',
            name,
            version: version.replace(/^\^|~/, ''),
            source: 'package.json'
          });
        });
      }
      
      if (packageJson.devDependencies) {
        Object.entries(packageJson.devDependencies).forEach(([name, version]) => {
          dependencies.push({
            ecosystem: 'npm',
            name,
            version: version.replace(/^\^|~/, ''),
            source: 'package.json (dev)'
          });
        });
      }
      console.log(`📦 Found ${dependencies.length} npm dependencies`);
    }
  } catch (e) {
    console.warn('Could not parse package.json:', e.message);
  }
  
  try {
    const requirementsPath = path.join(repoPath, 'requirements.txt');
    if (fs.existsSync(requirementsPath)) {
      const content = fs.readFileSync(requirementsPath, 'utf8');
      const lines = content.split('\n');
      
      lines.forEach(line => {
        const cleanLine = line.trim();
        if (cleanLine && !cleanLine.startsWith('#')) {
          const match = cleanLine.match(/^([a-zA-Z0-9-_\[\]]+)([=!~]=?)?([0-9a-zA-Z.-]*)/);
          if (match && match[1]) {
            dependencies.push({
              ecosystem: 'PyPI',
              name: match[1],
              version: match[3] || 'unknown',
              source: 'requirements.txt'
            });
          }
        }
      });
      console.log(`📦 Found Python dependencies from requirements.txt`);
    }
  } catch (e) {
    console.warn('Could not parse requirements.txt:', e.message);
  }
  
  return dependencies;
};

// ==================== OSV CHECKER ====================
const checkOSVVulnerabilities = async (dependencies) => {
  if (dependencies.length === 0) {
    return { vulnerabilities: [], summary: 'No dependencies found to check' };
  }
  
  try {
    const queries = dependencies
      .map(dep => ({
        version: dep.version || '0.0.0',
        package: {
          name: dep.name || 'unknown',
          ecosystem: dep.ecosystem || 'npm'
        }
      }))
      .filter(q => q.package.name !== 'unknown' && q.version !== '0.0.0');
    
    if (queries.length === 0) {
      return { vulnerabilities: [], summary: 'No valid dependency versions found' };
    }
    
    console.log(`🔍 Checking ${queries.length} dependencies with OSV...`);
    
    const response = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ queries })
    });
    
    if (!response.ok) {
      throw new Error(`OSV API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    const vulnerabilities = [];
    data.results?.forEach((result, index) => {
      if (result.vulns && result.vulns.length > 0) {
        const dep = dependencies[index];
        result.vulns.forEach(vuln => {
          let severity = determineSeverityFromOSV(vuln);
          
          vulnerabilities.push({
            id: vuln.id || `osv-${Date.now()}-${index}-${Math.random().toString(36).substr(2, 5)}`,
            title: vuln.summary || `${dep.name} Vulnerability`,
            severity: severity,
            category: 'A06: Vulnerable Components',
            riskScore: calculateRealRiskScoreForOSV(vuln, dep, severity),
            stride: mapOSVToSTRIDE(vuln),
            cwe: extractCWE(vuln),
            component: `${dep.name}@${dep.version}`,
            description: vuln.details || `Security vulnerability in ${dep.name} version ${dep.version}`,
            attackVector: generateAttackVectorForOSV(vuln, dep),
            impact: calculateOSVImpact(severity, vuln),
            likelihood: severity === 'critical' ? 'HIGH' : severity === 'high' ? 'HIGH' : severity === 'medium' ? 'MEDIUM' : 'LOW',
            affectedAssets: getRandomAffectedAssets(dep.name, 'OSV'),
            mitigation: generateMitigationForOSV(dep.name, vuln),
            codeExample: {
              vulnerable: `// Vulnerable: ${dep.name}@${dep.version}\n// This version has known security issues`,
              secure: `// Fixed: Update to secure version\n// Run: npm update ${dep.name}\n// Or check OSV for fixed version`
            },
            testing: 'Run npm audit, yarn audit, or use Snyk for dependency scanning',
            references: vuln.references?.map(ref => ref.url) || ['https://osv.dev'],
            confirmed: true,
            source: 'OSV.dev API',
            file: 'package.json',
            line: 'dependencies section'
          });
        });
      }
    });
    
    console.log(`📊 OSV found ${vulnerabilities.length} vulnerabilities`);
    
    const severityCounts = {
      critical: vulnerabilities.filter(v => v.severity === 'critical').length,
      high: vulnerabilities.filter(v => v.severity === 'high').length,
      medium: vulnerabilities.filter(v => v.severity === 'medium').length,
      low: vulnerabilities.filter(v => v.severity === 'low').length
    };
    console.log('   OSV Severity Distribution:', severityCounts);
    
    return {
      vulnerabilities,
      summary: `Found ${vulnerabilities.length} confirmed vulnerabilities in ${dependencies.length} dependencies`
    };
    
  } catch (error) {
    console.error('OSV check failed:', error);
    return { vulnerabilities: [], summary: `Dependency check failed: ${error.message}` };
  }
};

// ==================== SEVERITY DETERMINATION ====================
const determineSeverityFromOSV = (vuln) => {
  if (vuln.database_specific?.cvss) {
    const cvss = vuln.database_specific.cvss;
    if (cvss.score) {
      if (cvss.score >= 9.0) return 'critical';
      if (cvss.score >= 7.0) return 'high';
      if (cvss.score >= 4.0) return 'medium';
      return 'low';
    }
  }
  
  if (vuln.severity) {
    const sev = vuln.severity.toUpperCase();
    if (sev === 'CRITICAL') return 'critical';
    if (sev === 'HIGH') return 'high';
    if (sev === 'MODERATE') return 'medium';
  }
  
  const summary = (vuln.summary || '').toLowerCase();
  const details = (vuln.details || '').toLowerCase();
  const fullText = summary + ' ' + details;
  
  if (fullText.includes('remote code execution') || fullText.includes('rce') || 
      fullText.includes('critical') || fullText.includes('arbitrary code')) {
    return 'critical';
  }
  if (fullText.includes('sql injection') || fullText.includes('xss') || 
      fullText.includes('authentication bypass') || fullText.includes('privilege escalation') ||
      fullText.includes('prototype pollution') || fullText.includes('command injection')) {
    return 'high';
  }
  if (fullText.includes('denial of service') || fullText.includes('dos') ||
      fullText.includes('information disclosure') || fullText.includes('directory traversal')) {
    return 'medium';
  }
  
  if (vuln.database_specific?.cwe_ids) {
    const criticalCWEs = ['CWE-94', 'CWE-95', 'CWE-77', 'CWE-78', 'CWE-89', 'CWE-502'];
    const highCWEs = ['CWE-79', 'CWE-287', 'CWE-269', 'CWE-1321'];
    const mediumCWEs = ['CWE-22', 'CWE-200', 'CWE-400'];
    
    for (const cwe of vuln.database_specific.cwe_ids) {
      if (criticalCWEs.some(c => cwe.includes(c))) return 'critical';
      if (highCWEs.some(c => cwe.includes(c))) return 'high';
      if (mediumCWEs.some(c => cwe.includes(c))) return 'medium';
    }
  }
  
  const popularPackages = ['express', 'lodash', 'mongoose', 'jquery', 'react', 'vue', 'angular', 'axios', 'body-parser', 'ejs'];
  if (popularPackages.some(pkg => vuln.id?.toLowerCase().includes(pkg))) {
    return 'high';
  }
  
  return 'medium';
};

const mapOSVToSTRIDE = (vuln) => {
  const summary = (vuln.summary || '').toLowerCase();
  const details = (vuln.details || '').toLowerCase();
  const fullText = summary + ' ' + details;
  
  if (fullText.includes('xss') || fullText.includes('spoof')) return 'Spoofing';
  if (fullText.includes('tamper') || fullText.includes('modify') || fullText.includes('injection')) return 'Tampering';
  if (fullText.includes('repudiation')) return 'Repudiation';
  if (fullText.includes('information disclosure') || fullText.includes('leak')) return 'Information Disclosure';
  if (fullText.includes('dos') || fullText.includes('denial')) return 'Denial of Service';
  if (fullText.includes('privilege') || fullText.includes('auth bypass')) return 'Elevation of Privilege';
  
  return 'Tampering';
};

// ==================== RISK SCORE CALCULATION ====================
const calculateRealRiskScoreForOSV = (vuln, dep, severity) => {
  let baseScore = 0;
  
  switch(severity) {
    case 'critical': baseScore = 9.5; break;
    case 'high': baseScore = 7.5; break;
    case 'medium': baseScore = 5.5; break;
    default: baseScore = 3.5;
  }
  
  if (vuln.database_specific?.cvss) {
    const cvss = vuln.database_specific.cvss;
    if (cvss.score) {
      baseScore = cvss.score;
    }
  }
  
  const highImpactPackages = ['express', 'lodash', 'mongoose', 'jquery', 'react', 'vue', 'angular', 'axios'];
  const mediumImpactPackages = ['body-parser', 'ejs', 'hbs', 'marked', 'moment', 'validator'];
  
  if (highImpactPackages.includes(dep.name?.toLowerCase())) {
    baseScore = Math.min(10, baseScore + 1.0);
  } else if (mediumImpactPackages.includes(dep.name?.toLowerCase())) {
    baseScore = Math.min(10, baseScore + 0.5);
  }
  
  if (vuln.references?.some(ref => ref.url?.includes('exploit') || ref.url?.includes('poc'))) {
    baseScore = Math.min(10, baseScore + 1.5);
  }
  
  if (vuln.modified) {
    const modifiedDate = new Date(vuln.modified);
    const ageInDays = (Date.now() - modifiedDate.getTime()) / (1000 * 60 * 60 * 24);
    if (ageInDays > 365) {
      baseScore = Math.min(10, baseScore + 0.5);
    }
  }
  
  return Math.round(baseScore * 10) / 10;
};

const calculateRealRiskScoreForSemgrep = (finding) => {
  const ruleId = finding.check_id?.toLowerCase() || '';
  let baseScore = 0;
  
  const severity = finding.extra?.severity;
  if (severity === 'ERROR') baseScore = 8.5;
  else if (severity === 'WARNING') baseScore = 6.5;
  else baseScore = 4.5;
  
  if (ruleId.includes('command') || ruleId.includes('exec') || ruleId.includes('eval')) {
    baseScore = Math.min(10, baseScore + 2.0);
  }
  else if (ruleId.includes('sql') || ruleId.includes('injection')) {
    baseScore = Math.min(10, baseScore + 1.8);
  }
  else if (ruleId.includes('xss')) {
    baseScore = Math.min(10, baseScore + 1.2);
  }
  else if (ruleId.includes('auth') || ruleId.includes('jwt') || ruleId.includes('session')) {
    baseScore = Math.min(10, baseScore + 1.5);
  }
  else if (ruleId.includes('path') || ruleId.includes('traversal')) {
    baseScore = Math.min(10, baseScore + 1.0);
  }
  else if (ruleId.includes('docker') || ruleId.includes('container') || ruleId.includes('root')) {
    baseScore = Math.min(10, baseScore + 2.0);
  }
  else if (ruleId.includes('csrf')) {
    baseScore = Math.min(10, baseScore + 1.0);
  }
  
  if (finding.extra?.message?.toLowerCase().includes('user') || 
      finding.extra?.message?.toLowerCase().includes('input')) {
    baseScore = Math.min(10, baseScore + 0.5);
  }
  
  return Math.round(baseScore * 10) / 10;
};

const generateAttackVectorForOSV = (vuln, dep) => {
  const summary = (vuln.summary || '').toLowerCase();
  const details = (vuln.details || '').toLowerCase();
  const fullText = summary + ' ' + details;
  
  if (fullText.includes('xss')) {
    return `Attacker injects malicious JavaScript through user input that gets rendered by ${dep.name}, executing in victims' browsers`;
  }
  if (fullText.includes('injection') || fullText.includes('sql')) {
    return `Attacker sends crafted input to manipulate ${dep.name} queries, potentially reading or modifying database data`;
  }
  if (fullText.includes('prototype') || fullText.includes('pollution')) {
    return `Attacker sends specially crafted JSON payload to pollute JavaScript prototypes, potentially causing DoS or property injection`;
  }
  if (fullText.includes('directory') || fullText.includes('traversal')) {
    return `Attacker uses ../ sequences to read arbitrary files from the server through ${dep.name}`;
  }
  if (fullText.includes('dos') || fullText.includes('denial')) {
    return `Attacker sends malformed or oversized requests to crash the application via ${dep.name}`;
  }
  if (fullText.includes('rce') || fullText.includes('remote code')) {
    return `Attacker exploits ${dep.name} to execute arbitrary code on the server, potentially gaining full control`;
  }
  
  return `Attacker exploits known vulnerability in ${dep.name} version ${dep.version} to compromise the application`;
};

const generateMitigationForOSV = (depName, vuln) => {
  const mitigations = [
    `Update ${depName} to the latest secure version using 'npm update ${depName}'`,
    'Run `npm audit fix` to automatically update vulnerable packages',
    'Review package.json and update all outdated dependencies',
    'Use Snyk, Dependabot, or npm audit for automated dependency scanning'
  ];
  
  if (vuln.database_specific?.fixed_versions) {
    mitigations.unshift(`Update to version ${vuln.database_specific.fixed_versions.join(' or ')} or higher`);
  }
  
  const summary = (vuln.summary || '').toLowerCase();
  if (summary.includes('xss')) {
    mitigations.push('Implement Content Security Policy (CSP) headers', 'Sanitize all user input before rendering');
  }
  if (summary.includes('prototype')) {
    mitigations.push('Use Object.freeze(Object.prototype) as defense in depth', 'Validate all JSON input against schema');
  }
  if (summary.includes('injection')) {
    mitigations.push('Use parameterized queries or ORM methods', 'Implement input validation with allowlist');
  }
  
  return mitigations;
};

const calculateOSVImpact = (severity, vuln) => {
  const summary = (vuln.summary || '').toLowerCase();
  const details = (vuln.details || '').toLowerCase();
  const fullText = summary + ' ' + details;
  
  if (fullText.includes('rce') || fullText.includes('remote code') || fullText.includes('command')) {
    return { confidentiality: 'HIGH', integrity: 'HIGH', availability: 'HIGH' };
  }
  if (fullText.includes('sql') || fullText.includes('injection')) {
    return { confidentiality: 'HIGH', integrity: 'HIGH', availability: 'MEDIUM' };
  }
  if (fullText.includes('xss')) {
    return { confidentiality: 'HIGH', integrity: 'MEDIUM', availability: 'LOW' };
  }
  if (fullText.includes('prototype') || fullText.includes('pollution')) {
    return { confidentiality: 'MEDIUM', integrity: 'HIGH', availability: 'LOW' };
  }
  if (fullText.includes('dos') || fullText.includes('denial')) {
    return { confidentiality: 'LOW', integrity: 'LOW', availability: 'HIGH' };
  }
  if (fullText.includes('directory') || fullText.includes('traversal')) {
    return { confidentiality: 'HIGH', integrity: 'LOW', availability: 'LOW' };
  }
  
  switch(severity) {
    case 'critical': return { confidentiality: 'HIGH', integrity: 'HIGH', availability: 'HIGH' };
    case 'high': return { confidentiality: 'HIGH', integrity: 'HIGH', availability: 'MEDIUM' };
    case 'medium': return { confidentiality: 'MEDIUM', integrity: 'MEDIUM', availability: 'LOW' };
    default: return { confidentiality: 'LOW', integrity: 'LOW', availability: 'LOW' };
  }
};

const extractCWE = (vuln) => {
  if (vuln.database_specific?.cwe_ids && vuln.database_specific.cwe_ids.length > 0) {
    return `CWE-${vuln.database_specific.cwe_ids[0]}`;
  }
  if (vuln.id?.includes('CWE')) {
    const match = vuln.id.match(/CWE-(\d+)/i);
    if (match) return `CWE-${match[1]}`;
  }
  return 'CWE-937';
};

// ==================== SINGLE API CALL FOR EVERYTHING (WITH IMPROVED NAMING) ====================
const processWithSingleAPICall = async (systemInfo, semgrepFindings, osvFindings) => {
  const totalFindings = semgrepFindings.length + osvFindings.length;
  
  if (totalFindings === 0) {
    return {
      enhancedSemgrep: semgrepFindings,
      enhancedOSV: osvFindings,
      insight: generateFallbackInsight(semgrepFindings, osvFindings, systemInfo),
      riskScore: calculateAggregatedRiskScore(semgrepFindings, osvFindings)
    };
  }
  
  const GEMINI_API_KEY = process.env.VITE_GEMINI_API_KEY_ThreatModel;
  
  if (!GEMINI_API_KEY) {
    console.warn('⚠️ Gemini API key not configured - using fallback');
    return {
      enhancedSemgrep: semgrepFindings,
      enhancedOSV: osvFindings,
      insight: generateFallbackInsight(semgrepFindings, osvFindings, systemInfo),
      riskScore: calculateAggregatedRiskScore(semgrepFindings, osvFindings)
    };
  }
  
  try {
    console.log(`🤖 Making SINGLE API call to process ${totalFindings} findings with improved naming...`);
    
    const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
    
    // Create detailed summaries for ALL findings
    const semgrepSummary = semgrepFindings.map((f, idx) => ({
      type: 'code_vulnerability',
      index: idx,
      rule: f.check_id?.split('.').pop() || 'unknown',
      message: (f.extra?.message || '').substring(0, 150),
      file: f.path ? path.basename(f.path) : 'unknown',
      severity: f.extra?.severity || 'INFO',
      riskScore: f.riskScore,
      context: f.extra?.lines ? 'Has code snippet' : 'No code snippet'
    }));
    
    const osvSummary = osvFindings.map((v, idx) => ({
      type: 'dependency_vulnerability',
      index: idx,
      package: v.component,
      severity: v.severity,
      riskScore: v.riskScore,
      title: (v.title || '').substring(0, 100),
      ecosystem: 'npm'
    }));
    
    const allSummaries = [...semgrepSummary, ...osvSummary];
    
    const prompt = `You are a senior cybersecurity expert. Analyze these ${totalFindings} security findings and provide TWO things:

PART 1: For EACH finding, provide a DESCRIPTIVE SHORT NAME (5-8 words that accurately describe the vulnerability - be specific!)
Example good names:
- "Command Injection via Unsanitized User Input in exec()"
- "Prototype Pollution in Lodash Allows Object Manipulation" 
- "Cross-Site Scripting (XSS) in EJS Template Engine"
- "Remote Code Execution via express-fileupload Library"
- "Hardcoded JWT Secret in Authentication Middleware"
- "Missing CSRF Protection on Sensitive API Endpoints"
- "Insecure Cookie Configuration Missing HttpOnly Flag"

BAD names to avoid:
- "Vulnerability in lodash" (too generic)
- "ejs outdated" (not descriptive)
- "Security Issue" (too vague)

For each finding also provide:
- detailedDescription: 2-3 sentences
- attackVector: 1-2 sentences  
- mitigationSteps: 4-6 specific steps
- secureCodeExample: code showing the fix
- testingRecommendation: 1 sentence

PART 2: Overall security analysis with recommendations

Findings (${totalFindings} total):
${JSON.stringify(allSummaries, null, 2)}

Application: ${systemInfo.appName || 'Unknown'} (${systemInfo.appType || 'Unknown'})

Return ONLY valid JSON in this exact format:
{
  "enhancements": [
    {
      "shortName": "Command Injection via Unsanitized User Input in exec()",
      "detailedDescription": "The application passes user-controlled input directly to the exec() function without sanitization...",
      "attackVector": "Attacker injects command separators like ; or && to execute arbitrary system commands...",
      "mitigationSteps": ["Use execFile() instead of exec()", "Validate and sanitize all user input", "Use path.resolve() to normalize paths", "Implement allowlist for allowed commands"],
      "secureCodeExample": "const { execFile } = require('child_process');\\nexecFile('ls', ['-la', sanitizedPath]);",
      "testingRecommendation": "Test with payloads containing ;, &&, || and command injection tools like Commix"
    }
  ],
  "analysis": {
    "insight": "The application has critical vulnerabilities including command injection and prototype pollution...",
    "riskScore": 85
  }
}

Return ONLY valid JSON, no other text.`;

    const result = await model.generateContent(prompt);
    const response = await result.response;
    const aiText = response.text();
    
    const sanitizedJson = sanitizeJSONString(aiText);
    const jsonMatch = sanitizedJson.match(/\{[\s\S]*\}/);
    
    if (!jsonMatch) {
      console.warn('No valid JSON found in AI response');
      return {
        enhancedSemgrep: semgrepFindings,
        enhancedOSV: osvFindings,
        insight: generateFallbackInsight(semgrepFindings, osvFindings, systemInfo),
        riskScore: calculateAggregatedRiskScore(semgrepFindings, osvFindings)
      };
    }
    
    let parsed;
    try {
      parsed = JSON.parse(jsonMatch[0]);
    } catch (parseError) {
      console.warn('Failed to parse AI response:', parseError.message);
      return {
        enhancedSemgrep: semgrepFindings,
        enhancedOSV: osvFindings,
        insight: generateFallbackInsight(semgrepFindings, osvFindings, systemInfo),
        riskScore: calculateAggregatedRiskScore(semgrepFindings, osvFindings)
      };
    }
    
    const enhancements = parsed.enhancements || [];
    const analysis = parsed.analysis || {};
    
    // Apply enhancements to Semgrep findings
    const enhancedSemgrep = semgrepFindings.map((finding, idx) => {
      const enhancement = enhancements[idx];
      if (enhancement && typeof enhancement === 'object' && enhancement.shortName) {
        return {
          ...finding,
          enhanced: {
            shortName: enhancement.shortName,
            detailedDescription: enhancement.detailedDescription || finding.extra?.message || 'Security vulnerability detected',
            attackVector: enhancement.attackVector || 'Exploitation through vulnerable code pattern',
            mitigationSteps: Array.isArray(enhancement.mitigationSteps) ? enhancement.mitigationSteps : ['Review and fix the vulnerable code', 'Implement proper input validation'],
            secureCodeExample: enhancement.secureCodeExample || '// Implement proper security controls for this vulnerability',
            testingRecommendation: enhancement.testingRecommendation || 'Manual code review and security testing',
            affectedAssets: getRandomAffectedAssets(finding.check_id, 'Semgrep')
          }
        };
      } else if (enhancement && typeof enhancement === 'object') {
        // Fallback for generic names
        return {
          ...finding,
          enhanced: {
            shortName: `${finding.check_id?.split('.').pop() || 'Security'} Vulnerability in ${path.basename(finding.path || 'unknown')}`,
            detailedDescription: enhancement.detailedDescription || finding.extra?.message || 'Security vulnerability detected',
            attackVector: enhancement.attackVector || 'Exploitation through vulnerable code pattern',
            mitigationSteps: Array.isArray(enhancement.mitigationSteps) ? enhancement.mitigationSteps : ['Review and fix the vulnerable code', 'Implement proper input validation'],
            secureCodeExample: enhancement.secureCodeExample || '// Implement proper security controls',
            testingRecommendation: enhancement.testingRecommendation || 'Manual code review',
            affectedAssets: getRandomAffectedAssets(finding.check_id, 'Semgrep')
          }
        };
      }
      return finding;
    });
    
    // Apply enhancements to OSV findings
    const enhancedOSV = osvFindings.map((vuln, idx) => {
      const enhancement = enhancements[semgrepFindings.length + idx];
      if (enhancement && typeof enhancement === 'object' && enhancement.shortName) {
        return {
          ...vuln,
          enhanced: {
            shortName: enhancement.shortName,
            detailedDescription: enhancement.detailedDescription || vuln.description,
            attackVector: enhancement.attackVector || vuln.attackVector,
            mitigationSteps: Array.isArray(enhancement.mitigationSteps) ? enhancement.mitigationSteps : vuln.mitigation,
            testingRecommendation: enhancement.testingRecommendation || vuln.testing,
            secureCodeExample: enhancement.secureCodeExample || vuln.codeExample?.secure
          }
        };
      } else if (enhancement && typeof enhancement === 'object') {
        const packageName = vuln.component?.split('@')[0] || 'dependency';
        return {
          ...vuln,
          enhanced: {
            shortName: `${vuln.severity?.toUpperCase() || 'Security'} Vulnerability in ${packageName} - ${vuln.title?.substring(0, 40) || 'Update Required'}`,
            detailedDescription: enhancement.detailedDescription || vuln.description,
            attackVector: enhancement.attackVector || vuln.attackVector,
            mitigationSteps: Array.isArray(enhancement.mitigationSteps) ? enhancement.mitigationSteps : vuln.mitigation,
            testingRecommendation: enhancement.testingRecommendation || vuln.testing,
            secureCodeExample: enhancement.secureCodeExample || vuln.codeExample?.secure
          }
        };
      }
      return vuln;
    });
    
    const enhancedCount = enhancedSemgrep.filter(f => f.enhanced).length + enhancedOSV.filter(v => v.enhanced).length;
    console.log(`✅ Single API call enhanced ${enhancedCount}/${totalFindings} findings with descriptive names!`);
    
    return {
      enhancedSemgrep,
      enhancedOSV,
      insight: analysis.insight || generateFallbackInsight(semgrepFindings, osvFindings, systemInfo),
      riskScore: analysis.riskScore || calculateAggregatedRiskScore(semgrepFindings, osvFindings)
    };
    
  } catch (error) {
    console.error('Single API call failed:', error);
    return {
      enhancedSemgrep: semgrepFindings,
      enhancedOSV: osvFindings,
      insight: generateFallbackInsight(semgrepFindings, osvFindings, systemInfo),
      riskScore: calculateAggregatedRiskScore(semgrepFindings, osvFindings)
    };
  }
};

const generateFallbackInsight = (semgrepFindings, osvVulnerabilities, systemInfo) => {
  const totalIssues = semgrepFindings.length + osvVulnerabilities.length;
  
  const criticalCount = [
    ...semgrepFindings.filter(f => f.extra?.severity === 'ERROR'),
    ...osvVulnerabilities.filter(v => v.severity === 'critical')
  ].length;
  
  const highCount = [
    ...semgrepFindings.filter(f => f.extra?.severity === 'WARNING'),
    ...osvVulnerabilities.filter(v => v.severity === 'high')
  ].length;
  
  let insight = `🔍 SECURITY SCAN SUMMARY: Found ${totalIssues} issues in ${systemInfo.appName}.\n\n`;
  
  if (semgrepFindings.length > 0) {
    insight += `📁 CODE ANALYSIS: ${semgrepFindings.length} code-level vulnerabilities.\n`;
  }
  
  if (osvVulnerabilities.length > 0) {
    insight += `📦 DEPENDENCY ANALYSIS: ${osvVulnerabilities.length} vulnerable dependencies.\n`;
  }
  
  insight += `\n🚨 CRITICAL: ${criticalCount} | ⚠️ HIGH: ${highCount}\n`;
  insight += `\nRECOMMENDATION: ${osvVulnerabilities.length > 0 ? 'Update dependencies first, ' : ''}${semgrepFindings.length > 0 ? 'then fix code issues.' : 'Implement security best practices.'}`;
  
  return insight;
};

const calculateAggregatedRiskScore = (semgrepFindings, osvVulnerabilities) => {
  let totalScore = 0;
  let count = 0;
  
  semgrepFindings.forEach(f => {
    if (f.riskScore) totalScore += f.riskScore;
    else if (f.extra?.severity === 'ERROR') totalScore += 8.5;
    else if (f.extra?.severity === 'WARNING') totalScore += 6.5;
    else totalScore += 4.5;
    count++;
  });
  
  osvVulnerabilities.forEach(v => {
    if (v.riskScore) totalScore += v.riskScore;
    else if (v.severity === 'critical') totalScore += 9.5;
    else if (v.severity === 'high') totalScore += 7.5;
    else if (v.severity === 'medium') totalScore += 5.5;
    else totalScore += 3.5;
    count++;
  });
  
  if (count === 0) return 30;
  
  const avgScore = totalScore / count;
  const criticalCount = semgrepFindings.filter(f => f.extra?.severity === 'ERROR').length + 
                        osvVulnerabilities.filter(v => v.severity === 'critical').length;
  const bonus = Math.min(20, criticalCount * 3);
  
  return Math.min(100, Math.round(avgScore * 10) + bonus);
};

// ==================== ENHANCED ANALYSIS ====================
const analyzeWithEnhancedAI = async (systemInfo, gitUrl) => {
  try {
    console.log('🔄 Starting enhanced AI analysis with Semgrep + OSV...');
    console.log('📌 Repository:', gitUrl);

    const semgrepData = await analyzeWithSemgrep(gitUrl);
    
    console.log('📋 Semgrep analysis completed');
    console.log('📦 Dependencies found:', semgrepData.dependencies.length);
    console.log('🔍 Semgrep findings:', semgrepData.findings.length);
    
    // Add risk scores to Semgrep findings
    const findingsWithRisk = semgrepData.findings.map(finding => ({
      ...finding,
      riskScore: calculateRealRiskScoreForSemgrep(finding)
    }));
    
    let osvResults = { vulnerabilities: [], summary: 'No dependencies to check' };
    if (semgrepData.dependencies.length > 0) {
      console.log('🔍 Checking OSV for', semgrepData.dependencies.length, 'dependencies...');
      try {
        osvResults = await checkOSVVulnerabilities(semgrepData.dependencies);
        console.log('📊 OSV Results:', osvResults.vulnerabilities.length, 'vulnerabilities found');
      } catch (osvError) {
        console.warn('OSV check failed:', osvError.message);
        osvResults = { 
          vulnerabilities: [], 
          summary: `OSV check failed: ${osvError.message}` 
        };
      }
    }
    
    // SINGLE API CALL for EVERYTHING (enhancements + analysis)
    const { enhancedSemgrep, enhancedOSV, insight, riskScore } = await processWithSingleAPICall(
      systemInfo,
      findingsWithRisk, 
      osvResults.vulnerabilities
    );
    
    const semgrepThreats = enhancedSemgrep.map((finding, index) => {
      const enhanced = finding.enhanced || {};
      
      const vulnerableCode = finding.extra?.lines 
        ? `// File: ${path.basename(finding.path)}\n// Line: ${finding.start?.line}\n${finding.extra.lines}`
        : `// Vulnerable code pattern detected in ${finding.path || 'unknown file'}\n// Vulnerability type: ${finding.check_id || 'security issue'}`;
      
      const secureCode = enhanced.secureCodeExample || 
        (finding.check_id?.includes('sql') 
          ? '// Use parameterized queries:\nconst query = "SELECT * FROM users WHERE id = ?";\ndb.query(query, [userId]);'
          : finding.check_id?.includes('xss')
            ? '// Sanitize user input:\nimport DOMPurify from "dompurify";\nconst safeHTML = DOMPurify.sanitize(userInput);'
            : finding.check_id?.includes('command')
              ? '// Use execFile instead of exec:\nconst { execFile } = require("child_process");\nexecFile("ls", ["-la", safePath]);'
              : '// Implement proper security controls');
      
      const testing = enhanced.testingRecommendation || 'Manual code review and security testing';
      const affectedAssets = enhanced.affectedAssets || getRandomAffectedAssets(finding.check_id, 'Semgrep');
      
      return {
        id: `semgrep-${Date.now()}-${index}-${Math.random().toString(36).substr(2, 5)}`,
        title: enhanced.shortName || (finding.extra?.message ? finding.extra.message.split('\n')[0].substring(0, 60) : 'Code Vulnerability'),
        severity: finding.extra?.severity === 'ERROR' ? 'critical' : 
                  finding.extra?.severity === 'WARNING' ? 'high' : 'medium',
        category: mapRuleToCategory(finding.check_id),
        riskScore: finding.riskScore || calculateRealRiskScoreForSemgrep(finding),
        stride: mapToSTRIDE(finding.check_id),
        cwe: finding.extra?.metadata?.cwe || 'CWE-000',
        component: finding.path || 'Unknown',
        description: enhanced.detailedDescription || finding.extra?.message || 'Code vulnerability detected',
        attackVector: enhanced.attackVector || 'Exploitation through vulnerable code pattern',
        impact: calculateImpact(finding.extra?.severity, finding.check_id),
        likelihood: finding.extra?.severity === 'ERROR' ? 'HIGH' : 'MEDIUM',
        affectedAssets: affectedAssets,
        mitigation: enhanced.mitigationSteps || ['Review and fix the vulnerable code', 'Implement proper input validation', 'Use secure coding practices'],
        codeExample: { vulnerable: vulnerableCode, secure: secureCode },
        testing: testing,
        references: generateReferences(finding.check_id, finding.extra?.metadata?.cwe),
        confirmed: true,
        source: 'Semgrep Code Analysis',
        file: finding.path,
        line: finding.start?.line
      };
    });
    
    const osvThreats = enhancedOSV.map((v, index) => {
      const enhanced = v.enhanced || {};
      return {
        ...v,
        id: v.id || `osv-${Date.now()}-${index}-${Math.random().toString(36).substr(2, 5)}`,
        title: enhanced.shortName || v.title,
        description: enhanced.detailedDescription || v.description,
        attackVector: enhanced.attackVector || v.attackVector,
        mitigation: enhanced.mitigationSteps || v.mitigation,
        testing: enhanced.testingRecommendation || v.testing,
        codeExample: {
          vulnerable: v.codeExample?.vulnerable || `// Using vulnerable version: ${v.component}`,
          secure: enhanced.secureCodeExample || v.codeExample?.secure || `// Update ${v.component?.split('@')[0]} to latest version`
        },
        source: 'OSV.dev API',
        confirmed: true,
        file: v.file || 'package.json',
        line: v.line || 'dependencies section'
      };
    });
    
    const allThreats = [...semgrepThreats, ...osvThreats];
    allThreats.sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));
    
    return {
      success: true,
      semgrepData: { ...semgrepData, threats: semgrepThreats },
      osvResults: { ...osvResults, threats: osvThreats },
      threats: allThreats,
      aiInsight: insight,
      riskScore: riskScore,
      summary: `Found ${allThreats.length} total issues (${semgrepThreats.length} code, ${osvThreats.length} dependency)`
    };
    
  } catch (error) {
    console.warn('⚠️ Enhanced analysis failed:', error.message);
    return {
      success: false,
      error: error.message,
      threats: [],
      aiInsight: `Analysis failed: ${error.message}`,
      riskScore: 50,
      summary: 'Analysis failed'
    };
  }
};

// ==================== HELPER FUNCTIONS ====================
const mapRuleToCategory = (ruleId) => {
  const ruleStr = ruleId?.toLowerCase() || '';
  if (ruleStr.includes('sql') || ruleStr.includes('inject') || ruleStr.includes('xss') || ruleStr.includes('command')) return 'A03: Injection';
  if (ruleStr.includes('jwt') || ruleStr.includes('auth') || ruleStr.includes('password') || ruleStr.includes('session')) return 'A07: Auth Failures';
  if (ruleStr.includes('crypto') || ruleStr.includes('encrypt') || ruleStr.includes('secret') || ruleStr.includes('key')) return 'A02: Cryptographic Failures';
  if (ruleStr.includes('path') || ruleStr.includes('traversal') || ruleStr.includes('file')) return 'A01: Broken Access Control';
  if (ruleStr.includes('prototype') || ruleStr.includes('pollution')) return 'A08: Data Integrity Failures';
  if (ruleStr.includes('docker') || ruleStr.includes('container')) return 'A05: Security Misconfiguration';
  return 'A03: Injection';
};

const mapToSTRIDE = (ruleId) => {
  const ruleStr = ruleId?.toLowerCase() || '';
  if (ruleStr.includes('sql') || ruleStr.includes('command') || ruleStr.includes('exec')) return 'Tampering';
  if (ruleStr.includes('xss')) return 'Spoofing';
  if (ruleStr.includes('jwt') || ruleStr.includes('auth')) return 'Elevation of Privilege';
  if (ruleStr.includes('path') || ruleStr.includes('file')) return 'Information Disclosure';
  if (ruleStr.includes('prototype')) return 'Tampering';
  if (ruleStr.includes('docker') || ruleStr.includes('container')) return 'Elevation of Privilege';
  return 'Tampering';
};

const calculateImpact = (severity, ruleId) => {
  const ruleStr = ruleId?.toLowerCase() || '';
  
  if (ruleStr.includes('sql') || ruleStr.includes('command') || ruleStr.includes('exec')) {
    return { confidentiality: 'HIGH', integrity: 'HIGH', availability: 'MEDIUM' };
  }
  if (ruleStr.includes('xss')) {
    return { confidentiality: 'HIGH', integrity: 'MEDIUM', availability: 'LOW' };
  }
  if (ruleStr.includes('jwt') || ruleStr.includes('auth')) {
    return { confidentiality: 'HIGH', integrity: 'HIGH', availability: 'MEDIUM' };
  }
  if (ruleStr.includes('path') || ruleStr.includes('file')) {
    return { confidentiality: 'HIGH', integrity: 'LOW', availability: 'LOW' };
  }
  if (ruleStr.includes('docker') || ruleStr.includes('container')) {
    return { confidentiality: 'HIGH', integrity: 'HIGH', availability: 'HIGH' };
  }
  
  if (severity === 'ERROR') {
    return { confidentiality: 'HIGH', integrity: 'HIGH', availability: 'MEDIUM' };
  } else if (severity === 'WARNING') {
    return { confidentiality: 'MEDIUM', integrity: 'MEDIUM', availability: 'LOW' };
  }
  return { confidentiality: 'MEDIUM', integrity: 'LOW', availability: 'LOW' };
};

const generateReferences = (ruleId, cwe) => {
  const refs = ['https://owasp.org'];
  if (cwe && typeof cwe === 'string' && cwe !== 'CWE-000') {
    const cweNumber = cwe.replace('CWE-', '');
    refs.push(`https://cwe.mitre.org/data/definitions/${cweNumber}.html`);
  }
  return refs;
};

// ==================== API ENDPOINTS ====================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/api/analyze-enhanced', async (req, res) => {
  try {
    const { systemInfo, gitUrl } = req.body;
    
    if (!gitUrl) {
      return res.status(400).json({ error: 'Git URL is required' });
    }
    
    console.log('📥 Received enhanced analysis request for:', gitUrl);
    
    const result = await analyzeWithEnhancedAI(systemInfo, gitUrl);
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(500).json({ error: result.error });
    }
  } catch (error) {
    console.error('Analysis endpoint error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/analyze-basic', async (req, res) => {
  try {
    const { systemInfo } = req.body;
    
    const GEMINI_API_KEY = process.env.VITE_GEMINI_API_KEY_ThreatModel;
    
    if (!GEMINI_API_KEY) {
      const staticAnalysis = generateStaticThreats(systemInfo);
      return res.json(staticAnalysis);
    }
    
    const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
    
    const prompt = `You are a senior cybersecurity expert. Analyze this application for security threats.

APPLICATION DETAILS:
- Name: ${systemInfo.appName || 'Unknown'}
- Type: ${systemInfo.appType || 'Unknown'}
- Description: ${systemInfo.description || 'Not specified'}
- Frontend: ${systemInfo.frontend?.join(', ') || 'Not specified'}
- Backend: ${systemInfo.backend?.join(', ') || 'Not specified'}
- Database: ${systemInfo.database?.join(', ') || 'Not specified'}
- Authentication: ${systemInfo.authentication?.join(', ') || 'Not specified'}
- User Input Areas: ${systemInfo.userInputs?.join(', ') || 'Various forms'}
- Sensitive Data: ${systemInfo.sensitiveData?.join(', ') || 'None specified'}

Provide a JSON response with:
1. "threats": Array of security threats with descriptive names (5-8 words each)
2. "insight": Overall analysis
3. "riskScore": 0-100

Format: {"threats":[{"title":"SQL Injection via Unsanitized User Input in Database Queries","severity":"critical","category":"A03: Injection","riskScore":9.0,"stride":"Tampering","cwe":"CWE-89","component":"Database","description":"...","attackVector":"...","impact":{"confidentiality":"HIGH","integrity":"HIGH","availability":"MEDIUM"},"likelihood":"HIGH","affectedAssets":["Database"],"mitigation":["Step1"],"codeExample":{"vulnerable":"bad","secure":"good"},"testing":"test","references":["url"]}],"insight":"summary","riskScore":75}`;

    const result = await model.generateContent(prompt);
    const response = await result.response;
    const aiText = response.text();
    
    const sanitizedJson = sanitizeJSONString(aiText);
    const jsonMatch = sanitizedJson.match(/\{[\s\S]*\}/);
    
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      if (parsed.threats) {
        return res.json(parsed);
      }
    }
    
    const staticAnalysis = generateStaticThreats(systemInfo);
    res.json(staticAnalysis);
  } catch (error) {
    console.error('Basic analysis error:', error);
    const staticAnalysis = generateStaticThreats(systemInfo);
    res.json(staticAnalysis);
  }
});

app.post('/api/chat', async (req, res) => {
  try {
    const { message, systemInfo, threats } = req.body;
    
    const GEMINI_API_KEY = process.env.VITE_GEMINI_API_KEY_ThreatModel;
    
    if (!GEMINI_API_KEY) {
      return res.json({ response: getStaticChatResponse(message) });
    }
    
    const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
    
    const criticalThreats = (threats || []).filter(t => t.severity === 'critical').slice(0, 3);
    
    const prompt = `You are a security assistant for "${systemInfo?.appName || 'the application'}". 

The scan found ${threats?.length || 0} issues including:
${criticalThreats.map(t => `- ${t.title}`).join('\n')}

User Question: ${message}

Provide a helpful, specific response.`;

    const result = await model.generateContent(prompt);
    const response = await result.response;
    const rawText = response.text();
    
    const cleanText = rawText.replace(/\*\*/g, '').replace(/\*/g, '').replace(/`/g, '');
    
    res.json({ response: cleanText });
  } catch (error) {
    console.error('Chat error:', error);
    res.json({ response: getStaticChatResponse(req.body.message || '') });
  }
});

const generateStaticThreats = (systemInfo) => {
  const threats = [];
  
  if (systemInfo.database?.some(db => ['MySQL', 'PostgreSQL', 'SQLite', 'Oracle'].includes(db)) && 
      systemInfo.userInputs?.length > 0) {
    threats.push({
      id: 'static-1',
      title: 'SQL Injection via Unsanitized User Input in Database Queries',
      severity: 'critical',
      category: 'A03: Injection',
      riskScore: 9.2,
      stride: 'Tampering',
      cwe: 'CWE-89',
      component: `${systemInfo.backend?.[0] || 'API'} - Database Queries`,
      description: 'User inputs may be concatenated into SQL queries without proper sanitization.',
      attackVector: 'Attacker injects malicious SQL through input fields.',
      impact: { confidentiality: 'HIGH', integrity: 'HIGH', availability: 'MEDIUM' },
      likelihood: 'HIGH',
      affectedAssets: ['User Database', 'Application Data'],
      mitigation: ['Use parameterized queries', 'Implement input validation'],
      codeExample: {
        vulnerable: `const query = "SELECT * FROM users WHERE email = '" + userEmail + "'";`,
        secure: `const query = "SELECT * FROM users WHERE email = ?";\ndb.query(query, [userEmail]);`
      },
      testing: 'Use SQLMap or OWASP ZAP',
      references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
      confirmed: false,
      source: 'Static Analysis'
    });
  }

  const insight = `🔍 STATIC ANALYSIS: Identified ${threats.length} potential security threats.`;
  const riskScore = threats.length > 0 ? 75 : 30;

  return { threats, insight, riskScore };
};

const getStaticChatResponse = (message) => {
  const lowerMessage = message.toLowerCase();
  if (lowerMessage.includes('xss')) {
    return "For XSS protection: 1) Implement CSP, 2) Sanitize all user inputs, 3) Use HTTPOnly cookies.";
  }
  if (lowerMessage.includes('sql') || lowerMessage.includes('injection')) {
    return "To prevent SQL injection: 1) Use parameterized queries, 2) Implement input validation.";
  }
  if (lowerMessage.includes('auth') || lowerMessage.includes('login')) {
    return "For secure authentication: 1) Implement MFA, 2) Use strong password policies, 3) Secure session management.";
  }
  return "Please check the threat report above for detailed security analysis and recommendations.";
};

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📝 API endpoints:`);
  console.log(`   - POST /api/analyze-enhanced`);
  console.log(`   - POST /api/analyze-basic`);
  console.log(`   - POST /api/chat`);
  console.log(`   - GET  /api/health`);
});