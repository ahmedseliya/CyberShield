import React, { useState, useEffect } from 'react';
import { Shield, Brain, AlertTriangle, CheckCircle, XCircle, Download, Loader, Send, Zap, Target, Lock, Database, Cloud, Code, FileText, BarChart3, TrendingUp, MessageSquare, Search, Filter, ChevronDown, ChevronRight, ExternalLink, Copy, Check, GitBranch, Package, AlertOctagon, FileCode } from 'lucide-react';
import { GoogleGenerativeAI } from '@google/generative-ai';

const GEMINI_API_KEY = import.meta.env.VITE_GEMINI_API_KEY_ThreatModel;
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
const CLOUDFLARE_PROXY_URL = import.meta.env.VITE_CLOUDFLARE_PROXY_URL;

const analyzeWithEnhancedAI = async (systemInfo, gitUrl) => {
  try {
    console.log('🔄 Starting enhanced AI analysis with Repomix + OSV...');
    console.log('📌 Repository:', gitUrl);

    const repoData = await getRepomixDigest(gitUrl);
    
    console.log('📋 Repomix analysis completed');
    console.log('📦 Dependencies found:', repoData.dependencies.length);
    console.log('📁 Files analyzed:', repoData.fileCount);
    console.log('📄 Total code size:', repoData.rawText.length, 'characters');
    
    const hasUsefulData = repoData.dependencies.length > 0 || 
                         repoData.fileCount > 0;
    
    if (!hasUsefulData) {
      console.warn('⚠️ Repomix returned limited data.');
    }
    
    let osvResults = { vulnerabilities: [], summary: 'No dependencies to check' };
    if (repoData.dependencies.length > 0) {
      console.log('🔍 Checking OSV for', repoData.dependencies.length, 'dependencies...');
      try {
        osvResults = await checkOSVVulnerabilities(repoData.dependencies);
        console.log('📊 OSV Results:', osvResults.vulnerabilities.length, 'vulnerabilities found');
      } catch (osvError) {
        console.warn('OSV check failed:', osvError.message);
        osvResults = { 
          vulnerabilities: [], 
          summary: `OSV check failed: ${osvError.message}` 
        };
      }
    } else {
      console.log('⏭️ Skipping OSV check - no dependencies found');
    }
    
    console.log('🤖 Generating enhanced AI analysis...');
    const enhancedResponse = await callEnhancedGeminiAPI(systemInfo, repoData, osvResults);
    
    console.log('✅ Enhanced AI analysis successful');
    return enhancedResponse;
    
  } catch (error) {
    console.warn('⚠️ Enhanced analysis failed, falling back to basic AI:', error.message);
    console.error('Full error:', error);
    
    const basicResponse = await analyzeWithAI(systemInfo);
    
    return {
      ...basicResponse,
      realityCheck: `Enhanced analysis failed: ${error.message}. Using basic AI analysis instead.`,
      analysisSummary: {
        confirmedVulns: 0,
        predictedVulns: basicResponse.threats.length,
        techRealityMatch: false,
        keyFindings: ['Enhanced analysis failed']
      }
    };
  }
};

const getRepomixDigest = async (gitUrl) => {
  try {
    console.log('🔍 Fetching repository via Repomix Bridge:', gitUrl);
    
    // Updated: Use your Cloudflare Worker as proxy to your Repomix Bridge
    const proxyUrl = `${CLOUDFLARE_PROXY_URL}`; // This should point to your Cloudflare Worker
    
    console.log('🔍 Using proxy URL:', proxyUrl);
    
    const requestBody = {
      url: gitUrl.trim(),
      format: 'text',
      include: 'code',
      excludePatterns: ['node_modules', 'dist', 'build', '.git', 'coverage', '*.log', '*.lock'],
      maxSize: 500000,
    };
    
    console.log('📤 Sending request to Repomix Bridge...');
    
    const response = await fetch(proxyUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody)
    });
    
    console.log('📥 Response status:', response.status);
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error('❌ Repomix Bridge error:', errorText);
      throw new Error(`Repomix Bridge error: ${response.status}`);
    }
    
    const result = await response.json();
    
    if (!result.success) {
      throw new Error(result.error || 'Repomix analysis failed');
    }
    
    console.log('✅ Repomix Bridge response received');
    console.log('📊 Files analyzed:', result.fileCount);
    console.log('📦 Dependencies found:', result.dependencies ? result.dependencies.length : 0);
    console.log('📄 Code size:', result.rawText ? result.rawText.length : 0, 'characters');
    
    // Extract files from raw text if fileStructure is not provided
    const fileStructure = extractFilesFromRepomix(result.rawText || '');
    
    // Generate a summary if not provided
    const summary = generateSummaryFromCode(result.rawText || '', result.fileCount || 0);
    
    return {
      rawText: result.rawText || '',
      dependencies: result.dependencies || [],
      fileStructure: fileStructure,
      fileCount: result.fileCount || 0,
      summary: summary
    };
    
  } catch (error) {
    console.error('❌ Repomix Bridge failed:', error);
    
    // Fallback: Try the old method as backup
    console.log('🔄 Trying fallback analysis...');
    try {
      const fallbackUrl = `https://repomix.com/api/analyze?url=${encodeURIComponent(gitUrl)}&format=text`;
      const fallbackResponse = await fetch(fallbackUrl);
      
      if (fallbackResponse.ok) {
        const rawText = await fallbackResponse.text();
        const dependencies = parseDependenciesFromCode(rawText);
        const fileCount = rawText.match(/Analyzed (\d+) files?/i)?.[1] || 0;
        const fileStructure = extractFilesFromRepomix(rawText);
        const summary = generateSummaryFromCode(rawText, fileCount);
        
        return {
          rawText,
          dependencies,
          fileStructure,
          fileCount: parseInt(fileCount),
          summary
        };
      }
    } catch (fallbackError) {
      console.warn('Fallback also failed:', fallbackError.message);
    }
    
    return {
      rawText: `Repomix analysis failed: ${error.message}`,
      dependencies: [],
      fileStructure: [],
      fileCount: 0,
      summary: 'Repository analysis failed - using limited data'
    };
  }
};

const extractFilesFromRepomix = (rawText) => {
  if (!rawText) return [];
  
  const files = [];
  const lines = rawText.split('\n');
  
  for (const line of lines) {
    const fileMatch = line.match(/File:\s*(.+)/i);
    if (fileMatch) {
      const fileName = fileMatch[1].trim();
      if (fileName && !fileName.includes('node_modules') && !fileName.includes('.git/')) {
        files.push(fileName);
      }
    }
  }
  
  return files;
};

const filterSecurityCriticalFiles = (rawText) => {
  console.log('🔍 Filtering security-critical files...');
  
  const lines = rawText.split('\n');
  let filteredLines = [];
  let currentFile = null;
  let isSecurityCritical = false;
  let securityFilesCount = 0;
  
  const SECURITY_FILE_PATTERNS = [
    /package\.json/i,
    /requirements\.txt/i,
    /composer\.json/i,
    /pom\.xml/i,
    /build\.gradle/i,
    /\.env/i,
    /config\./i,
    /security\./i,
    /auth/i,
    /middleware/i,
    /routes?\./i,
    /controllers?\./i,
    /api\./i,
    /server\./i,
    /app\./i,
    /main\./i,
    /index\./i,
    /dockerfile/i,
    /\.config\.js/i,
    /webpack\.config/i,
    /\.eslintrc/i,
    /\.prettierrc/i
  ];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    // Check if this is a file header (Repomix format)
    if (line.startsWith('File: ') || line.includes('────────────────')) {
      const fileMatch = line.match(/File:\s*(.+)/i);
      if (fileMatch) {
        const fileName = fileMatch[1].trim();
        isSecurityCritical = SECURITY_FILE_PATTERNS.some(pattern => pattern.test(fileName));
        currentFile = fileName;
        
        if (isSecurityCritical) {
          securityFilesCount++;
          filteredLines.push(line);
        }
      } else if (line.includes('────────────────') && currentFile && isSecurityCritical) {
        filteredLines.push(line);
      }
    } else if (currentFile && isSecurityCritical) {
      // Keep lines from security-critical files
      filteredLines.push(line);
    }
    
    // Stop if we have enough security files
    if (securityFilesCount > 50 && filteredLines.length > 10000) {
      console.log('📦 Collected', securityFilesCount, 'security-critical files, stopping...');
      filteredLines.push('\n\n... (additional files truncated for security analysis)');
      break;
    }
  }
  
  console.log('✅ Filtered to', securityFilesCount, 'security-critical files');
  return filteredLines.join('\n');
};

const parseDependenciesFromCode = (rawText) => {
  const dependencies = [];
  
  console.log('🔍 Extracting dependencies from full code...');
  
  // Try to find package.json content
  const packageJsonMatch = rawText.match(/File: .*package\.json[\s\S]*?```json\s*([\s\S]*?)```/i);
  if (packageJsonMatch) {
    try {
      console.log('📦 Found package.json, parsing...');
      const jsonStr = packageJsonMatch[1].trim();
      const packageJson = JSON.parse(jsonStr);
      
      if (packageJson.dependencies) {
        Object.entries(packageJson.dependencies).forEach(([name, version]) => {
          dependencies.push({
            ecosystem: 'npm',
            name,
            version: version.replace(/^\^|~/, ''),
            source: 'package.json',
            confirmed: true
          });
        });
      }
      
      if (packageJson.devDependencies) {
        Object.entries(packageJson.devDependencies).forEach(([name, version]) => {
          dependencies.push({
            ecosystem: 'npm',
            name,
            version: version.replace(/^\^|~/, ''),
            source: 'package.json (dev)',
            confirmed: true
          });
        });
      }
    } catch (e) {
      console.warn('Could not parse package.json:', e.message);
    }
  }
  
  // Try to find requirements.txt
  const requirementsMatch = rawText.match(/File: .*requirements\.txt[\s\S]*?```txt\s*([\s\S]*?)```/i);
  if (requirementsMatch) {
    console.log('🐍 Found requirements.txt');
    const requirementsContent = requirementsMatch[1];
    const lines = requirementsContent.split('\n');
    
    lines.forEach((line) => {
      const cleanLine = line.trim();
      if (cleanLine && !cleanLine.startsWith('#')) {
        const match = cleanLine.match(/^([a-zA-Z0-9-_\[\]]+)([=<>!~]=?)?([0-9a-zA-Z.-]*)/);
        if (match && match[1]) {
          dependencies.push({
            ecosystem: 'PyPI',
            name: match[1],
            version: match[3] || 'unknown',
            source: 'requirements.txt',
            confirmed: true
          });
        }
      }
    });
  }
  
  // Try to find composer.json
  const composerMatch = rawText.match(/File: .*composer\.json[\s\S]*?```json\s*([\s\S]*?)```/i);
  if (composerMatch) {
    try {
      console.log('🎵 Found composer.json');
      const composerJson = JSON.parse(composerMatch[1].trim());
      
      if (composerJson.require) {
        Object.entries(composerJson.require).forEach(([name, version]) => {
          dependencies.push({
            ecosystem: 'Packagist',
            name,
            version: version.replace(/^\^|~/, ''),
            source: 'composer.json',
            confirmed: true
          });
        });
      }
    } catch (e) {
      console.warn('Could not parse composer.json:', e.message);
    }
  }
  
  // Try to find pom.xml
  const pomMatch = rawText.match(/File: .*pom\.xml[\s\S]*?```xml\s*([\s\S]*?)```/i);
  if (pomMatch) {
    console.log('☕ Found pom.xml');
    const pomContent = pomMatch[1];
    
    const depRegex = /<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>/g;
    let depMatch;
    
    while ((depMatch = depRegex.exec(pomContent)) !== null) {
      dependencies.push({
        ecosystem: 'Maven',
        name: `${depMatch[1]}:${depMatch[2]}`,
        version: 'unknown',
        source: 'pom.xml',
        confirmed: true
      });
    }
  }
  
  // Scan for other dependency patterns in code
  if (dependencies.length === 0) {
    console.log('🔍 Scanning code for import/require patterns...');
    
    // Look for npm imports
    const importRegex = /(?:import|require)\(?['"]([@\w\-\/]+)['"]\)?/g;
    let importMatch;
    while ((importMatch = importRegex.exec(rawText)) !== null) {
      if (importMatch[1] && !importMatch[1].startsWith('.')) {
        dependencies.push({
          ecosystem: 'npm',
          name: importMatch[1],
          version: 'unknown',
          source: 'code pattern',
          confirmed: false
        });
      }
    }
  }
  
  console.log(`🔍 Total dependencies found: ${dependencies.length}`);
  
  // Remove duplicates
  const uniqueDeps = [];
  const seen = new Set();
  
  dependencies.forEach(dep => {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueDeps.push(dep);
    }
  });
  
  return uniqueDeps;
};

const generateSummaryFromCode = (rawText, fileCount) => {
  // Analyze code to generate intelligent summary
  const hasReact = rawText.includes('import React') || rawText.includes('from "react"');
  const hasVue = rawText.includes('Vue.component') || rawText.includes('new Vue(');
  const hasAngular = rawText.includes('@angular') || rawText.includes('@Component');
  const hasExpress = rawText.includes('express()') || rawText.includes('require(\'express\')');
  const hasDjango = rawText.includes('django') || rawText.includes('from django');
  const hasFlask = rawText.includes('flask') || rawText.includes('Flask(');
  const hasSpring = rawText.includes('@SpringBootApplication') || rawText.includes('import org.springframework');
  const hasNode = rawText.includes('require(') || rawText.includes('module.exports');
  const hasPython = rawText.includes('def ') || rawText.includes('import ') && rawText.includes('.py');
  const hasJava = rawText.includes('public class') || rawText.includes('.java');
  
  let techStack = [];
  if (hasReact) techStack.push('React');
  if (hasVue) techStack.push('Vue.js');
  if (hasAngular) techStack.push('Angular');
  if (hasExpress) techStack.push('Express.js');
  if (hasDjango) techStack.push('Django');
  if (hasFlask) techStack.push('Flask');
  if (hasSpring) techStack.push('Spring Boot');
  if (hasNode) techStack.push('Node.js');
  if (hasPython) techStack.push('Python');
  if (hasJava) techStack.push('Java');
  
  const stack = techStack.length > 0 ? techStack.join(' + ') : 'Unknown technology stack';
  
  return `${stack} application with ${fileCount} files analyzed via Repomix`;
};

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
    
    const proxyUrl = `${CLOUDFLARE_PROXY_URL}?url=${encodeURIComponent('https://api.osv.dev/v1/querybatch')}`;
    
    const response = await fetch(proxyUrl, {
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
          vulnerabilities.push({
            id: vuln.id || `osv-${index}-${Date.now()}`,
            title: vuln.summary || `Vulnerability in ${dep.name}`,
            severity: determineSeverity(vuln),
            category: 'A06: Vulnerable Components',
            riskScore: 8.0,
            stride: 'Tampering',
            cwe: extractCWE(vuln),
            component: `${dep.name}@${dep.version}`,
            description: vuln.details || `Known vulnerability in ${dep.name} version ${dep.version}`,
            attackVector: 'Exploitation of known vulnerability in dependency',
            impact: { confidentiality: 'HIGH', integrity: 'HIGH', availability: 'MEDIUM' },
            likelihood: 'HIGH',
            affectedAssets: ['Application', 'User Data'],
            mitigation: [`Update ${dep.name} to a secure version`, 'Review dependency update process'],
            codeExample: {
              vulnerable: `// Using vulnerable version: ${dep.name}@${dep.version}`,
              secure: `// Update to secure version (check OSV for fixed versions)`
            },
            testing: 'Dependency vulnerability scanning',
            references: vuln.references?.map(ref => ref.url) || [],
            confirmed: true,
            source: 'OSV.dev API'
          });
        });
      }
    });
    
    return {
      vulnerabilities,
      summary: `Found ${vulnerabilities.length} confirmed vulnerabilities in ${dependencies.length} dependencies`
    };
    
  } catch (error) {
    console.error('OSV check failed:', error);
    return { vulnerabilities: [], summary: 'Dependency check failed' };
  }
};

const determineSeverity = (vuln) => {
  const summary = vuln.summary?.toLowerCase() || '';
  if (summary.includes('critical') || summary.includes('remote code execution')) return 'critical';
  if (summary.includes('high') || summary.includes('sql injection') || summary.includes('xss')) return 'high';
  if (summary.includes('medium') || summary.includes('information disclosure')) return 'medium';
  return 'low';
};

const extractCWE = (vuln) => {
  if (vuln.database_specific?.cwe_ids?.[0]) {
    return `CWE-${vuln.database_specific.cwe_ids[0]}`;
  }
  return 'CWE-000';
};

const callEnhancedGeminiAPI = async (systemInfo, repoData, osvResults) => {
  try {
    console.log('🤖 Calling enhanced Gemini API...');
    
    const prompt = createEnhancedAIPrompt(systemInfo, repoData, osvResults);
    
    console.log('📝 Prompt length:', prompt.length);
    
    const result = await model.generateContent(prompt);
    const response = await result.response;
    const aiText = response.text();
    
    console.log('📄 AI response received, parsing...');
    
    return parseEnhancedAIResponse(aiText, systemInfo, repoData, osvResults);
  } catch (error) {
    console.error('Enhanced Gemini API call failed:', error);
    throw error;
  }
};

const createEnhancedAIPrompt = (systemInfo, repoData, osvResults) => {
  let codeAnalysisContent = '';
  
  if (repoData.rawText && repoData.rawText.length > 100) {
    // Send up to 150,000 characters (safely under Gemini limits)
    codeAnalysisContent = repoData.rawText.substring(0, 150000);
  }
  
  // FIXED: Handle undefined repoData.summary
  const repoSummary = repoData.summary || `Repository analyzed: ${repoData.fileCount} files, ${repoData.dependencies.length} dependencies`;
  const summaryFirstLine = repoSummary.split ? repoSummary.split('\n')[0] || repoSummary : repoSummary;
  
  const repomixSection = repoData.dependencies.length > 0 || repoData.fileCount > 0
    ? `CODE ANALYSIS RESULTS (via Repomix - FULL CODE ANALYSIS):
- Repository Summary: ${repoSummary}
- Files Analyzed: ${repoData.fileCount} files${repoData.fileStructure && repoData.fileStructure.length > 0 ? ` (first 20): ${repoData.fileStructure.slice(0, 20).join(', ')}${repoData.fileStructure.length > 20 ? `... and ${repoData.fileStructure.length - 20} more` : ''}` : ''}
- Dependencies Found: ${repoData.dependencies.length > 0 ? repoData.dependencies.map(d => `${d.name}@${d.version}`).slice(0, 15).join(', ') + (repoData.dependencies.length > 15 ? `... and ${repoData.dependencies.length - 15} more` : '') : 'None detected'}
- Code Analysis: Full repository code analyzed (${repoData.rawText ? repoData.rawText.length : 0} characters)`
    : `CODE ANALYSIS RESULTS: Repository was analyzed but no significant code files were found.`;

  const osvSection = osvResults.vulnerabilities.length > 0
    ? `CONFIRMED VULNERABILITIES (from OSV.dev):
${osvResults.vulnerabilities.slice(0, 10).map(v => `- ${v.title} in ${v.component} (${v.severity})`).join('\n')}${osvResults.vulnerabilities.length > 10 ? `\n... and ${osvResults.vulnerabilities.length - 10} more confirmed vulnerabilities` : ''}`
    : 'CONFIRMED VULNERABILITIES (from OSV.dev): No confirmed vulnerabilities found in dependencies';

  return `
You are a senior cybersecurity expert analyzing a repository. Return ONLY valid JSON.

REPOSITORY: ${summaryFirstLine}

USER-PROVIDED APPLICATION INFO:
- Name: ${systemInfo.appName}
- Type: ${systemInfo.appType}
- Description: ${systemInfo.description || 'Not specified'}
- Frontend: ${systemInfo.frontend.join(', ') || 'Not specified'}
- Backend: ${systemInfo.backend.join(', ') || 'Not specified'}
- Database: ${systemInfo.database.join(', ') || 'Not specified'}

${repomixSection}

${osvSection}

FULL CODE ANALYSIS CONTENT (first 150K chars of ${repoData.rawText ? repoData.rawText.length : 0} total):
${codeAnalysisContent}

ANALYSIS INSTRUCTIONS:
1. Compare user tech stack with actual repository contents
2. If repository has different tech than user input, note this in "realityCheck"
3. Include all OSV vulnerabilities as CONFIRMED threats
4. Analyze the ACTUAL CODE for security vulnerabilities - look for:
   - Hardcoded secrets and API keys
   - SQL injection patterns
   - XSS vulnerabilities
   - Authentication/authorization flaws
   - Insecure configurations
   - Missing security headers
   - Business logic vulnerabilities
5. Reference specific files and line numbers when possible
6. Focus on REAL vulnerabilities in the provided code, not generic advice

RETURN THIS EXACT JSON FORMAT:
{
  "realityCheck": "Brief note about tech stack match/mismatch and code analysis quality",
  "threats": [
    {
      "id": 1,
      "title": "Specific vulnerability name",
      "severity": "critical/high/medium/low",
      "category": "OWASP category",
      "riskScore": 1-10,
      "stride": "STRIDE category",
      "cwe": "CWE-XXX or empty",
      "component": "Specific component/file",
      "description": "Detailed explanation with file references",
      "attackVector": "How attack happens",
      "impact": { "confidentiality": "HIGH/MEDIUM/LOW", "integrity": "HIGH/MEDIUM/LOW", "availability": "HIGH/MEDIUM/LOW" },
      "likelihood": "HIGH/MEDIUM/LOW",
      "affectedAssets": ["Asset1", "Asset2"],
      "mitigation": ["Step1", "Step2"],
      "codeExample": { "vulnerable": "Actual vulnerable code from repository", "secure": "Fixed code" },
      "testing": "Testing advice",
      "references": ["url1"],
      "confirmed": true/false,
      "source": "OSV.dev API / Code Analysis / AI Prediction"
    }
  ],
  "insight": "Overall analysis summary",
  "riskScore": 1-100,
  "analysisSummary": {
    "confirmedVulns": ${osvResults.vulnerabilities.length},
    "predictedVulns": 0,
    "techRealityMatch": true/false,
    "keyFindings": ["finding1", "finding2"]
  }
}
`;
};

const parseEnhancedAIResponse = (aiText, systemInfo, repoData, osvResults) => {
  try {
    console.log('🔍 Parsing enhanced AI response...');
    
    const jsonMatch = aiText.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      
      console.log('✅ Successfully parsed AI response');
      
      const allThreats = [];
      
      osvResults.vulnerabilities.forEach((vuln, index) => {
        allThreats.push({
          ...vuln,
          id: index + 1,
          confirmed: true,
          source: 'OSV.dev API (Confirmed)'
        });
      });
      
      if (parsed.threats && Array.isArray(parsed.threats)) {
        parsed.threats.forEach((threat, index) => {
          allThreats.push({
            ...threat,
            id: index + osvResults.vulnerabilities.length + 1,
            confirmed: threat.confirmed || false,
            source: threat.source || 'AI Prediction (Code Analysis)'
          });
        });
      }
      
      const validatedThreats = allThreats.map((threat, index) => ({
        id: threat.id || index + 1,
        title: threat.title || 'Security Vulnerability',
        severity: threat.severity || 'medium',
        category: threat.category || 'A03: Injection',
        riskScore: threat.riskScore || 7.0,
        stride: threat.stride || 'Tampering',
        cwe: threat.cwe || 'CWE-000',
        component: threat.component || `${systemInfo.backend[0] || 'Unknown'} Component`,
        description: threat.description || 'Security vulnerability identified',
        attackVector: threat.attackVector || 'Attack vector not specified',
        impact: threat.impact || { confidentiality: 'MEDIUM', integrity: 'MEDIUM', availability: 'LOW' },
        likelihood: threat.likelihood || 'MEDIUM',
        affectedAssets: threat.affectedAssets || ['Application Data'],
        mitigation: threat.mitigation || ['Implement security controls'],
        codeExample: threat.codeExample || {
          vulnerable: '// Vulnerable code',
          secure: '// Secure code'
        },
        testing: threat.testing || 'Security testing required',
        references: threat.references || ['https://owasp.org'],
        confirmed: threat.confirmed || false,
        source: threat.source || 'Analysis'
      }));
      
      console.log(`📊 Total threats after validation: ${validatedThreats.length}`);
      
      return {
        threats: validatedThreats,
        insight: (parsed.insight || 'Enhanced security analysis completed')
          .replace(/\*\*/g, '')
          .replace(/\*/g, ''),
        riskScore: parsed.riskScore || calculateRiskScore(validatedThreats),
        realityCheck: parsed.realityCheck || '',
        analysisSummary: parsed.analysisSummary || {
          confirmedVulns: osvResults.vulnerabilities.length,
          predictedVulns: validatedThreats.length - osvResults.vulnerabilities.length,
          techRealityMatch: !parsed.realityCheck || !parsed.realityCheck.includes('mismatch'),
          keyFindings: []
        }
      };
    }
    throw new Error('Invalid JSON format from AI');
  } catch (error) {
    console.error('Failed to parse enhanced AI response:', error);
    console.log('📄 Raw AI response:', aiText.substring(0, 500) + '...');
    throw new Error('Enhanced AI response parsing failed');
  }
};

const analyzeWithAI = async (systemInfo) => {
  try {
    console.log('🔄 Attempting Gemini AI analysis...');
    
    const geminiResponse = await callGeminiAPI(systemInfo);
    if (geminiResponse && geminiResponse.threats) {
      console.log('✅ Gemini AI analysis successful');
      return geminiResponse;
    }
    throw new Error('Gemini returned invalid response');
  } catch (error) {
    console.warn('⚠️ Gemini API failed, using static analysis:', error.message);
    return generateStaticThreats(systemInfo);
  }
};

const callGeminiAPI = async (systemInfo) => {
  try {
    const prompt = createAIPrompt(systemInfo);
    
    const result = await model.generateContent(prompt);
    const response = await result.response;
    const aiText = response.text();
    
    return parseAIResponse(aiText, systemInfo);
  } catch (error) {
    console.error('Gemini API call failed:', error);
    throw error;
  }
};

const createAIPrompt = (systemInfo) => {
  return `
You are a senior cybersecurity expert. Analyze this application for security threats and return ONLY valid JSON.

APPLICATION DETAILS:
- Frontend: ${systemInfo.frontend.join(', ') || 'Not specified'}
- Backend: ${systemInfo.backend.join(', ') || 'Not specified'}
- Database: ${systemInfo.database.join(', ') || 'Not specified'}
- Authentication: ${systemInfo.authentication.join(', ') || 'Not specified'}
- Third-party: ${systemInfo.thirdParty.join(', ') || 'None'}
- App Type: ${systemInfo.appType}
- User Input Areas: ${systemInfo.userInputs.join(', ') || 'Various forms'}
- Description: ${systemInfo.description || 'General application'}
- Sensitive Data: ${systemInfo.sensitiveData.join(', ') || 'None specified'}

Provide a comprehensive security analysis with OWASP Top 10 and STRIDE methodology.

Return EXACTLY this JSON format:
{
  "threats": [
    {
      "id": 1,
      "title": "Specific vulnerability name",
      "severity": "critical/high/medium",
      "category": "A01: Broken Access Control/A02: Cryptographic Failures/A03: Injection/etc",
      "riskScore": 8.5,
      "stride": "Spoofing/Tampering/Repudiation/Information Disclosure/Denial of Service/Elevation of Privilege",
      "cwe": "CWE-XXX",
      "component": "Specific component name",
      "description": "Detailed explanation specific to the technologies mentioned",
      "attackVector": "How the attack would be carried out",
      "impact": {
        "confidentiality": "HIGH/MEDIUM/LOW",
        "integrity": "HIGH/MEDIUM/LOW", 
        "availability": "HIGH/MEDIUM/LOW"
      },
      "likelihood": "HIGH/MEDIUM/LOW",
      "affectedAssets": ["Asset1", "Asset2"],
      "mitigation": ["Step 1", "Step 2", "Step 3"],
      "codeExample": {
        "vulnerable": "Vulnerable code example",
        "secure": "Secure code example"
      },
      "testing": "Testing recommendations",
      "references": ["https://reference1", "https://reference2"]
    }
  ],
  "insight": "Comprehensive AI analysis summary with specific recommendations",
  "riskScore": 75
}

Focus on REAL security risks based on the actual technologies mentioned. Be specific and practical.
`;
};

const parseAIResponse = (aiText, systemInfo) => {
  try {
    const jsonMatch = aiText.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      
      if (parsed.threats && Array.isArray(parsed.threats)) {
        const validatedThreats = parsed.threats.map((threat, index) => ({
          id: threat.id || index + 1,
          title: threat.title || 'Security Vulnerability',
          severity: threat.severity || 'medium',
          category: threat.category || 'A03: Injection',
          riskScore: threat.riskScore || 7.0,
          stride: threat.stride || 'Tampering',
          cwe: threat.cwe || 'CWE-000',
          component: threat.component || `${systemInfo.backend[0]} Component`,
          description: threat.description || 'Security vulnerability identified',
          attackVector: threat.attackVector || 'Attack vector not specified',
          impact: threat.impact || { confidentiality: 'MEDIUM', integrity: 'MEDIUM', availability: 'LOW' },
          likelihood: threat.likelihood || 'MEDIUM',
          affectedAssets: threat.affectedAssets || ['Application Data'],
          mitigation: threat.mitigation || ['Implement security controls'],
          codeExample: threat.codeExample || {
            vulnerable: '// Vulnerable code',
            secure: '// Secure code'
          },
          testing: threat.testing || 'Security testing required',
          references: threat.references || ['https://owasp.org'],
          confirmed: false,
          source: 'AI Prediction'
        }));
        
        return {
          threats: validatedThreats,
          insight: (parsed.insight || 'AI security analysis completed')
            .replace(/\*\*/g, '')
            .replace(/\*/g, ''),
          riskScore: parsed.riskScore || calculateRiskScore(validatedThreats)
        };
      }
    }
    throw new Error('Invalid JSON format from AI');
  } catch (error) {
    console.error('Failed to parse AI response:', error);
    throw new Error('AI response parsing failed');
  }
};

const chatWithAI = async (message, systemInfo) => {
  try {
    const response = await callGeminiChat(message, systemInfo);
    return response;
  } catch (error) {
    console.warn('⚠️ AI chat failed, using static responses');
    return getStaticChatResponse(message);
  }
};

const callGeminiChat = async (message, systemInfo) => {
  try {
    const appKeywords = [
      'my app', 'my application', 'this app', 'our app', systemInfo.appName.toLowerCase(),
      'feature', 'functionality', 'what does this app do', 'describe app', 'explain app',
      'secure', 'security', 'protect', 'vulnerability', 'threat', 'risk', 'safe',
      'improve', 'enhance', 'add feature', 'suggest feature', 'mitigation tips', 'mitigate', 'project', 'my project'
    ];
    
    const isAppQuestion = appKeywords.some(keyword => 
      message.toLowerCase().includes(keyword)
    );
    
    const hasAppContext = systemInfo.appName && systemInfo.appType;
    
    let prompt;
    
    if (isAppQuestion && hasAppContext) {
      prompt = `
You are a helpful assistant for an application called "${systemInfo.appName}". 

APPLICATION CONTEXT:
- Application Name: ${systemInfo.appName}
- Application Type: ${systemInfo.appType}
- Description: ${systemInfo.description}
- Frontend: ${systemInfo.frontend.join(', ')}
- Backend: ${systemInfo.backend.join(', ')}
- Database: ${systemInfo.database.join(', ')}
- Authentication: ${systemInfo.authentication.join(', ')}
- User Input Areas: ${systemInfo.userInputs.join(', ')}
- Sensitive Data: ${systemInfo.sensitiveData.join(', ')}

User Question: ${message}

Provide a helpful response specifically about this application. Answer exactly what the user asked about your app.
`;
    } else {
      prompt = `
You are a helpful assistant.

User Question: ${message}

Provide a helpful and informative response. Answer the question directly without mentioning any specific application.
`;
    }

    const result = await model.generateContent(prompt);
    const response = await result.response;
    const rawText = response.text();
    
    return rawText
      .replace(/\*\*/g, '')
      .replace(/\*/g, '')
      .replace(/`/g, '')
      .replace(/\n#### /g, '\n📌 ')
      .replace(/\n### /g, '\n🔸 ')
      .replace(/\n## /g, '\n🏷️ ')
      .replace(/\n# /g, '\n📋 ')
      .replace(/#/g, '');
  } catch (error) {
    console.error('Chat API call failed:', error);
    throw error;
  }
};

const generateStaticThreats = (systemInfo) => {
  const threats = [];
  let threatId = 1;

  if (systemInfo.database.some(db => ['MySQL', 'PostgreSQL', 'SQLite', 'Oracle'].includes(db)) && 
      systemInfo.userInputs.length > 0) {
    threats.push({
      id: threatId++,
      title: 'SQL Injection Vulnerability',
      severity: 'critical',
      category: 'A03: Injection',
      riskScore: 9.2,
      stride: 'Tampering',
      cwe: 'CWE-89',
      component: `${systemInfo.backend[0]} API - Database Queries`,
      description: 'User inputs are directly concatenated into SQL queries without proper sanitization or parameterization.',
      attackVector: 'Attacker can inject malicious SQL code through input fields, URL parameters, or API endpoints to manipulate database queries.',
      impact: {
        confidentiality: 'HIGH',
        integrity: 'HIGH',
        availability: 'MEDIUM'
      },
      likelihood: 'HIGH',
      affectedAssets: ['User Database', 'Application Data', 'Admin Credentials'],
      mitigation: [
        'Use parameterized queries or prepared statements',
        'Implement input validation with whitelist approach',
        'Use ORM frameworks instead of raw SQL',
        'Apply principle of least privilege to database users',
        'Implement Web Application Firewall (WAF)'
      ],
      codeExample: {
        vulnerable: `// BAD: Vulnerable to SQL Injection\nconst query = "SELECT * FROM users WHERE email = '" + userEmail + "'";\ndb.query(query);`,
        secure: `// GOOD: Using parameterized query\nconst query = "SELECT * FROM users WHERE email = ?";\ndb.query(query, [userEmail]);\n\n// OR using ORM (Sequelize)\nUser.findOne({ where: { email: userEmail } });`
      },
      testing: 'Use SQLMap, OWASP ZAP, or Burp Suite to test for SQL injection vulnerabilities',
      references: [
        'https://owasp.org/www-community/attacks/SQL_Injection',
        'https://cwe.mitre.org/data/definitions/89.html'
      ],
      confirmed: false,
      source: 'Static Analysis'
    });
  }

  if (systemInfo.userInputs.includes('Comments') || systemInfo.userInputs.includes('Forms')) {
    threats.push({
      id: threatId++,
      title: 'Cross-Site Scripting (XSS)',
      severity: 'high',
      category: 'A03: Injection',
      riskScore: 7.8,
      stride: 'Spoofing',
      cwe: 'CWE-79',
      component: `${systemInfo.frontend[0]} - User Input Display`,
      description: 'User-generated content is displayed without proper sanitization, allowing malicious scripts to execute in victim browsers.',
      attackVector: 'Attacker injects malicious JavaScript code through input fields that gets executed when other users view the content.',
      impact: {
        confidentiality: 'HIGH',
        integrity: 'MEDIUM',
        availability: 'LOW'
      },
      likelihood: 'HIGH',
      affectedAssets: ['User Sessions', 'Cookies', 'User Data', 'Authentication Tokens'],
      mitigation: [
        'Sanitize all user inputs with DOMPurify',
        'Implement Content Security Policy (CSP)',
        'Use framework built-in escaping (React handles this by default)',
        'Validate input on both client and server side',
        'Set HTTPOnly and Secure flags on cookies'
      ],
      codeExample: {
        vulnerable: `// BAD: Direct HTML injection\n<div dangerouslySetInnerHTML={{__html: userComment}} />`,
        secure: `// GOOD: Sanitized output\nimport DOMPurify from 'dompurify';\n\n<div dangerouslySetInnerHTML={{\n  __html: DOMPurify.sanitize(userComment)\n}} />\n\n// OR just use React's default (safest)\n<div>{userComment}</div>`
      },
      testing: 'Test with XSS payloads like <script>alert("XSS")</script> and use OWASP ZAP scanner',
      references: [
        'https://owasp.org/www-community/attacks/xss/',
        'https://cwe.mitre.org/data/definitions/79.html'
      ],
      confirmed: false,
      source: 'Static Analysis'
    });
  }

  if (systemInfo.authentication.includes('JWT')) {
    threats.push({
      id: threatId++,
      title: 'Weak JWT Implementation',
      severity: 'high',
      category: 'A07: Auth Failures',
      riskScore: 8.1,
      stride: 'Elevation of Privilege',
      cwe: 'CWE-287',
      component: `${systemInfo.backend[0]} - Authentication System`,
      description: 'JWT tokens lack proper expiration, validation, or are signed with weak secrets.',
      attackVector: 'Attacker can steal tokens, forge signatures with weak secrets, or reuse expired tokens to gain unauthorized access.',
      impact: {
        confidentiality: 'HIGH',
        integrity: 'HIGH',
        availability: 'LOW'
      },
      likelihood: 'MEDIUM',
      affectedAssets: ['User Accounts', 'Admin Panel', 'Protected Resources'],
      mitigation: [
        'Set short expiration times (15-30 minutes)',
        'Implement refresh token mechanism',
        'Use strong secrets (256+ bits)',
        'Validate tokens on every request',
        'Implement token revocation list',
        'Store tokens securely (HttpOnly cookies)'
      ],
      codeExample: {
        vulnerable: `// BAD: No expiration, weak secret\nconst token = jwt.sign({ userId: user.id }, 'secret123');`,
        secure: `// GOOD: Proper JWT implementation\nconst token = jwt.sign(\n  { userId: user.id },\n  process.env.JWT_SECRET, // Strong secret from env\n  { expiresIn: '15m' }\n);\n\n// Verify token\njwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {\n  if (err) return res.status(401).send('Invalid token');\n  req.user = decoded;\n  next();\n});`
      },
      testing: 'Use jwt.io to decode tokens, test with expired tokens, and attempt signature forgery',
      references: [
        'https://owasp.org/www-community/vulnerabilities/JWT',
        'https://cwe.mitre.org/data/definitions/287.html'
      ],
      confirmed: false,
      source: 'Static Analysis'
    });
  }

  if (systemInfo.userInputs.includes('File Uploads')) {
    threats.push({
      id: threatId++,
      title: 'Unrestricted File Upload',
      severity: 'critical',
      category: 'A04: Insecure Design',
      riskScore: 8.5,
      stride: 'Tampering',
      cwe: 'CWE-434',
      component: 'File Upload Handler',
      description: 'Application accepts file uploads without proper validation of file type, size, or content.',
      attackVector: 'Attacker uploads malicious files (web shells, executables) that can lead to remote code execution.',
      impact: {
        confidentiality: 'HIGH',
        integrity: 'HIGH',
        availability: 'HIGH'
      },
      likelihood: 'MEDIUM',
      affectedAssets: ['Server', 'Application Code', 'Database', 'User Data'],
      mitigation: [
        'Whitelist allowed file extensions',
        'Validate file content (magic numbers)',
        'Limit file size',
        'Store files outside web root',
        'Rename uploaded files',
        'Use antivirus scanning',
        'Implement rate limiting'
      ],
      codeExample: {
        vulnerable: `// BAD: No validation\napp.post('/upload', (req, res) => {\n  const file = req.files.upload;\n  file.mv('./uploads/' + file.name);\n});`,
        secure: `// GOOD: Proper validation\nconst multer = require('multer');\nconst path = require('path');\n\nconst storage = multer.diskStorage({\n  destination: './uploads/',\n  filename: (req, file, cb) => {\n    cb(null, Date.now() + '-' + Math.random().toString(36));\n  }\n});\n\nconst upload = multer({\n  storage: storage,\n  limits: { fileSize: 5 * 1024 * 1024 },\n  fileFilter: (req, file, cb) => {\n    const allowed = ['.jpg', '.jpeg', '.png', '.pdf'];\n    const ext = path.extname(file.originalname).toLowerCase();\n    if (allowed.includes(ext)) {\n      cb(null, true);\n    } else {\n      cb(new Error('Invalid file type'));\n    }\n  }\n});`
      },
      testing: 'Attempt to upload .php, .exe, .sh files and files with double extensions',
      references: [
        'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
        'https://cwe.mitre.org/data/definitions/434.html'
      ],
      confirmed: false,
      source: 'Static Analysis'
    });
  }

  if (systemInfo.sensitiveData.length > 0) {
    threats.push({
      id: threatId++,
      title: 'Sensitive Data Exposure',
      severity: 'high',
      category: 'A02: Cryptographic Failures',
      riskScore: 7.5,
      stride: 'Information Disclosure',
      cwe: 'CWE-311',
      component: 'Data Storage & Transmission',
      description: `Application handles sensitive data (${systemInfo.sensitiveData.join(', ')}) without proper encryption or protection.`,
      attackVector: 'Attacker intercepts network traffic or accesses database to steal unencrypted sensitive information.',
      impact: {
        confidentiality: 'HIGH',
        integrity: 'LOW',
        availability: 'LOW'
      },
      likelihood: 'MEDIUM',
      affectedAssets: systemInfo.sensitiveData,
      mitigation: [
        'Use HTTPS/TLS for all communications',
        'Encrypt sensitive data at rest (AES-256)',
        'Hash passwords with bcrypt (cost 12+)',
        'Never log sensitive data',
        'Implement key management system',
        'Use secure storage APIs'
      ],
      codeExample: {
        vulnerable: `// BAD: Plain text password\nconst user = {\n  email: email,\n  password: password // Plain text!\n};\nawait db.save(user);`,
        secure: `// GOOD: Hashed password\nconst bcrypt = require('bcrypt');\n\nconst hashedPassword = await bcrypt.hash(password, 12);\nconst user = {\n  email: email,\n  password: hashedPassword\n};\nawait db.save(user);\n\n// Verification\nconst match = await bcrypt.compare(inputPassword, user.password);`
      },
      testing: 'Check network traffic with Wireshark, inspect database for plain text secrets',
      references: [
        'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url',
        'https://cwe.mitre.org/data/definitions/311.html'
      ],
      confirmed: false,
      source: 'Static Analysis'
    });
  }

  threats.push({
    id: threatId++,
    title: 'Missing Rate Limiting',
    severity: 'medium',
    category: 'A05: Security Misconfiguration',
    riskScore: 6.2,
    stride: 'Denial of Service',
    cwe: 'CWE-770',
    component: 'API Endpoints',
    description: 'Application does not limit the number of requests from a single source.',
    attackVector: 'Attacker can perform brute force attacks, scraping, or cause denial of service through excessive requests.',
    impact: {
      confidentiality: 'LOW',
      integrity: 'LOW',
      availability: 'HIGH'
    },
    likelihood: 'HIGH',
    affectedAssets: ['Server Resources', 'Database', 'User Accounts'],
    mitigation: [
      'Implement rate limiting (express-rate-limit)',
      'Use CAPTCHA for sensitive operations',
      'Implement account lockout after failed attempts',
      'Use CDN with DDoS protection',
      'Monitor and alert on unusual traffic'
    ],
    codeExample: {
      vulnerable: `// BAD: No rate limiting\napp.post('/api/login', async (req, res) => {\n  // Unlimited login attempts!\n});`,
      secure: `// GOOD: Rate limiting\nconst rateLimit = require('express-rate-limit');\n\nconst loginLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000, // 15 minutes\n  max: 5, // Limit each IP to 5 requests per windowMs\n  message: 'Too many login attempts, please try again later'\n});\n\napp.post('/api/login', loginLimiter, async (req, res) => {\n  // Protected endpoint\n});`
    },
    testing: 'Send 100+ rapid requests and verify blocking occurs',
    references: [
      'https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks',
      'https://cwe.mitre.org/data/definitions/770.html'
    ],
    confirmed: false,
    source: 'Static Analysis'
  });

  if (systemInfo.appType.includes('API') || systemInfo.frontend.length > 0) {
    threats.push({
      id: threatId++,
      title: 'CORS Misconfiguration',
      severity: 'medium',
      category: 'A05: Security Misconfiguration',
      riskScore: 5.8,
      stride: 'Information Disclosure',
      cwe: 'CWE-942',
      component: 'API CORS Policy',
      description: 'Cross-Origin Resource Sharing (CORS) is configured to allow all origins (*), enabling unauthorized cross-domain requests.',
      attackVector: 'Malicious websites can make authenticated requests to your API on behalf of users.',
      impact: {
        confidentiality: 'MEDIUM',
        integrity: 'MEDIUM',
        availability: 'LOW'
      },
      likelihood: 'MEDIUM',
      affectedAssets: ['User Data', 'API Endpoints', 'User Sessions'],
      mitigation: [
        'Whitelist specific origins',
        'Avoid using Access-Control-Allow-Origin: *',
        'Validate origin header',
        'Implement proper authentication',
        'Use credentials flag carefully'
      ],
      codeExample: {
        vulnerable: `// BAD: Allows all origins\napp.use(cors({\n  origin: '*', // Dangerous!\n  credentials: true\n}));`,
        secure: `// GOOD: Whitelist origins\nconst allowedOrigins = [\n  'https://yourapp.com',\n  'https://app.yourapp.com'\n];\n\napp.use(cors({\n  origin: (origin, callback) => {\n    if (allowedOrigins.includes(origin) || !origin) {\n      callback(null, true);\n    } else {\n      callback(new Error('Not allowed by CORS'));\n    }\n  },\n  credentials: true\n}));`
      },
      testing: 'Test with different Origin headers using curl or browser dev tools',
      references: [
        'https://owasp.org/www-community/vulnerabilities/CORS_OriginHeaderScrutiny',
        'https://cwe.mitre.org/data/definitions/942.html'
      ],
      confirmed: false,
      source: 'Static Analysis'
    });
  }

  return {
    threats,
    insight: generateAIInsight(threats, systemInfo),
    riskScore: calculateRiskScore(threats)
  };
};

const generateAIInsight = (threats, systemInfo) => {
  const criticalCount = threats.filter(t => t.severity === 'critical').length;
  const highCount = threats.filter(t => t.severity === 'high').length;
  const categories = [...new Set(threats.map(t => t.category))];
  
  return `🤖 AI Analysis Complete: Identified ${threats.length} potential security threats in your ${systemInfo.appType}. 
    
Critical Priority: ${criticalCount} threats require immediate attention, particularly ${threats[0]?.title} which has a risk score of ${threats[0]?.riskScore}/10. 

Your application is most vulnerable to ${categories[0]} attacks. Based on your tech stack (${systemInfo.frontend[0]}, ${systemInfo.backend[0]}, ${systemInfo.database[0]}), I recommend implementing input validation and parameterized queries as the first line of defense.

Estimated remediation time: ${Math.ceil(threats.length * 2)} hours. Priority order: ${criticalCount} critical → ${highCount} high severity issues. Implementation of top 3 recommendations will reduce your risk score by approximately 60%.`;
};

const calculateRiskScore = (threats) => {
  if (threats.length === 0) return 0;
  const totalRisk = threats.reduce((sum, t) => sum + t.riskScore, 0);
  return Math.round((totalRisk / threats.length) * 10);
};

const getStaticChatResponse = (message) => {
  const lowerMessage = message.toLowerCase();
  
  if (lowerMessage.includes('xss')) {
    return "For XSS protection: 1) Implement Content Security Policy, 2) Sanitize all user inputs, 3) Use HTTPOnly cookies, 4) Escape user content in HTML.";
  }
  
  if (lowerMessage.includes('sql') || lowerMessage.includes('injection')) {
    return "To prevent SQL injection: 1) Use parameterized queries, 2) Implement input validation, 3) Use ORM frameworks, 4) Apply principle of least privilege.";
  }
  
  if (lowerMessage.includes('auth') || lowerMessage.includes('login')) {
    return "For secure authentication: 1) Implement multi-factor authentication, 2) Use strong password policies, 3) Secure session management, 4) Protect against brute force attacks.";
  }
  
  return "I understand your security question. For comprehensive analysis, please check the threat report above. For immediate concerns: always validate input, use HTTPS, and implement proper authentication.";
};

// COMPLETE REACT COMPONENT
const ThreatModelingAssistant = () => {
  const [step, setStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [systemInfo, setSystemInfo] = useState({
    appType: '',
    appName: '',
    description: '',
    frontend: [],
    backend: [],
    database: [],
    authentication: [],
    thirdParty: [],
    userInputs: [],
    sensitiveData: [],
    deployment: []
  });
  const [gitUrl, setGitUrl] = useState('');
  const [useEnhancedAnalysis, setUseEnhancedAnalysis] = useState(false);
  const [threats, setThreats] = useState([]);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterCategory, setFilterCategory] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState('');
  const [checklist, setChecklist] = useState([]);
  const [expandedThreats, setExpandedThreats] = useState([]);
  const [copiedCode, setCopiedCode] = useState(null);
  const [aiInsight, setAiInsight] = useState('');
  const [riskScore, setRiskScore] = useState(0);
  const [usingAI, setUsingAI] = useState(true);
  const [realityCheck, setRealityCheck] = useState('');
  const [analysisSummary, setAnalysisSummary] = useState(null);

  const appTypes = ['Web Application', 'Mobile App', 'REST API', 'Desktop Application', 'Microservices', 'Mobile App + Web App', 'Mobile App + Desktop App', 'Desktop App + Web App', 'Web App + Desktop App + Mobile App'];
  
  const techOptions = {
  frontend: [
    'React', 'Next.js', 'Vue.js', 'Angular', 'Svelte', 'React Native', 'Flutter', 
    'Ionic', 'SwiftUI', 'Jetpack Compose', 'Xamarin', 'Apache Cordova', 'Electron',
    'Tailwind CSS', 'Bootstrap', 'Material UI', 'Chakra UI', 'Ant Design', 'Bulma',
    'Plain HTML/CSS/JS', 'jQuery', 'Ember.js', 'Backbone.js', 'Alpine.js', 'Solid.js',
    'Stencil', 'Marko', 'Mithril', 'Preact', 'Lit', 'Stimulus', 'Hotwire'
  ],
  backend: [
    'Node.js', 'Express.js', 'NestJS', 'Fastify', 'Koa', 'Hapi', 'AdonisJS',
    'Python/Django', 'Python/Flask', 'FastAPI', 'Python/Pyramid', 'Python/Bottle',
    'Java/Spring Boot', 'Java/Spring MVC', 'Java/Spring Security', 'Java/Micronaut',
    'Java/Quarkus', 'Java/Play Framework', 'Java/Spark', 'Java/Vert.x',
    'PHP/Laravel', 'PHP/Symfony', 'PHP/CodeIgniter', 'PHP/CakePHP', 'PHP/Yii',
    'Ruby on Rails', 'Ruby/Sinatra', 'Ruby/Hanami', 'Ruby/Grape',
    'Go/Gin', 'Go/Echo', 'Go/Fiber', 'Go/Chi', 'Go/Beego', 'Go/Revel',
    '.NET', 'C#/ASP.NET Core', 'C#/ASP.NET MVC', 'F#/Giraffe', 'VB.NET',
    'Rust/Actix', 'Rust/Rocket', 'Rust/Warp', 'Rust/Axum',
    'Elixir/Phoenix', 'Elixir/Plug', 'Scala/Play', 'Scala/Akka HTTP',
    'Kotlin/Ktor', 'Kotlin/Spring Boot', 'Dart/Aqueduct', 'Perl/Dancer',
    'Haskell/Yesod', 'Haskell/Scotty', 'Clojure/Luminus', 'C++/Crow'
  ],
  database: [
    'MySQL', 'PostgreSQL', 'MariaDB', 'SQLite', 'Oracle', 'Microsoft SQL Server',
    'MongoDB', 'Redis', 'Cassandra', 'Couchbase', 'CouchDB', 'RavenDB',
    'Firebase Realtime DB', 'Firestore', 'DynamoDB', 'ElasticSearch',
    'Neo4j', 'ArangoDB', 'OrientDB', 'JanusGraph', 'Amazon Neptune',
    'InfluxDB', 'TimescaleDB', 'Prometheus', 'Graphite',
    'ClickHouse', 'Apache Druid', 'Apache Pinot', 'Snowflake',
    'BigQuery', 'Redshift', 'Cosmos DB', 'FaunaDB', 'Supabase',
    'CockroachDB', 'YugabyteDB', 'TiDB', 'Vitess', 'PlanetScale'
  ],
  authentication: [
    'JWT (JSON Web Token)', 'OAuth 2.0', 'OpenID Connect', 'Session-based', 
    'API Keys', 'Basic Auth', 'Digest Auth', 'HMAC', 'AWS Signature',
    'Firebase Auth', 'Auth0', 'Cognito', 'Okta', 'OneLogin', 'Ping Identity',
    'Azure AD', 'Keycloak', 'Passport.js', 'Devise', 'Spring Security',
    '2FA / MFA', 'Biometric', 'WebAuthn', 'FIDO2', 'U2F', 'TOTP', 'HOTP',
    'SAML', 'LDAP', 'Kerberos', 'CAS', 'Social Login (Google/Facebook/GitHub)'
  ],
  thirdParty: [
    'Stripe', 'PayPal', 'Square', 'Braintree', 'Adyen', 'Razorpay',
    'Google Maps API', 'Mapbox', 'Leaflet', 'OpenStreetMap',
    'AWS S3', 'Google Cloud Storage', 'Azure Blob Storage', 'Cloudflare R2',
    'Cloudinary', 'Imgix', 'Uploadcare', 'Filestack',
    'Twilio', 'Vonage', 'Plivo', 'MessageBird', 'Bandwidth',
    'SendGrid', 'Mailgun', 'Postmark', 'Amazon SES', 'Resend',
    'Slack API', 'Microsoft Teams API', 'Discord API', 'Zoom API',
    'Google OAuth', 'Facebook Login', 'GitHub OAuth', 'Apple Sign In',
    'OpenAI API', 'Anthropic Claude', 'Google Gemini', 'Azure OpenAI',
    'AWS Bedrock', 'Hugging Face', 'Cohere', 'Stability AI',
    'Stripe Connect', 'Plaid', 'Yodlee', 'Teller', 'Finicity'
  ],
  userInputs: [
    'Forms', 'File Uploads', 'Search', 'Comments', 'Chat/Messaging', 
    'Rich Text Editor', 'JSON API Input', 'URL Parameters', 'Headers',
    'Cookies', 'WebSockets', 'GraphQL Queries', 'gRPC Messages',
    'XML Input', 'CSV Upload', 'Image Upload', 'Video Upload',
    'Audio Upload', 'Document Upload', 'Archive Upload',
    'User Profiles', 'Settings', 'Preferences', 'Contact Forms',
    'Registration Forms', 'Login Forms', 'Payment Forms',
    'Feedback Forms', 'Survey Forms', 'Quiz Forms'
  ],
  sensitiveData: [
    'Passwords', 'Credit/Debit Cards', 'Bank Accounts', 'Cryptocurrency',
    'PII (Personal Identifiable Information)', 'Health Data (PHI)', 
    'Financial Records', 'Tax Information', 'Insurance Information',
    'API Keys', 'Access Tokens', 'Refresh Tokens', 'Session Tokens',
    'Encryption Keys', 'Digital Certificates', 'SSH Keys',
    'Biometric Data', 'Genetic Data', 'Facial Recognition Data',
    'Location Data', 'GPS Coordinates', 'IP Addresses', 'MAC Addresses',
    'Social Security Numbers', 'Passport Numbers', 'Driver License',
    'Medical Records', 'Prescription Data', 'Insurance Claims',
    'Salary Information', 'Tax Returns', 'Investment Portfolios',
    'Trade Secrets', 'Source Code', 'Algorithm Data', 'Training Data'
  ],
  deployment: [
    'AWS', 'Google Cloud', 'Azure', 'IBM Cloud', 'Oracle Cloud', 'Alibaba Cloud',
    'Heroku', 'Vercel', 'Netlify', 'Railway', 'Render', 'Fly.io',
    'DigitalOcean', 'Linode', 'Vultr', 'Scaleway', 'Upcloud',
    'Docker', 'Kubernetes', 'Docker Swarm', 'Nomad', 'Mesos',
    'On-Premise', 'Bare Metal', 'Colocation', 'Private Cloud',
    'Nginx', 'Apache', 'Caddy', 'Traefik', 'Envoy', 'HAProxy',
    'Cloudflare', 'Akamai', 'Fastly', 'AWS CloudFront', 'Google CDN',
    'GitHub Pages', 'GitLab Pages', 'Bitbucket Pages', 'Surge.sh'
  ]
};

  const owaspCategories = [
    'A01: Broken Access Control',
    'A02: Cryptographic Failures',
    'A03: Injection',
    'A04: Insecure Design',
    'A05: Security Misconfiguration',
    'A06: Vulnerable Components',
    'A07: Auth Failures',
    'A08: Data Integrity Failures',
    'A09: Logging Failures',
    'A10: SSRF'
  ];

  const generateThreats = async () => {
    setLoading(true);
    setUsingAI(true);
    setRealityCheck('');
    setAnalysisSummary(null);
    
    try {
      let analysis;
      
      if (useEnhancedAnalysis && gitUrl) {
        analysis = await analyzeWithEnhancedAI(systemInfo, gitUrl);
        setRealityCheck(analysis.realityCheck || '');
        setAnalysisSummary(analysis.analysisSummary || null);
      } else {
        analysis = await analyzeWithAI(systemInfo);
      }
      
      setThreats(analysis.threats);
      setAiInsight(analysis.insight);
      setRiskScore(analysis.riskScore);
      generateChecklist(analysis.threats);
      
    } catch (error) {
      console.error('Analysis failed:', error);
      setUsingAI(false);
      
      const staticAnalysis = generateStaticThreats(systemInfo);
      setThreats(staticAnalysis.threats);
      setAiInsight(staticAnalysis.insight);
      setRiskScore(staticAnalysis.riskScore);
      generateChecklist(staticAnalysis.threats);
    }
    
    setLoading(false);
    setStep(3);
  };

  const handleChat = async () => {
    if (!chatInput.trim()) return;
    
    const userMessage = { role: 'user', content: chatInput };
    setChatMessages(prev => [...prev, userMessage]);
    setChatInput('');
    
    try {
      const aiResponse = await chatWithAI(chatInput, systemInfo);
      setChatMessages(prev => [...prev, { 
        role: 'assistant', 
        content: aiResponse 
      }]);
    } catch (error) {
      const fallbackResponse = getStaticChatResponse(chatInput);
      setChatMessages(prev => [...prev, { 
        role: 'assistant', 
        content: fallbackResponse 
      }]);
    }
  };

  const generateChecklist = (threats) => {
  const items = [];
  threats.forEach(threat => {
    threat.mitigation.forEach((mitigation, idx) => {
      const cleanMitigation = mitigation
        .replace(/\*\*/g, '')
        .replace(/\*/g, '')
        .replace(/`/g, '');
      
      items.push({
        id: `${threat.id}-${idx}`,
        text: cleanMitigation,
        category: threat.category,
        severity: threat.severity,
        completed: false
      });
    });
  });
  setChecklist(items);
};

  const handleMultiSelect = (category, value) => {
    setSystemInfo(prev => ({
      ...prev,
      [category]: prev[category].includes(value)
        ? prev[category].filter(item => item !== value)
        : [...prev[category], value]
    }));
  };

  const filteredThreats = threats.filter(threat => {
    const matchesSeverity = filterSeverity === 'all' || threat.severity === filterSeverity;
    const matchesCategory = filterCategory === 'all' || threat.category === filterCategory;
    const matchesSearch = threat.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         threat.description.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSeverity && matchesCategory && matchesSearch;
  });

  const toggleThreatExpand = (threatId) => {
    setExpandedThreats(prev =>
      prev.includes(threatId)
        ? prev.filter(id => id !== threatId)
        : [...prev, threatId]
    );
  };

  const copyCode = (code, id) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const downloadReport = () => {
    const report = `
THREAT MODEL REPORT
===================
Application: ${systemInfo.appName}
Type: ${systemInfo.appType}
Analysis Type: ${usingAI ? 'AI-Powered' : 'Static Analysis'}
Enhanced Analysis: ${useEnhancedAnalysis ? 'Yes (Repomix + OSV)' : 'No'}
Git Repository: ${gitUrl || 'Not provided'}
Generated: ${new Date().toLocaleString()}

${realityCheck ? `\nREALITY CHECK:\n${realityCheck}\n` : ''}

${analysisSummary ? `\nANALYSIS SUMMARY:\n- Confirmed Vulnerabilities: ${analysisSummary.confirmedVulns}\n- Predicted Vulnerabilities: ${analysisSummary.predictedVulns}\n- Tech Reality Match: ${analysisSummary.techRealityMatch ? 'Yes' : 'No'}\n` : ''}

${aiInsight}

IDENTIFIED THREATS
------------------
${threats.map((t, idx) => `
${idx + 1}. ${t.title} [${t.severity.toUpperCase()}] ${t.confirmed ? '[CONFIRMED]' : '[PREDICTED]'}
   Source: ${t.source}
   Risk Score: ${t.riskScore}/10
   Category: ${t.category}
   CWE: ${t.cwe}
   
   Description: ${t.description}
   
   Mitigation:
   ${t.mitigation.map((m, i) => `   ${i + 1}. ${m}`).join('\n')}
`).join('\n')}
`;

    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-model-${systemInfo.appName}-${Date.now()}.txt`;
    a.click();
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'critical': return '#dc2626';
      case 'high': return '#f59e0b';
      case 'medium': return '#eab308';
      default: return '#22c55e';
    }
  };

  const toggleChecklistItem = (id) => {
    setChecklist(prev =>
      prev.map(item =>
        item.id === id ? { ...item, completed: !item.completed } : item
      )
    );
  };

 const renderAIStatus = () => (
  <div className={`tm-ai-status ${usingAI ? 'ai-active' : 'ai-fallback'}`}>
    {usingAI ? (
      <div style={{ display: 'flex', alignItems: 'center', gap: '4.5px' }}>
        <Brain size={16} />
        <span>{useEnhancedAnalysis ? 'Enhanced AI Analysis' : 'AI-Powered Analysis'}</span>
      </div>
    ) : (
      <div style={{ display: 'flex', alignItems: 'center', gap: '4.5px' }}>
        <Shield size={16} />
        <span>Static Analysis</span>
      </div>
    )}
  </div>
);

  if (step === 1) {
    return (
      <div className="threat-modeling-container">
        <div className="tm-header">
          <div className="tm-header-content">
            <Brain size={40} className="tm-logo" />
            <div>
              <h1>AI-Powered Threat Modeling Assistant</h1>
              <p>Identify security vulnerabilities in your application architecture</p>
            </div>
          </div>
          {renderAIStatus()}
        </div>

        <div className="tm-wizard">
          <div className="tm-wizard-steps">
            <div className="tm-step active">
              <div className="tm-step-number">1</div>
              <div className="tm-step-label">System Info</div>
            </div>
            <div className="tm-step-line"></div>
            <div className="tm-step">
              <div className="tm-step-number">2</div>
              <div className="tm-step-label">Analysis</div>
            </div>
            <div className="tm-step-line"></div>
            <div className="tm-step">
              <div className="tm-step-number">3</div>
              <div className="tm-step-label">Results</div>
            </div>
          </div>

          <div className="tm-form">
            <div className="tm-form-section">
              <h3>Basic Information</h3>
              <div className="tm-input-group">
                <label>Application Name</label>
                <input
                  type="text"
                  placeholder="e.g., My E-commerce Platform"
                  value={systemInfo.appName}
                  onChange={(e) => setSystemInfo({...systemInfo, appName: e.target.value})}
                />
              </div>

              <div className="tm-input-group">
                <label>Application Type</label>
                <select
                  value={systemInfo.appType}
                  onChange={(e) => setSystemInfo({...systemInfo, appType: e.target.value})}
                >
                  <option value="">Select type...</option>
                  {appTypes.map(type => (
                    <option key={type} value={type}>{type}</option>
                  ))}
                </select>
              </div>

              <div className="tm-input-group">
                <label>Description</label>
                <textarea
                  placeholder="Describe your application in plain English (required)..."
                  value={systemInfo.description}
                  onChange={(e) => setSystemInfo({...systemInfo, description: e.target.value})}
                  rows={4}
                  required
                />
              </div>

              <div className="tm-input-group">
                <label>
                  <GitBranch size={16} style={{ marginRight: '8px', verticalAlign: 'middle' }} />
                  Git Repository URL (Optional)
                </label>
                <input
                  type="text"
                  placeholder="https://github.com/user/repository"
                  value={gitUrl}
                  onChange={(e) => setGitUrl(e.target.value)}
                />
                <div className="tm-input-hint">
                  Provide a GitHub/GitLab URL for enhanced analysis with actual code review
                </div>
              </div>

              {gitUrl && (
                <div className="tm-toggle-group">
                  <label className="tm-toggle">
                    <input
                      type="checkbox"
                      checked={useEnhancedAnalysis}
                      onChange={(e) => setUseEnhancedAnalysis(e.target.checked)}
                    />
                    <span className="tm-toggle-slider"></span>
                    <span className="tm-toggle-label">
                      <Package size={14} style={{ marginRight: '6px' }} />
                      Enable Enhanced Analysis (Repomix + OSV)
                    </span>
                  </label>
                  <div className="tm-input-hint">
                    When enabled: Analyzes ACTUAL code + checks for confirmed vulnerabilities in dependencies
                  </div>
                </div>
              )}
            </div>

            <div className="tm-form-section">
              <h3><Code size={20} /> Technology Stack</h3>
              
              <div className="tm-multi-select">
                <label>Frontend Technologies</label>
                <div className="tm-chips">
                  {techOptions.frontend.map(tech => (
                    <button
                      key={tech}
                      className={`tm-chip ${systemInfo.frontend.includes(tech) ? 'active' : ''}`}
                      onClick={() => handleMultiSelect('frontend', tech)}
                    >
                      {tech}
                    </button>
                  ))}
                </div>
              </div>

              <div className="tm-multi-select">
                <label>Backend Technologies</label>
                <div className="tm-chips">
                  {techOptions.backend.map(tech => (
                    <button
                      key={tech}
                      className={`tm-chip ${systemInfo.backend.includes(tech) ? 'active' : ''}`}
                      onClick={() => handleMultiSelect('backend', tech)}
                    >
                      {tech}
                    </button>
                  ))}
                </div>
              </div>

              <div className="tm-multi-select">
                <label>Database</label>
                <div className="tm-chips">
                  {techOptions.database.map(tech => (
                    <button
                      key={tech}
                      className={`tm-chip ${systemInfo.database.includes(tech) ? 'active' : ''}`}
                      onClick={() => handleMultiSelect('database', tech)}
                    >
                      {tech}
                    </button>
                  ))}
                </div>
              </div>

              <div className="tm-multi-select">
                <label>Authentication Methods</label>
                <div className="tm-chips">
                  {techOptions.authentication.map(tech => (
                    <button
                      key={tech}
                      className={`tm-chip ${systemInfo.authentication.includes(tech) ? 'active' : ''}`}
                      onClick={() => handleMultiSelect('authentication', tech)}
                    >
                      {tech}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="tm-form-section">
              <h3><Target size={20} /> Attack Surface</h3>
              
              <div className="tm-multi-select">
                <label>User Input Points</label>
                <div className="tm-chips">
                  {techOptions.userInputs.map(tech => (
                    <button
                      key={tech}
                      className={`tm-chip ${systemInfo.userInputs.includes(tech) ? 'active' : ''}`}
                      onClick={() => handleMultiSelect('userInputs', tech)}
                    >
                      {tech}
                    </button>
                  ))}
                </div>
              </div>

              <div className="tm-multi-select">
                <label>Sensitive Data Handled</label>
                <div className="tm-chips">
                  {techOptions.sensitiveData.map(tech => (
                    <button
                      key={tech}
                      className={`tm-chip ${systemInfo.sensitiveData.includes(tech) ? 'active' : ''}`}
                      onClick={() => handleMultiSelect('sensitiveData', tech)}
                    >
                      {tech}
                    </button>
                  ))}
                </div>
              </div>

              <div className="tm-multi-select">
                <label>Third-party Integrations</label>
                <div className="tm-chips">
                  {techOptions.thirdParty.map(tech => (
                    <button
                      key={tech}
                      className={`tm-chip ${systemInfo.thirdParty.includes(tech) ? 'active' : ''}`}
                      onClick={() => handleMultiSelect('thirdParty', tech)}
                    >
                      {tech}
                    </button>
                  ))}
                </div>
              </div>

              <div className="tm-multi-select">
                <label>Deployment Environment</label>
                <div className="tm-chips">
                  {techOptions.deployment.map(tech => (
                    <button
                      key={tech}
                      className={`tm-chip ${systemInfo.deployment.includes(tech) ? 'active' : ''}`}
                      onClick={() => handleMultiSelect('deployment', tech)}
                    >
                      {tech}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <button 
              className="tm-btn-primary tm-btn-large"
              onClick={() => setStep(2)}
              disabled={!systemInfo.appName || !systemInfo.appType || !systemInfo.description || systemInfo.backend.length === 0}
            >
              Continue to Analysis <ChevronRight size={20} />
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (step === 2) {
  return (
    <div className="threat-modeling-container">
      <div className="tm-header">
        <div className="tm-header-content">
          <Brain size={40} className="tm-logo" />
          <div>
            <h1>AI-Powered Threat Modeling Assistant</h1>
            <p>Analyzing your application for security threats...</p>
          </div>
        </div>
        {renderAIStatus()}
      </div>

      <div className="tm-wizard">
        <div className="tm-wizard-steps">
          <div className="tm-step completed">
            <div className="tm-step-number"><CheckCircle size={20} /></div>
            <div className="tm-step-label">System Info</div>
          </div>
          <div className="tm-step-line active"></div>
          <div className="tm-step active">
            <div className="tm-step-number">2</div>
            <div className="tm-step-label">Analysis</div>
          </div>
          <div className="tm-step-line"></div>
          <div className="tm-step">
            <div className="tm-step-number">3</div>
            <div className="tm-step-label">Results</div>
          </div>
        </div>

        <div className="tm-analysis-screen">
          <div className="tm-analysis-card">
            <Shield size={64} className="tm-analysis-icon pulse" />
            <h2>Analyzing Security Posture</h2>
            <p>
              {useEnhancedAnalysis && gitUrl 
                ? "AI is analyzing your ACTUAL codebase and checking for confirmed vulnerabilities..." 
                : loading 
                  ? "AI is actively scanning your application..." 
                  : "Ready to analyze your application architecture"}
            </p>
            
            <div className="tm-progress-steps">
              {useEnhancedAnalysis && gitUrl && (
                <>
                  <div className={`tm-progress-step ${loading ? 'active' : ''}`}>
                    {loading ? <Loader className="spin" size={16} /> : <div className="tm-step-icon"><FileCode size={14} /></div>}
                    <span>Fetching repository</span>
                    {loading && <div className="tm-step-status">Using Repomix...</div>}
                  </div>
                  <div className={`tm-progress-step ${loading ? 'active' : ''}`}>
                    {loading ? <Loader className="spin" size={16} /> : <div className="tm-step-icon"><Package size={14} /></div>}
                    <span>Analyzing dependencies</span>
                    {loading && <div className="tm-step-status">Checking OSV...</div>}
                  </div>
                </>
              )}
              <div className={`tm-progress-step ${loading ? 'active' : ''}`}>
                {loading ? <Loader className="spin" size={16} /> : <div className="tm-step-icon">1</div>}
                <span>Mapping attack surface</span>
                {loading && <div className="tm-step-status">Scanning code...</div>}
              </div>
              <div className={`tm-progress-step ${loading ? 'active' : ''}`}>
                {loading ? <Loader className="spin" size={16} /> : <div className="tm-step-icon">2</div>}
                <span>Identifying threat vectors</span>
                {loading && <div className="tm-step-status">Analyzing patterns...</div>}
              </div>
              <div className={`tm-progress-step ${loading ? 'active' : ''}`}>
                {loading ? <Loader className="spin" size={16} /> : <div className="tm-step-icon">3</div>}
                <span>Calculating risk scores</span>
                {loading && <div className="tm-step-status">Processing...</div>}
              </div>
              <div className={`tm-progress-step ${loading ? 'active' : ''}`}>
                {loading ? <Loader className="spin" size={16} /> : <div className="tm-step-icon">4</div>}
                <span>Generating mitigations</span>
                {loading && <div className="tm-step-status">Compiling report...</div>}
              </div>
            </div>

            <button 
              className="tm-btn-primary tm-btn-large"
              onClick={generateThreats}
              disabled={loading}
            >
              {loading ? (
                <>
                  <Loader className="spin" size={20} />
                  {useEnhancedAnalysis && gitUrl ? 'Enhanced Analysis in Progress...' : 'AI Analysis in Progress...'}
                </>
              ) : (
                <>
                  <Zap size={20} />
                  {useEnhancedAnalysis && gitUrl ? 'Start Enhanced Analysis' : 'Start AI Analysis'}
                </>
              )}
            </button>

            {loading && (
              <div className="tm-analysis-tip">
                <Brain size={16} />
                <span>
                  {useEnhancedAnalysis && gitUrl 
                    ? "Analyzing ACTUAL code from repository - this provides 80% better accuracy than generic analysis" 
                    : "This may take 40-55 seconds as our AI analyzes your tech stack..."}
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
  return (
    <div className="threat-modeling-container">
      <div className="tm-header">
        <div className="tm-header-content">
          <Brain size={36} className="tm-logo" />
          <div>
            <h2>{systemInfo.appName} - Threat Model</h2>
            <p>{usingAI ? 'AI-generated security analysis' : 'Static security analysis'} and recommendations</p>
            {useEnhancedAnalysis && (
              <div className="tm-enhanced-badge">
                <Package size={14} />
                <span>Enhanced Analysis (Repomix + OSV)</span>
              </div>
            )}
          </div>
        </div>
        <div className="tm-header-actions">
          {renderAIStatus()}
          <button className="tm-btn-secondary" onClick={downloadReport}>
            <Download size={18} />
            Download Report
          </button>
        </div>
      </div>

      {realityCheck && (
        <div className="tm-reality-check">
          <AlertOctagon size={24} />
          <div>
            <h3>Reality Check</h3>
            <p>{realityCheck}</p>
          </div>
        </div>
      )}

      <div className="tm-dashboard">
        <div className="tm-stat-card critical">
          <AlertTriangle size={28} />
          <div>
            <h3>{threats.filter(t => t.severity === 'critical').length}</h3>
            <p>Critical Threats</p>
          </div>
        </div>
        <div className="tm-stat-card high">
          <Shield size={28} />
          <div>
            <h3>{threats.filter(t => t.severity === 'high').length}</h3>
            <p>High Severity</p>
          </div>
        </div>
        <div className="tm-stat-card medium">
          <Target size={28} />
          <div>
            <h3>{threats.filter(t => t.severity === 'medium').length}</h3>
            <p>Medium Risk</p>
          </div>
        </div>
        <div className="tm-stat-card score">
          <TrendingUp size={28} />
          <div>
            <h3>{riskScore}/100</h3>
            <p>Risk Score</p>
          </div>
        </div>
        {useEnhancedAnalysis && analysisSummary && (
          <>
            <div className="tm-stat-card confirmed">
              <CheckCircle size={28} />
              <div>
                <h3>{analysisSummary.confirmedVulns}</h3>
                <p>Confirmed Vulns</p>
              </div>
            </div>
            <div className="tm-stat-card predicted">
              <Brain size={28} />
              <div>
                <h3>{analysisSummary.predictedVulns}</h3>
                <p>Predicted Vulns</p>
              </div>
            </div>
          </>
        )}
      </div>

      <div className="tm-ai-insight">
        <div className="tm-ai-header">
          <Brain size={24} />
          <h3>AI Security Insight</h3>
        </div>
        <p>{aiInsight}</p>
      </div>

      <div className="tm-filters">
        <div className="tm-search">
          <Search size={18} />
          <input
            type="text"
            placeholder="Search threats..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
        </select>
        <select value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)}>
          <option value="all">All Categories</option>
          {owaspCategories.map(cat => (
            <option key={cat} value={cat}>{cat}</option>
          ))}
          <option value="Non-OWASP">Non-OWASP Issues</option>
        </select>
        {useEnhancedAnalysis && (
          <select onChange={(e) => {
            if (e.target.value === 'confirmed') {
              setFilterCategory('all');
              setFilterSeverity('all');
              setSearchQuery('[CONFIRMED]');
            } else if (e.target.value === 'predicted') {
              setFilterCategory('all');
              setFilterSeverity('all');
              setSearchQuery('[PREDICTED]');
            }
          }}>
            <option value="">All Sources</option>
            <option value="confirmed">Confirmed Only</option>
            <option value="predicted">Predicted Only</option>
          </select>
        )}
      </div>

      <div className="tm-content-grid">
        <div className="tm-threats-panel">
          <h2>Identified Threats ({filteredThreats.length})</h2>
          {useEnhancedAnalysis && analysisSummary && (
            <div className="tm-analysis-summary">
              <div className="tm-summary-item">
                <strong>Confirmed Vulnerabilities:</strong> {analysisSummary.confirmedVulns}
              </div>
              <div className="tm-summary-item">
                <strong>AI Predictions:</strong> {analysisSummary.predictedVulns}
              </div>
              <div className="tm-summary-item">
                <strong>Tech Stack Match:</strong> {analysisSummary.techRealityMatch ? '✅ Matched' : '⚠️ Mismatch'}
              </div>
              <div className="tm-summary-item">
                <strong>Code Analysis:</strong> ✅ Actual code analyzed via Repomix
              </div>
            </div>
          )}
          <div className="tm-threats-list">
            {filteredThreats.map(threat => (
              <div key={threat.id} className="tm-threat-card">
                <div 
                  className="tm-threat-header"
                  onClick={() => toggleThreatExpand(threat.id)}
                  style={{ borderLeft: `4px solid ${getSeverityColor(threat.severity)}` }}
                >
                  <div className="tm-threat-title">
                    <div className="tm-threat-severity-badge" style={{ backgroundColor: getSeverityColor(threat.severity) }}>
                      {threat.severity.toUpperCase()}
                    </div>
                    <h3>{threat.title}</h3>
                    {threat.confirmed && (
                      <div className="tm-source-badge confirmed">
                        <CheckCircle size={12} />
                        <span>CONFIRMED</span>
                      </div>
                    )}
                    {!threat.confirmed && (
                      <div className="tm-source-badge predicted">
                        <Brain size={12} />
                        <span>PREDICTED</span>
                      </div>
                    )}
                  </div>
                  <div className="tm-threat-meta">
                    <span className="tm-threat-score">Risk: {threat.riskScore}/10</span>
                    {expandedThreats.includes(threat.id) ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
                  </div>
                </div>

                {expandedThreats.includes(threat.id) && (
                  <div className="tm-threat-details">
                    <div className="tm-threat-info">
                      <div className="tm-info-row">
                        <strong>Source:</strong> 
                        <span className={`tm-source ${threat.confirmed ? 'confirmed' : 'predicted'}`}>
                          {threat.source}
                        </span>
                      </div>
                      <div className="tm-info-row">
                        <strong>Category:</strong> {threat.category}
                      </div>
                      <div className="tm-info-row">
                        <strong>Component:</strong> {threat.component}
                      </div>
                      <div className="tm-info-row">
                        <strong>CWE:</strong> {threat.cwe}
                      </div>
                      <div className="tm-info-row">
                        <strong>STRIDE:</strong> {threat.stride}
                      </div>
                    </div>

                    <div className="tm-section">
                      <h4>Description</h4>
                      <p>{threat.description}</p>
                    </div>

                    <div className="tm-section">
                      <h4>Attack Vector</h4>
                      <p>{threat.attackVector}</p>
                    </div>

                    <div className="tm-section">
                      <h4>Impact Assessment</h4>
                      <div className="tm-impact-grid">
                        <div className="tm-impact-item">
                          <strong>Confidentiality:</strong>
                          <span className={`tm-impact-badge ${threat.impact.confidentiality.toLowerCase()}`}>
                            {threat.impact.confidentiality}
                          </span>
                        </div>
                        <div className="tm-impact-item">
                          <strong>Integrity:</strong>
                          <span className={`tm-impact-badge ${threat.impact.integrity.toLowerCase()}`}>
                            {threat.impact.integrity}
                          </span>
                        </div>
                        <div className="tm-impact-item">
                          <strong>Availability:</strong>
                          <span className={`tm-impact-badge ${threat.impact.availability.toLowerCase()}`}>
                            {threat.impact.availability}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="tm-section">
                      <h4>Affected Assets</h4>
                      <div className="tm-tags">
                        {threat.affectedAssets.map(asset => (
                          <span key={asset} className="tm-tag">{asset}</span>
                        ))}
                      </div>
                    </div>

                    <div className="tm-section">
                      <h4>Mitigation Strategies</h4>
                      <ul className="tm-mitigation-list">
                        {threat.mitigation.map((step, idx) => (
                          <li key={idx}>{step}</li>
                        ))}
                      </ul>
                    </div>

                    {threat.codeExample && (
                      <div className="tm-section">
                        <h4>Code Example</h4>
                        <div className="tm-code-examples">
                          <div className="tm-code-block vulnerable">
                            <div className="tm-code-header">
                              <XCircle size={16} />
                              <span>Vulnerable Code</span>
                              <button onClick={() => copyCode(threat.codeExample.vulnerable, `vuln-${threat.id}`)}>
                                {copiedCode === `vuln-${threat.id}` ? <Check size={16} /> : <Copy size={16} />}
                              </button>
                            </div>
                            <pre><code>{threat.codeExample.vulnerable}</code></pre>
                          </div>
                          <div className="tm-code-block secure">
                            <div className="tm-code-header">
                              <CheckCircle size={16} />
                              <span>Secure Code</span>
                              <button onClick={() => copyCode(threat.codeExample.secure, `secure-${threat.id}`)}>
                                {copiedCode === `secure-${threat.id}` ? <Check size={16} /> : <Copy size={16} />}
                              </button>
                            </div>
                            <pre><code>{threat.codeExample.secure}</code></pre>
                          </div>
                        </div>
                      </div>
                    )}

                    <div className="tm-section">
                      <h4>Testing Recommendations</h4>
                      <p>{threat.testing}</p>
                    </div>

                    <div className="tm-section">
                      <h4>References</h4>
                      <div className="tm-references">
                        {threat.references.map((ref, idx) => (
                          <a key={idx} href={ref} target="_blank" rel="noopener noreferrer">
                            <ExternalLink size={14} />
                            {ref.split('/').slice(-1)[0]}
                          </a>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="tm-sidebar">
          <div className="tm-checklist-card">
            <h3>
              <CheckCircle size={20} />
              Security Checklist
            </h3>
            <div className="tm-checklist-progress">
              <div className="tm-progress-bar">
                <div 
                  className="tm-progress-fill"
                  style={{ width: `${(checklist.filter(i => i.completed).length / checklist.length) * 100}%` }}
                />
              </div>
              <span>{checklist.filter(i => i.completed).length} / {checklist.length} completed</span>
            </div>
            <div className="tm-checklist">
              {checklist.map(item => (
                <div key={item.id} className="tm-checklist-item">
                  <input
                    type="checkbox"
                    checked={item.completed}
                    onChange={() => toggleChecklistItem(item.id)}
                  />
                  <span className={item.completed ? 'completed' : ''}>{item.text}</span>
                </div>
              ))}
            </div>
          </div>
          
          <div className="tm-chat-card">
            <h3>
              <MessageSquare size={20} />
              AI Assistant
            </h3>
            <div className="tm-chat-messages">
              {chatMessages.length === 0 ? (
                <p className="tm-chat-empty">Ask me anything about your security threats...</p>
              ) : (
                chatMessages.map((msg, idx) => (
                  <div key={idx} className={`tm-chat-message ${msg.role}`}>
                    <div className="tm-chat-content">
                      {msg.content}
                    </div>
                  </div>
                ))
              )}
            </div>
            <div className="tm-chat-input">
              <input
                type="text"
                placeholder="Ask a question..."
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleChat()}
              />
              <button onClick={handleChat} disabled={!chatInput.trim()}>
                <Send size={18} />
              </button>
            </div>
          </div>

          <div className="tm-stats-card">
            <h3>
              <BarChart3 size={20} />
              Quick Stats
            </h3>
            <div className="tm-stats-list">
              <div className="tm-stat-item">
                <span>Total Threats</span>
                <strong>{threats.length}</strong>
              </div>
              <div className="tm-stat-item">
                <span>Avg Risk Score</span>
                <strong>{(threats.reduce((sum, t) => sum + t.riskScore, 0) / threats.length).toFixed(1)}</strong>
              </div>
              <div className="tm-stat-item">
                <span>OWASP Categories</span>
                <strong>{new Set(threats.map(t => t.category)).size}</strong>
              </div>
              <div className="tm-stat-item">
                <span>Est. Fix Time</span>
                <strong>{threats.length * 2}h</strong>
              </div>
              {useEnhancedAnalysis && (
                <>
                  <div className="tm-stat-item">
                    <span>Confirmed Vulns</span>
                    <strong>{threats.filter(t => t.confirmed).length}</strong>
                  </div>
                  <div className="tm-stat-item">
                    <span>Predicted Vulns</span>
                    <strong>{threats.filter(t => !t.confirmed).length}</strong>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatModelingAssistant;