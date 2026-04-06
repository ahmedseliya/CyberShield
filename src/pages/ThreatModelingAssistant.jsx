import React, { useState } from 'react';
import { Shield, Brain, AlertTriangle, CheckCircle, XCircle, Download, Loader, Send, Zap, Target, Lock, Database, Cloud, Code, FileText, BarChart3, TrendingUp, MessageSquare, Search, Filter, ChevronDown, ChevronRight, ExternalLink, Copy, Check, GitBranch, Package, AlertOctagon, FileCode } from 'lucide-react';

// ==================== STATIC THREATS (FALLBACK) ====================
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
    insight: generateFallbackInsight(threats, systemInfo),
    riskScore: calculateRiskScore(threats)
  };
};

const generateFallbackInsight = (threats, systemInfo) => {
  const criticalCount = threats.filter(t => t.severity === 'critical').length;
  const highCount = threats.filter(t => t.severity === 'high').length;
  const categories = [...new Set(threats.map(t => t.category))];
  
  return `🔍 STATIC ANALYSIS: Identified ${threats.length} potential security threats in your ${systemInfo.appType}. 
    
🚨 CRITICAL PRIORITY: ${criticalCount} threats require immediate attention, particularly ${threats[0]?.title} which has a risk score of ${threats[0]?.riskScore}/10. 

📊 Your application is most vulnerable to ${categories[0]} attacks. Based on your tech stack (${systemInfo.frontend[0]}, ${systemInfo.backend[0]}, ${systemInfo.database[0]}), I recommend implementing input validation and parameterized queries as the first line of defense.

⏱️ Estimated remediation time: ${Math.ceil(threats.length * 2)} hours. Priority order: ${criticalCount} critical → ${highCount} high severity issues. Implementation of top 3 recommendations will reduce your risk score by approximately 60%.`;
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

// ==================== MAIN COMPONENT ====================
const ThreatModelingAssistant = () => {
  const [step, setStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [scanType, setScanType] = useState('basic');
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
  const [analysisSummary, setAnalysisSummary] = useState(null);
  const [semgrepFindings, setSemgrepFindings] = useState([]);
  const [osvFindings, setOsvFindings] = useState([]);

  const API_BASE_URL = 'http://localhost:3001/api';

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
  setAnalysisSummary(null);
  
  try {
    let analysis;
    
    if (scanType === 'advanced' && gitUrl) {
      const response = await fetch(`${API_BASE_URL}/analyze-enhanced`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ systemInfo, gitUrl })
      });
      
      if (!response.ok) {
        throw new Error('Advanced scan failed');
      }
      
      const data = await response.json();
      
      if (data.success) {
        // CRITICAL FIX: Proper sorting function - critical first, then high, then medium, then low
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        
        const sortedThreats = (data.threats || []).sort((a, b) => {
          // Get order values, default to 999 if severity not found
          const orderA = severityOrder[a.severity?.toLowerCase()] ?? 999;
          const orderB = severityOrder[b.severity?.toLowerCase()] ?? 999;
          return orderA - orderB;
        });
        
        console.log('Sorted threats order:', sortedThreats.map(t => `${t.severity}: ${t.title}`)); // Debug log
        
        setThreats(sortedThreats);
        setAiInsight(data.aiInsight || 'Analysis completed');
        setRiskScore(data.riskScore || 50);
        setSemgrepFindings(data.semgrepData?.findings || []);
        setOsvFindings(data.osvResults?.vulnerabilities || []);
        generateChecklist(sortedThreats);
      } else {
        throw new Error(data.error || 'Analysis failed');
      }
      
    } else {
      const response = await fetch(`${API_BASE_URL}/analyze-basic`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ systemInfo })
      });
      
      if (response.ok) {
        analysis = await response.json();
        
        // CRITICAL FIX: Proper sorting function
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        
        const sortedThreats = (analysis.threats || []).sort((a, b) => {
          const orderA = severityOrder[a.severity?.toLowerCase()] ?? 999;
          const orderB = severityOrder[b.severity?.toLowerCase()] ?? 999;
          return orderA - orderB;
        });
        
        console.log('Sorted threats order:', sortedThreats.map(t => `${t.severity}: ${t.title}`)); // Debug log
        
        setThreats(sortedThreats);
        setAiInsight(analysis.insight);
        setRiskScore(analysis.riskScore);
        generateChecklist(sortedThreats);
      } else {
        throw new Error('Basic scan failed');
      }
    }
    
  } catch (error) {
    console.error('Analysis failed:', error);
    setUsingAI(false);
    
    const staticAnalysis = generateStaticThreats(systemInfo);
    
    // CRITICAL FIX: Proper sorting for static threats too
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    
    const sortedThreats = (staticAnalysis.threats || []).sort((a, b) => {
      const orderA = severityOrder[a.severity?.toLowerCase()] ?? 999;
      const orderB = severityOrder[b.severity?.toLowerCase()] ?? 999;
      return orderA - orderB;
    });
    
    setThreats(sortedThreats);
    setAiInsight(staticAnalysis.insight);
    setRiskScore(staticAnalysis.riskScore);
    generateChecklist(sortedThreats);
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
      const response = await fetch(`${API_BASE_URL}/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          message: chatInput, 
          systemInfo,
          threats: threats.slice(0, 10)
        })
      });
      
      if (response.ok) {
        const data = await response.json();
        setChatMessages(prev => [...prev, { 
          role: 'assistant', 
          content: data.response 
        }]);
      } else {
        throw new Error('Chat failed');
      }
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
Scan Type: ${scanType === 'advanced' ? 'Advanced Scan' : 'Basic Scan'}
Git Repository: ${gitUrl || 'Not provided'}
Generated: ${new Date().toLocaleString()}

${aiInsight}

IDENTIFIED THREATS
------------------
${threats.map((t, idx) => `
${idx + 1}. ${t.title} [${t.severity.toUpperCase()}] ${t.confirmed ? '[CONFIRMED]' : '[PREDICTED]'}
   Source: ${t.source}
   Risk Score: ${t.riskScore}/10
   Category: ${t.category}
   CWE: ${t.cwe}
   ${t.file ? `File: ${t.file}` : ''}
   ${t.line ? `Line: ${t.line}` : ''}
   
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
          <span>{scanType === 'advanced' ? 'Advanced Scan' : 'Basic Scan'}</span>
        </div>
      ) : (
        <div style={{ display: 'flex', alignItems: 'center', gap: '4.5px' }}>
          <Shield size={16} />
          <span>Static Analysis</span>
        </div>
      )}
    </div>
  );

  // STEP 1 UI
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

        <div className="tm-scan-selector">
          <button 
            className={`tm-scan-btn ${scanType === 'basic' ? 'active' : ''}`}
            onClick={() => setScanType('basic')}
          >
            <Zap size={20} />
            <div>
              <h3>Basic Scan</h3>
              <p>Quick analysis based on your tech stack and description</p>
            </div>
          </button>
          <button 
            className={`tm-scan-btn ${scanType === 'advanced' ? 'active' : ''}`}
            onClick={() => setScanType('advanced')}
          >
            <Package size={20} />
            <div>
              <h3>Advanced Scan</h3>
              <p>Deep analysis with actual code review and dependency checking</p>
            </div>
          </button>
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
                  placeholder={scanType === 'advanced' 
                    ? "Describe your application in detail including tech stack, features, and architecture..." 
                    : "Describe your application in plain English (required)..."}
                  value={systemInfo.description}
                  onChange={(e) => setSystemInfo({...systemInfo, description: e.target.value})}
                  rows={4}
                  required
                />
              </div>

              {scanType === 'advanced' && (
                <div className="tm-input-group">
                  <label>
                    <GitBranch size={16} style={{ marginRight: '8px', verticalAlign: 'middle' }} />
                    Git Repository URL
                  </label>
                  <input
                    type="text"
                    placeholder="https://github.com/user/repository"
                    value={gitUrl}
                    onChange={(e) => setGitUrl(e.target.value)}
                    required={scanType === 'advanced'}
                  />
                  <div className="tm-input-hint">
                    Provide a GitHub/GitLab URL for actual code analysis and dependency checking
                  </div>
                </div>
              )}
            </div>

            {scanType === 'basic' && (
              <>
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
              </>
            )}

            <button 
              className="tm-btn-primary tm-btn-large"
              onClick={() => setStep(2)}
              disabled={
                !systemInfo.appName || 
                !systemInfo.appType || 
                !systemInfo.description || 
                (scanType === 'basic' && systemInfo.backend.length === 0) ||
                (scanType === 'advanced' && !gitUrl)
              }
            >
              Continue to Analysis <ChevronRight size={20} />
            </button>
          </div>
        </div>
      </div>
    );
  }

  // STEP 2 UI
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
                {scanType === 'advanced' && gitUrl 
                  ? "AI is analyzing your ACTUAL codebase and checking for confirmed vulnerabilities..." 
                  : loading 
                    ? "AI is actively scanning your application..." 
                    : "Ready to analyze your application architecture"}
              </p>
              
              <div className="tm-progress-steps">
                {scanType === 'advanced' && gitUrl && (
                  <>
                    <div className={`tm-progress-step ${loading ? 'active' : ''}`}>
                      {loading ? <Loader className="spin" size={16} /> : <div className="tm-step-icon"><FileCode size={14} /></div>}
                      <span>Cloning repository</span>
                      {loading && <div className="tm-step-status">Using git...</div>}
                    </div>
                    <div className={`tm-progress-step ${loading ? 'active' : ''}`}>
                      {loading ? <Loader className="spin" size={16} /> : <div className="tm-step-icon"><Code size={14} /></div>}
                      <span>Running Semgrep scan</span>
                      {loading && <div className="tm-step-status">Analyzing code...</div>}
                    </div>
                    <div className={`tm-progress-step ${loading ? 'active' : ''}`}>
                      {loading ? <Loader className="spin" size={16} /> : <div className="tm-step-icon"><Package size={14} /></div>}
                      <span>Checking dependencies</span>
                      {loading && <div className="tm-step-status">OSV API...</div>}
                    </div>
                  </>
                )}
                <div className={`tm-progress-step ${loading ? 'active' : ''}`}>
                  {loading ? <Loader className="spin" size={16} /> : <div className="tm-step-icon">1</div>}
                  <span>Mapping attack surface</span>
                  {loading && <div className="tm-step-status">Processing...</div>}
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
                    {scanType === 'advanced' && gitUrl ? 'Advanced Analysis in Progress...' : 'AI Analysis in Progress...'}
                  </>
                ) : (
                  <>
                    <Zap size={20} />
                    {scanType === 'advanced' && gitUrl ? 'Start Advanced Analysis' : 'Start Analysis'}
                  </>
                )}
              </button>

              {loading && (
                <div className="tm-analysis-tip">
                  <Brain size={16} />
                  <span>
                    {scanType === 'advanced' && gitUrl 
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

  // STEP 3 UI (Results)
  return (
    <div className="threat-modeling-container">
      <div className="tm-header">
        <div className="tm-header-content">
          <Brain size={36} className="tm-logo" />
          <div>
            <h2>{systemInfo.appName} - Threat Model</h2>
            <p>
              {usingAI 
                ? scanType === 'advanced' ? 'Advanced security analysis with code review' : 'AI-generated security analysis'
                : 'Static security analysis'} 
              and recommendations
            </p>
            {scanType === 'advanced' && (
              <div className="tm-enhanced-badge">
                <Package size={14} />
                <span>Advanced Scan</span>
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
      </div>

      <div className="tm-ai-insight">
        <div className="tm-ai-header">
          <Brain size={24} />
          <h3>AI Security Insight</h3>
        </div>
        <p style={{ whiteSpace: 'pre-wrap' }}>{aiInsight}</p>
      </div>

      {scanType === 'advanced' && semgrepFindings.length > 0 && (
        <div className="tm-summary-stats" style={{ display: 'flex', gap: '16px', marginBottom: '20px', padding: '16px', background: '#f8fafc', borderRadius: '12px' }}>
          <div style={{ flex: 1, textAlign: 'center' }}>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#dc2626' }}>{semgrepFindings.length}</div>
            <div style={{ fontSize: '14px', color: '#666' }}>Code Vulnerabilities</div>
          </div>
          <div style={{ flex: 1, textAlign: 'center' }}>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#f59e0b' }}>{osvFindings.length}</div>
            <div style={{ fontSize: '14px', color: '#666' }}>Dependency Vulnerabilities</div>
          </div>
          <div style={{ flex: 1, textAlign: 'center' }}>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#2563eb' }}>{threats.length}</div>
            <div style={{ fontSize: '14px', color: '#666' }}>Total Issues</div>
          </div>
        </div>
      )}

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
          <option value="low">Low</option>
        </select>
        <select value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)}>
          <option value="all">All Categories</option>
          {owaspCategories.map(cat => (
            <option key={cat} value={cat}>{cat}</option>
          ))}
          <option value="Non-OWASP">Non-OWASP Issues</option>
        </select>
      </div>

      <div className="tm-content-grid">
        <div className="tm-threats-panel">
          <h2>Identified Threats ({filteredThreats.length})</h2>
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
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        marginLeft: 'auto',
                        marginRight: '16px',
                        fontSize: '12px',
                        fontWeight: 500,
                        whiteSpace: 'nowrap',
                        maxWidth: '180px',
                        flexShrink: 0
                      }}>
                        <CheckCircle size={12} color={
                          threat.source && threat.source.includes('OSV') 
                            ? '#8b5cf6'
                            : '#059669'
                        } />
                        <span style={{
                          color: threat.source && threat.source.includes('OSV') 
                            ? '#8b5cf6'
                            : threat.source && threat.source.includes('Code Analysis')
                              ? '#059669'
                              : '#0284c7'
                        }}>
                          {threat.source && threat.source.includes('OSV') 
                            ? 'Confirmed via OSV' 
                            : threat.source && threat.source.includes('Code Analysis')
                              ? 'Confirmed via Semgrep'
                              : 'Confirmed'}
                        </span>
                      </span>
                    )}
                    {!threat.confirmed && (
                      <span style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        marginLeft: 'auto',
                        marginRight: '16px',
                        fontSize: '12px',
                        fontWeight: 500,
                        whiteSpace: 'nowrap',
                        maxWidth: '180px',
                        flexShrink: 0
                      }}>
                        <Brain size={12} color="#6b7280" />
                        <span style={{ color: '#6b7280' }}>
                          Predicted
                        </span>
                      </span>
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
                      {threat.file && (
                        <div className="tm-info-row">
                          <strong>File:</strong> 
                          <span style={{ fontFamily: 'monospace', fontSize: '12px', background: '#f1f5f9', padding: '2px 6px', borderRadius: '4px' }}>
                            {threat.file}
                          </span>
                        </div>
                      )}
                      {threat.line && (
                        <div className="tm-info-row">
                          <strong>Line:</strong> {threat.line}
                        </div>
                      )}
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
                              {threat.file && (
                                <span style={{ 
                                  fontSize: '12px', 
                                  color: '#666',
                                  marginLeft: '8px',
                                  fontFamily: 'monospace',
                                  background: '#fee2e2',
                                  padding: '2px 6px',
                                  borderRadius: '4px'
                                }}>
                                  📁 {threat.file.includes('/') ? threat.file.split('/').pop() : threat.file}
                                  {threat.line && `:${threat.line}`}
                                </span>
                              )}
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
                              {threat.file && (
                                <span style={{ 
                                  fontSize: '12px', 
                                  color: '#666',
                                  marginLeft: '8px',
                                  fontFamily: 'monospace',
                                  background: '#dcfce7',
                                  padding: '2px 6px',
                                  borderRadius: '4px'
                                }}>
                                  📁 {threat.file.includes('/') ? threat.file.split('/').pop() : threat.file}
                                </span>
                              )}
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
            <div className="tm-checklist" style={{ maxHeight: '400px', overflowY: 'auto' }}>
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
              {scanType === 'advanced' && (
                <>
                  <div className="tm-stat-item">
                    <span>Code Issues</span>
                    <strong>{threats.filter(t => t.source && t.source.includes('Code Analysis')).length}</strong>
                  </div>
                  <div className="tm-stat-item">
                    <span>Dependency Issues</span>
                    <strong>{threats.filter(t => t.source && t.source.includes('OSV')).length}</strong>
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