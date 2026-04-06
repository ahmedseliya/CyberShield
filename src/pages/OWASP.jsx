import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  getFirestore, 
  doc, 
  getDoc, 
  setDoc, 
  updateDoc 
} from 'firebase/firestore';
import { getAuth, onAuthStateChanged } from 'firebase/auth';
import ThreatModelingAssistant from './ThreatModelingAssistant';
import OWASPAttackSimulator from './OWASPAttackSimulator';
import SecurityHeaderAnalyzer from './SecurityHeaderAnalyzer';

function OWASP() {
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [expandedExample, setExpandedExample] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [completedItems, setCompletedItems] = useState([]);
  const [viewedItems, setViewedItems] = useState({});
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showQuickAssessment, setShowQuickAssessment] = useState(false);
  const [assessmentScore, setAssessmentScore] = useState(null);
  const navigate = useNavigate();

  const db = getFirestore();
  const auth = getAuth();

  // Listen for auth state changes
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (user) => {
      setCurrentUser(user);
      if (user) {
        await loadUserProgress(user.uid);
      } else {
        setCompletedItems([]);
        setViewedItems({});
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  // Load user progress from Firestore
  const loadUserProgress = async (userId) => {
    try {
      const userProgressRef = doc(db, 'userProgress', userId);
      const userProgressSnap = await getDoc(userProgressRef);
      
      if (userProgressSnap.exists()) {
        const progressData = userProgressSnap.data();
        setCompletedItems(progressData.completedItems || []);
        setViewedItems(progressData.viewedItems || {});
      } else {
        setCompletedItems([]);
        setViewedItems({});
        await setDoc(userProgressRef, {
          completedItems: [],
          viewedItems: {},
          createdAt: new Date(),
          lastUpdated: new Date()
        });
      }
    } catch (error) {
      console.error('Error loading user progress:', error);
      setCompletedItems([]);
      setViewedItems({});
    }
  };

  // Save user progress to Firestore
  const saveUserProgress = async (newCompleted, newViewed) => {
    if (!currentUser) return;
    
    try {
      const userProgressRef = doc(db, 'userProgress', currentUser.uid);
      await updateDoc(userProgressRef, {
        completedItems: newCompleted,
        viewedItems: newViewed,
        lastUpdated: new Date()
      });
    } catch (error) {
      console.error('Error saving user progress:', error);
    }
  };

  // TryHackMe-style auto-completion detection
  useEffect(() => {
    let viewTimer;
    
    if (selectedVuln && expandedExample === selectedVuln && currentUser) {
      viewTimer = setTimeout(() => {
        if (!completedItems.includes(selectedVuln)) {
          const newCompleted = [...completedItems, selectedVuln];
          setCompletedItems(newCompleted);
          
          const newViewed = {
            ...viewedItems,
            [selectedVuln]: Date.now()
          };
          setViewedItems(newViewed);
          
          saveUserProgress(newCompleted, newViewed);
        }
      }, 5000);
    }

    return () => {
      if (viewTimer) clearTimeout(viewTimer);
    };
  }, [selectedVuln, expandedExample, completedItems, viewedItems, currentUser]);

  const owaspData = [
    {
      id: 1,
      title: "A01:2025 – Broken Access Control",
      severity: "Critical",
      description: "Flaws allowing attackers to bypass authorization, access unauthorized data, or perform restricted actions. Consolidates multiple access enforcement weaknesses including SSRF-style trust abuses. Affects 3.73% of tested applications on average with 40 associated CWEs.",
      types: [
        {
          name: "Vertical Privilege Escalation",
          explanation: "A user gains access to functionality they shouldn't have (e.g., regular user accessing admin functions)"
        },
        {
          name: "Horizontal Privilege Escalation", 
          explanation: "A user accesses resources belonging to another user at the same privilege level"
        },
        {
          name: "SSRF-based Access Bypass",
          explanation: "Server-side request forgery used to bypass access controls and access internal resources"
        }
      ],
      realExample: {
        scenario: "Facebook Access Token Breach (2018)",
        details: "Facebook had a bug where the 'View As' feature, designed to let users see how their profile appears to others, inadvertently generated access tokens for the accounts being viewed. Attackers could exploit this to access tokens for up to 50 million accounts, allowing them to take over these accounts completely. The vulnerability occurred because the access control system failed to properly validate permissions when generating these tokens, allowing unauthorized access to user accounts.",
        impact: "50+ million accounts compromised, complete account takeover possible",
        technical: "The bug was in the video uploader feature within 'View As' that incorrectly generated access tokens for the profile being viewed instead of the viewer, combined with insufficient access control validation."
      },
      detectionTools: [
        { 
          name: "Burp Suite Professional", 
          use: "Advanced access control testing with autorize extension to detect privilege escalation flaws and horizontal/vertical bypasses. Use the Proxy tab to capture requests, then modify user IDs or session tokens in the Repeater tab to test if the application properly validates access permissions."
        },
        { 
          name: "Postman with Auth Testing", 
          use: "Validate API authorization controls through automated token manipulation and role-based access testing. Create collections with requests using various user tokens to verify that each user can only access their authorized resources and functions."
        },
        { 
          name: "OWASP ZAP Access Control Testing", 
          use: "Automated access control scanner to identify forced browsing and insecure direct object references. Configure it as a proxy, browse the application normally, then run an Active Scan to detect authorization bypasses and session management flaws."
        }
      ]
    },
    {
      id: 2,
      title: "A02:2025 – Security Misconfiguration",
      severity: "High",
      description: "Risks caused by insecure defaults, exposed services, unnecessary features, or inconsistent security hardening across environments and cloud resources. Impacts 3.00% of applications due to growing configuration complexity.",
      types: [
        {
          name: "Default Configurations",
          explanation: "Using default passwords, settings, and configurations that are publicly known"
        },
        {
          name: "Cloud Misconfigurations",
          explanation: "Improperly configured cloud services (S3 buckets, databases, etc.)"
        },
        {
          name: "Server Misconfigurations",
          explanation: "Web servers, application servers with insecure settings"
        }
      ],
      realExample: {
        scenario: "Capital One Data Breach (2019)",
        details: "Capital One suffered a breach affecting 106 million customers due to a misconfigured Web Application Firewall (WAF) on Amazon Web Services. The attacker, a former AWS employee, exploited the misconfigured WAF to perform Server-Side Request Forgery (SSRF) attacks. The WAF was misconfigured to allow access to metadata services, which provided credentials to access S3 buckets containing customer data. The breach occurred because the WAF had overly permissive rules and the application had excessive privileges to access AWS services.",
        impact: "106 million customers affected, $190 million in fines and legal costs",
        technical: "Misconfigured WAF allowed SSRF attacks against AWS metadata service (169.254.169.254), which returned temporary security credentials that were then used to access S3 buckets containing customer data."
      },
      detectionTools: [
        { 
          name: "Nessus Professional", 
          use: "Comprehensive vulnerability scanning to detect exposed services, weak configurations, and cloud policy violations. Run credentialed scans to detect missing patches, weak passwords, unnecessary services, and policy violations."
        },
        { 
          name: "OpenVAS", 
          use: "Deep infrastructure scanning for misconfigurations, default credentials, and insecure component settings. Configure scan targets and credentials, then run comprehensive scans to identify system misconfigurations and security policy violations."
        },
        { 
          name: "CloudSploit", 
          use: "Cloud infrastructure security scanning for AWS, Azure, and GCP misconfigurations. Set up Config Rules to automatically evaluate cloud resources against security best practices, continuously monitoring permissions and settings."
        }
      ]
    },
    {
      id: 3,
      title: "A03:2025 – Software Supply Chain Failures",
      severity: "Critical",
      description: "Vulnerabilities introduced via third-party dependencies, CI/CD pipelines, build systems, and distribution mechanisms that compromise application integrity. Covers 5 CWEs with high exploit scores.",
      types: [
        {
          name: "Supply Chain Attacks",
          explanation: "Compromised components in the software supply chain"
        },
        {
          name: "Unsigned Updates",
          explanation: "Software updates without proper digital signatures"
        },
        {
          name: "CI/CD Pipeline Compromises",
          explanation: "Attacks targeting continuous integration and deployment systems"
        }
      ],
      realExample: {
        scenario: "SolarWinds Supply Chain Attack (2020)",
        details: "The SolarWinds attack was one of the most sophisticated supply chain attacks in history. Attackers compromised SolarWinds' Orion software build system and injected malicious code called 'SUNBURST' into legitimate software updates. The malicious code was digitally signed with SolarWinds' legitimate certificates, making it appear trustworthy. When approximately 18,000 customers installed the infected updates, the malware provided backdoor access to their networks. The attack went undetected for months because the malicious code was carefully designed to blend in with normal network traffic.",
        impact: "18,000+ organizations affected including US government agencies, months-long undetected access",
        technical: "Malicious code (SUNBURST) injected into SolarWinds.Orion.Core.BusinessLayer.dll, signed with legitimate certificates, used DNS for C2 communication to avoid detection."
      },
      detectionTools: [
        { 
          name: "Snyk", 
          use: "Continuous monitoring of dependencies for vulnerable or malicious packages with automated fix recommendations. Run 'snyk test' in your project directory to scan package.json/requirements.txt for vulnerable dependencies with fix suggestions."
        },
        { 
          name: "OWASP Dependency-Check", 
          use: "Identify known vulnerable libraries and components in project dependencies. Integrate into build pipelines with 'dependency-check --project MyApp --scan ./lib' to automatically identify vulnerable libraries and generate CVE reports."
        },
        { 
          name: "GitHub Advanced Security", 
          use: "Dependency review and code scanning to detect supply chain threats in pull requests. Automatically scans for vulnerable dependencies and creates pull requests with security updates."
        },
        { 
          name: "Sigstore", 
          use: "Verify software artifact authenticity and integrity through cryptographic signing. Use 'cosign sign' to digitally sign container images and software artifacts, providing cryptographic proof of authenticity."
        }
      ]
    },
    {
      id: 4,
      title: "A04:2025 – Cryptographic Failures",
      severity: "High",
      description: "Weak, misused, or outdated cryptographic protections leading to exposure of sensitive data or compromise of secure communications. Includes 32 CWEs, affecting 3.80% of applications.",
      types: [
        {
          name: "Data in Transit",
          explanation: "Unencrypted data transmitted over networks (HTTP instead of HTTPS, unencrypted APIs)"
        },
        {
          name: "Data at Rest",
          explanation: "Stored data without encryption (databases, files, backups stored in plaintext)"
        },
        {
          name: "Weak Cryptographic Algorithms",
          explanation: "Using outdated or weak encryption methods (MD5, SHA1, DES, weak SSL/TLS versions)"
        }
      ],
      realExample: {
        scenario: "Equifax Data Breach (2017)",
        details: "Equifax suffered a massive data breach affecting 147 million people. While the initial attack vector was a web application vulnerability (Apache Struts), the breach was exacerbated by cryptographic failures. Personal information including Social Security numbers, birth dates, addresses, and driver's license numbers were stored without adequate encryption. The company also failed to implement proper encryption for data in transit in some systems, and used outdated cryptographic protocols.",
        impact: "147 million people affected, $700+ million in fines and settlements",
        technical: "Sensitive data stored in plaintext or with weak encryption, inadequate key management, poor certificate management leading to man-in-the-middle possibilities."
      },
      detectionTools: [
        { 
          name: "testssl.sh", 
          use: "Comprehensive TLS/SSL evaluation including cipher suites, certificate validation, and protocol vulnerabilities. Execute './testssl.sh https://target.com' to perform extensive checks including cipher strength, protocol support, and vulnerability assessments."
        },
        { 
          name: "SSLyze", 
          use: "Fast and thorough SSL/TLS configuration analysis with support for modern security standards. Run 'sslyze --regular domain.com' to check for weak cipher suites, outdated TLS versions, and certificate issues."
        },
        { 
          name: "TLS Observatory", 
          use: "Monitor and validate TLS configurations across infrastructure for compliance. Provides detailed reports on cryptographic implementations and identifies weak encryption algorithms across multiple services."
        }
      ]
    },
    {
      id: 5,
      title: "A05:2025 – Injection",
      severity: "Critical",
      description: "Improper input handling enabling execution of malicious commands or queries such as SQL, OS command, or script injection. Associated with 38 CWEs and numerous CVEs.",
      types: [
        {
          name: "SQL Injection",
          explanation: "Malicious SQL code inserted into application queries to manipulate database operations"
        },
        {
          name: "Command Injection",
          explanation: "Execution of arbitrary commands on the host operating system via vulnerable applications"
        },
        {
          name: "NoSQL Injection",
          explanation: "Injection attacks targeting NoSQL databases like MongoDB"
        }
      ],
      realExample: {
        scenario: "TalkTalk SQL Injection Attack (2015)",
        details: "TalkTalk, a UK telecommunications company, suffered a SQL injection attack that compromised personal data of 4 million customers. The attackers exploited a basic SQL injection vulnerability in the company's website. They used simple SQL injection techniques to bypass authentication and extract customer data including names, addresses, phone numbers, email addresses, and in some cases, financial information.",
        impact: "4 million customers affected, £77 million total cost, significant reputational damage",
        technical: "The attackers used union-based SQL injection to extract data: ' UNION SELECT username, password FROM users-- which allowed them to dump entire database tables."
      },
      detectionTools: [
        { 
          name: "SQLMap", 
          use: "Automated detection and exploitation of SQL injection flaws with comprehensive database fingerprinting. Use 'sqlmap -u \"http://target.com/page?id=1\" --dbs' to detect and exploit SQL injection vulnerabilities, extract database schemas, and dump sensitive data."
        },
        { 
          name: "Burp Suite Scanner", 
          use: "Active scanning for injection vulnerabilities including SQL, NoSQL, and command injection. Capture requests, identify input parameters, then use payload lists with injection patterns to test each parameter systematically."
        },
        { 
          name: "NoSQLMap", 
          use: "Automated NoSQL injection testing for MongoDB and other document databases. Specialized tool for detecting and exploiting injection flaws in NoSQL databases."
        }
      ]
    },
    {
      id: 6,
      title: "A06:2025 – Insecure Design",
      severity: "High", 
      description: "Security weaknesses arising from flawed architectural decisions, missing controls, or inadequate threat modeling during system design. Shows industry improvements but remains critical.",
      types: [
        {
          name: "Threat Modeling Failures",
          explanation: "Not identifying and addressing potential threats during the design phase"
        },
        {
          name: "Business Logic Flaws",
          explanation: "Vulnerabilities in the application's business logic that can be exploited"
        },
        {
          name: "Architecture Security Flaws",
          explanation: "Fundamental security weaknesses in system architecture and design"
        }
      ],
      realExample: {
        scenario: "Zoom Security Design Issues (2020)",
        details: "During the COVID-19 pandemic, Zoom faced multiple security issues rooted in insecure design decisions. The most notable was 'Zoombombing' - uninvited participants joining meetings. This occurred because Zoom's original design prioritized ease of use over security. Meetings had simple, predictable IDs, default settings allowed anyone to join, and there were insufficient host controls. The design didn't anticipate the security implications of mass public usage.",
        impact: "Millions of disrupted meetings, privacy concerns, temporary bans by organizations",
        technical: "Sequential meeting IDs made brute force attacks feasible, insufficient access controls in meeting design, poor default security configurations."
      },
      detectionTools: [
        { 
          name: "Microsoft Threat Modeling Tool", 
          use: "Visual tool for creating threat models during design phase. Import system architecture diagrams, identify trust boundaries and data flows, then systematically analyze potential attack vectors using STRIDE methodology to uncover design-level security flaws."
        },
        { 
          name: "OWASP Threat Dragon", 
          use: "Web-based threat modeling platform. Create system diagrams, define components and data flows, then generate threat analyses. It helps identify design vulnerabilities before implementation by modeling potential attack scenarios."
        },
        { 
          name: "IriusRisk", 
          use: "Automated threat modeling and security requirements generation based on design decisions. Helps identify design-level security gaps before implementation."
        }
      ]
    },
    {
      id: 7,
      title: "A07:2025 – Authentication Failures",
      severity: "High",
      description: "Weaknesses in login mechanisms, credential handling, password policies, or session management enabling unauthorized account access. Covers 36 CWEs.",
      types: [
        {
          name: "Weak Password Policies",
          explanation: "Allowing weak passwords, no complexity requirements"
        },
        {
          name: "Session Management Issues",
          explanation: "Poor session handling, session fixation, inadequate timeouts"
        },
        {
          name: "Multi-factor Authentication Bypass",
          explanation: "Flaws in MFA implementation allowing bypass"
        }
      ],
      realExample: {
        scenario: "Twitter Bitcoin Scam (2020)",
        details: "In July 2020, Twitter suffered a major security breach where attackers took control of high-profile accounts including Barack Obama, Elon Musk, and Bill Gates to promote a Bitcoin scam. The attack was facilitated by social engineering Twitter employees, but was made worse by authentication failures in Twitter's internal tools. These tools had insufficient authentication controls - they relied primarily on basic login credentials without adequate multi-factor authentication.",
        impact: "130+ high-profile accounts compromised, significant reputational damage",
        technical: "Internal admin tools lacked proper authentication controls, no adequate MFA for administrative functions, insufficient access controls on account management systems."
      },
      detectionTools: [
        { 
          name: "Burp Intruder", 
          use: "Advanced brute force testing and authentication bypass technique validation. Configure payloads with common passwords or session tokens, then test login endpoints for brute force protection, session fixation, and authentication bypass vulnerabilities."
        },
        { 
          name: "Hydra", 
          use: "Password spraying and credential stuffing simulation against authentication endpoints. Use 'hydra -l admin -P passwords.txt http-post-form target.com' to perform brute force attacks against login forms, testing for weak passwords."
        },
        { 
          name: "JWT Tool", 
          use: "Test JSON Web Token implementations for signature validation and algorithm confusion flaws. Analyzes session tokens for security weaknesses."
        }
      ]
    },
    {
      id: 8,
      title: "A08:2025 – Software or Data Integrity Failures",
      severity: "High",
      description: "Failures to verify integrity of software updates, code, or critical data, allowing tampering, malicious modification, or unauthorized changes.",
      types: [
        {
          name: "Unsigned Software",
          explanation: "Lack of digital signatures on software updates and releases"
        },
        {
          name: "Tampered Data",
          explanation: "Data modified without detection due to missing integrity checks"
        },
        {
          name: "Build System Compromise",
          explanation: "Compromised build pipelines producing malicious artifacts"
        }
      ],
      realExample: {
        scenario: "Codecov Bash Uploader Compromise (2021)",
        details: "Attackers modified Codecov's Bash uploader script, which customers run to upload coverage reports. The modified script allowed exfiltration of environment variables, including credentials and tokens, from customer CI/CD environments. The integrity failure occurred because the script was distributed without proper integrity verification mechanisms, allowing customers to unknowingly download and execute the compromised version.",
        impact: "Hundreds of customer environments compromised, credentials and tokens exposed",
        technical: "The Bash uploader script was modified to exfiltrate environment variables to an attacker-controlled server, made possible by insufficient integrity checks on the distributed script."
      },
      detectionTools: [
        { 
          name: "in-toto", 
          use: "Verify software supply chain integrity through cryptographic attestations. Create metadata about each step in your build process, then verify the complete chain of custody from source to deployment."
        },
        { 
          name: "Grafeas", 
          use: "Store and query metadata about software artifacts including integrity proofs. Centralizes metadata storage for software components and their security properties."
        },
        { 
          name: "Code signing validation tools", 
          use: "Validate authenticity and integrity of artifacts, updates, and code packages. Implements digital signatures to verify software hasn't been tampered with."
        }
      ]
    },
    {
      id: 9,
      title: "A09:2025 – Logging & Alerting Failures",
      severity: "Medium",
      description: "Insufficient logging, monitoring, or alerting mechanisms that prevent timely detection and response to security incidents.",
      types: [
        {
          name: "Insufficient Logging",
          explanation: "Not logging critical security events and user activities"
        },
        {
          name: "Poor Log Management",
          explanation: "Logs not properly stored, protected, or analyzed"
        },
        {
          name: "No Real-time Monitoring",
          explanation: "Lack of real-time detection and alerting systems"
        }
      ],
      realExample: {
        scenario: "Marriott Data Breach (2018)",
        details: "Marriott announced that attackers had been in their Starwood guest reservation database since 2014 - four years before detection. The breach affected up to 500 million guests and included names, addresses, phone numbers, email addresses, passport numbers, and encrypted payment card information. The attackers maintained persistent access for years because Marriott had inadequate logging and monitoring systems.",
        impact: "500 million guests affected, $28 million in fines, 4-year undetected presence",
        technical: "Insufficient network monitoring, no detection of lateral movement, inadequate database activity logging, poor anomaly detection systems."
      },
      detectionTools: [
        { 
          name: "Wazuh", 
          use: "Centralized security monitoring with real-time alerting and compliance reporting. Deploy agents across your infrastructure to collect security events, configure rules for detecting threats, and generate real-time alerts."
        },
        { 
          name: "ELK Stack", 
          use: "Comprehensive log aggregation, analysis, and visualization for security events. Use Logstash to collect and parse logs, Elasticsearch to store and index them, and Kibana to create visualizations and dashboards."
        },
        { 
          name: "Splunk Enterprise Security", 
          use: "Advanced SIEM capabilities with threat intelligence integration and automated alerting. Configure data inputs to collect logs from all systems, create dashboards for monitoring, and set up alerts for suspicious activities."
        }
      ]
    },
    {
      id: 10,
      title: "A10:2025 – Mishandling of Exceptional Conditions",
      severity: "Medium",
      description: "Improper error handling, insecure failure states, or logical exception flaws that expose sensitive data or enable denial-of-service conditions. Includes 24 CWEs.",
      types: [
        {
          name: "Information Disclosure via Errors",
          explanation: "Error messages revealing sensitive system information"
        },
        {
          name: "Insecure Fallback States",
          explanation: "System entering insecure state when exceptions occur"
        },
        {
          name: "Denial of Service via Exceptions",
          explanation: "Exception flooding causing resource exhaustion"
        }
      ],
      realExample: {
        scenario: "GitHub DDoS via Exception Handling (2018)",
        details: "GitHub experienced a massive DDoS attack that peaked at 1.35 Tbps. The attack exploited how the application handled malformed requests. Poor exception handling caused the application to consume excessive resources when processing maliciously crafted requests, leading to resource exhaustion and service degradation.",
        impact: "Service disruption, performance degradation during attack",
        technical: "Exception handling flaws caused excessive resource consumption when processing malformed requests, leading to denial-of-service conditions."
      },
      detectionTools: [
        { 
          name: "Fuzzing frameworks (AFL, libFuzzer)", 
          use: "Trigger edge cases and exception paths to identify crash conditions and information disclosure. Automatically generate malformed inputs to test application error handling."
        },
        { 
          name: "Burp Suite Intruder with error analysis", 
          use: "Submit malformed inputs and analyze error responses for sensitive data exposure. Test exception handling by sending unexpected payloads and analyzing system responses."
        },
        { 
          name: "Custom error monitoring scripts", 
          use: "Inspect exception handling behavior across API endpoints and application components. Create automated tests that trigger exceptional conditions and verify secure handling."
        }
      ]
    }
  ];

  // Filter vulnerabilities based on severity and search
  const filteredVulns = owaspData.filter(vuln => {
    const matchesSeverity = filterSeverity === 'all' || vuln.severity.toLowerCase() === filterSeverity;
    const matchesSearch = vuln.title.toLowerCase().includes(searchTerm.toLowerCase()) || 
                         vuln.description.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  const toggleVulnerability = (id) => {
    setSelectedVuln(selectedVuln === id ? null : id);
    setExpandedExample(null);
  };

  const toggleExample = (id) => {
    setExpandedExample(expandedExample === id ? null : id);
  };

  const handleMitigation = (vulnTitle) => {
    navigate('/mitigation', { state: { vulnerability: vulnTitle } });
  };

  const handleSimulation = (vulnTitle) => {
    navigate('/simulations', { state: { vulnerability: vulnTitle } });
  };

  const calculateProgress = () => {
    return Math.round((completedItems.length / owaspData.length) * 100);
  };

  const runQuickAssessment = () => {
    setShowQuickAssessment(true);
    setAssessmentScore(null);
    
    // Real assessment based on actual completion and interaction
    const baseScore = Math.round((completedItems.length / owaspData.length) * 100);
    const interactionBonus = selectedVuln ? 10 : 0;
    const exampleBonus = expandedExample ? 5 : 0;
    
    const finalScore = Math.min(100, baseScore + interactionBonus + exampleBonus);
    
    setTimeout(() => {
      setAssessmentScore(finalScore);
    }, 2000);
  };

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading your security progress...</p>
      </div>
    );
  }

  return (
    <>
      <div className="owasp-header">
        <h1>OWASP Top 10 - 2025</h1>
        <p className="owasp-subtitle">
          The Open Web Application Security Project (OWASP) Top 10 is a standard awareness document 
          representing a broad consensus about the most critical security risks to web applications.
        </p>
        
        {/* Progress Tracker */}
        <div className="progress-section">
          <div className="progress-bar-container">
            <div className="progress-bar">
              <div 
                className="progress-fill" 
                style={{ width: `${calculateProgress()}%` }}
              ></div>
            </div>
            <span className="progress-text">{calculateProgress()}% Complete</span>
          </div>
          <button className="assessment-btn" onClick={runQuickAssessment}>
            🎯 Quick Assessment
          </button>
        </div>
      </div>

      {/* Filter and Search Controls */}
      <div className="controls-section">
        <div className="filter-controls">
          <input
            type="text"
            placeholder="🔍 Search vulnerabilities..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
          <select 
            value={filterSeverity} 
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="severity-filter"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
          </select>
        </div>
        
        {/* Stats Overview */}
        <div className="stats-overview">
          <div className="stat-item">
            <span className="stat-number">{filteredVulns.filter(v => v.severity === 'Critical').length}</span>
            <span className="stat-label">Critical</span>
          </div>
          <div className="stat-item">
            <span className="stat-number">{filteredVulns.filter(v => v.severity === 'High').length}</span>
            <span className="stat-label">High</span>
          </div>
          <div className="stat-item">
            <span className="stat-number">{filteredVulns.filter(v => v.severity === 'Medium').length}</span>
            <span className="stat-label">Medium</span>
          </div>
        </div>
      </div>

      {/* Quick Assessment Modal */}
      {showQuickAssessment && (
        <div className="assessment-modal">
          <div className="assessment-content">
            <h3>🎯 Security Knowledge Assessment</h3>
            {assessmentScore === null ? (
              <div className="assessment-loading">
                <div className="loading-spinner"></div>
                <p>Analyzing your progress...</p>
              </div>
            ) : (
              <div className="assessment-result">
                <div className="score-circle">
                  <span className="score">{assessmentScore}%</span>
                </div>
                <p className="assessment-text">
                  {assessmentScore >= 80 ? "🏆 Excellent! You're well-versed in OWASP vulnerabilities." :
                   assessmentScore >= 60 ? "👍 Good progress! Keep learning to improve your security knowledge." :
                   assessmentScore >= 40 ? "📚 You're on the right track. Focus on completing more vulnerabilities." :
                   "🎯 Great start! Explore more vulnerabilities to build your expertise."}
                </p>
                <div className="assessment-actions">
                  <button onClick={() => setShowQuickAssessment(false)}>Continue Learning</button>
                  <button onClick={() => navigate('/simulations')}>Practice Skills</button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

     
      <div className="owasp-grid">
        {filteredVulns.map((vuln) => (
          <div key={vuln.id} className={`owasp-card ${completedItems.includes(vuln.id) ? 'completed' : ''}`} data-vuln-id={vuln.id}>
            <div 
              className="owasp-card-header"
              onClick={() => toggleVulnerability(vuln.id)}
            >
              <div className="owasp-title-section">
                <div className="title-with-meta">
                  <h3>{vuln.title}</h3>
                </div>
                <div className="badges-section">
                  <span className={`severity-badge severity-${vuln.severity.toLowerCase()}`}>
                    {vuln.severity}
                  </span>
                  {completedItems.includes(vuln.id) && (
                    <span className="auto-completed-badge">✓ Completed</span>
                  )}
                </div>
              </div>
              <div className={`expand-icon ${selectedVuln === vuln.id ? 'expanded' : ''}`}>
                ▼
              </div>
            </div>

            {selectedVuln === vuln.id && (
              <div className="owasp-card-content">
                <div className="vulnerability-description">
                  <p>{vuln.description}</p>
                </div>

                {/* Detection Tools Section */}
                <div className="detection-tools">
                  <h4>🛠️ Detection Tools:</h4>
                  <div className="tools-list">
                    {vuln.detectionTools.map((tool, index) => (
                      <div key={index} className="tool-item">
                        <h5 className="tool-name">{tool.name}</h5>
                        <p className="tool-description">{tool.use}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="vulnerability-types">
                  <h4>Types & Variations:</h4>
                  <div className="types-grid">
                    {vuln.types.map((type, index) => (
                      <div key={index} className="type-card">
                        <h5>{type.name}</h5>
                        <p>{type.explanation}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="real-example-section">
                  <div 
                    className="example-header"
                    onClick={() => toggleExample(vuln.id)}
                  >
                    <h4>Real-World Example</h4>
                    <span className={`example-toggle ${expandedExample === vuln.id ? 'expanded' : ''}`}>
                      {expandedExample === vuln.id ? '−' : '+'}
                    </span>
                  </div>
                  
                  {expandedExample === vuln.id && (
                    <div className="example-content">
                      {!completedItems.includes(vuln.id) && (
                        <div className="completion-timer">
                          <div className="timer-bar">
                            <div className="timer-fill"></div>
                          </div>
                          <span className="timer-text">Reading... Auto-completing in 5s</span>
                        </div>
                      )}
                      <div className="example-scenario">
                        <h5>{vuln.realExample.scenario}</h5>
                        <p>{vuln.realExample.details}</p>
                      </div>
                      
                      <div className="example-details">
                        <div className="impact-box">
                          <h6>Impact:</h6>
                          <p>{vuln.realExample.impact}</p>
                        </div>
                        
                        <div className="technical-box">
                          <h6>Technical Details:</h6>
                          <p>{vuln.realExample.technical}</p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                <div className="action-buttons">
                  <button 
                    className="action-btn mitigation-btn"
                    onClick={() => handleMitigation(vuln.title)}
                  >
                    🛡️ Learn Mitigation
                  </button>
                  <button 
                    className="action-btn simulation-btn"
                    onClick={() => handleSimulation(vuln.title)}
                  >
                    🎯 Try Simulation
                  </button>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="owasp-footer">
        <div className="footer-stats">
          <div className="footer-stat">
            <span className="stat-value">{completedItems.length}/{owaspData.length}</span>
            <span className="stat-desc">Completed</span>
          </div>
          <div className="footer-stat">
            <span className="stat-value">2025</span>
            <span className="stat-desc">Latest Version</span>
          </div>
        </div>
        <p>
          Stay updated with the latest security practices and regularly assess your applications 
          against these vulnerabilities. Remember: security is an ongoing process, not a one-time fix.
        </p>
      </div>
       <SecurityHeaderAnalyzer />
       <ThreatModelingAssistant />
       <OWASPAttackSimulator />
    </>
  );
}

export default OWASP;