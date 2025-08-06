
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import OWASPVulnerabilityFeed from './OWASPVulnerabilityFeed'; // ✅ correct

function OWASP() {
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [expandedExample, setExpandedExample] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [completedItems, setCompletedItems] = useState(() => {
    const saved = localStorage.getItem('owasp-completed');
    return saved ? JSON.parse(saved) : [];
  });
  const [viewedItems, setViewedItems] = useState(() => {
    const saved = localStorage.getItem('owasp-viewed');
    return saved ? JSON.parse(saved) : {};
  });
  const [showQuickAssessment, setShowQuickAssessment] = useState(false);
  const [assessmentScore, setAssessmentScore] = useState(null);
  const navigate = useNavigate();

  // TryHackMe-style auto-completion detection
  useEffect(() => {
    let viewTimer;
    
    if (selectedVuln && expandedExample === selectedVuln) {
      viewTimer = setTimeout(() => {
        // Auto-complete after viewing example for 5 seconds
        if (!completedItems.includes(selectedVuln)) {
          const newCompleted = [...completedItems, selectedVuln];
          setCompletedItems(newCompleted);
          localStorage.setItem('owasp-completed', JSON.stringify(newCompleted));
          
          // Track viewing time
          const newViewed = {
            ...viewedItems,
            [selectedVuln]: Date.now()
          };
          setViewedItems(newViewed);
          localStorage.setItem('owasp-viewed', JSON.stringify(newViewed));
        }
      }, 5000);
    }

    return () => {
      if (viewTimer) clearTimeout(viewTimer);
    };
  }, [selectedVuln, expandedExample, completedItems, viewedItems]);
  

  const owaspData = [
    {
      id: 1,
      title: "A01 Broken Access Control",
      severity: "Critical",
      description: "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.",
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
          name: "Context-dependent Access Control",
          explanation: "Failing to check permissions based on application state or business logic"
        }
      ],
      realExample: {
        scenario: "Facebook Photo Privacy Breach (2018)",
        details: "Facebook had a bug where the 'View As' feature, designed to let users see how their profile appears to others, inadvertently generated access tokens for the accounts being viewed. Attackers could exploit this to access tokens for up to 50 million accounts, allowing them to take over these accounts completely. The vulnerability occurred because the access control system failed to properly validate permissions when generating these tokens, allowing unauthorized access to user accounts.",
        impact: "50+ million accounts compromised, complete account takeover possible",
        technical: "The bug was in the video uploader feature within 'View As' that incorrectly generated access tokens for the profile being viewed instead of the viewer."
      },
      detectionTools: [
        { 
          name: "Burp Suite", 
          use: "Intercepts HTTP requests and responses to manually test authorization controls. Use the Proxy tab to capture requests, then modify user IDs or session tokens in the Repeater tab to test if the application properly validates access permissions for different users."
        },
        { 
          name: "OWASP ZAP", 
          use: "Free security testing proxy that automatically scans for broken access control issues. Configure it as a proxy, browse the application normally, then run an Active Scan to detect authorization bypasses and session management flaws."
        },
        { 
          name: "Postman", 
          use: "API testing tool perfect for testing REST endpoints with different user credentials. Create collections with requests using various user tokens to verify that each user can only access their authorized resources and functions."
        }
      ]
    },
    {
      id: 2,
      title: "A02 Cryptographic Failures",
      severity: "High",
      description: "Previously known as Sensitive Data Exposure, this focuses on failures related to cryptography which often leads to sensitive data exposure or system compromise.",
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
        details: "Equifax suffered a massive data breach affecting 147 million people. While the initial attack vector was a web application vulnerability (Apache Struts), the breach was exacerbated by cryptographic failures. Personal information including Social Security numbers, birth dates, addresses, and driver's license numbers were stored without adequate encryption. The company also failed to implement proper encryption for data in transit in some systems, and used outdated cryptographic protocols in certain areas of their infrastructure.",
        impact: "147 million people affected, $700+ million in fines and settlements",
        technical: "Sensitive data stored in plaintext or with weak encryption, inadequate key management, poor certificate management leading to man-in-the-middle possibilities."
      },
      detectionTools: [
        { 
          name: "SSLyze", 
          use: "Python-based SSL/TLS scanner that analyzes server configurations. Run 'sslyze --regular domain.com' to check for weak cipher suites, outdated TLS versions, and certificate issues. It provides detailed reports on cryptographic implementations."
        },
        { 
          name: "testssl.sh", 
          use: "Comprehensive bash script for testing TLS/SSL encryption. Execute './testssl.sh https://target.com' to perform extensive checks including cipher strength, protocol support, and vulnerability assessments like Heartbleed and POODLE."
        },
        { 
          name: "Nmap SSL Scripts", 
          use: "Network scanner with specialized SSL testing capabilities. Use 'nmap --script ssl-enum-ciphers -p 443 target.com' to enumerate supported ciphers and identify weak encryption algorithms across multiple services."
        }
      ]
    },
    {
      id: 3,
      title: "A03 Injection",
      severity: "Critical",
      description: "Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.",
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
          name: "LDAP Injection",
          explanation: "Exploiting web applications that construct LDAP statements based on user input"
        },
        {
          name: "XPath Injection",
          explanation: "Injecting malicious XPath code to manipulate XML document queries"
        }
      ],
      realExample: {
        scenario: "TalkTalk SQL Injection Attack (2015)",
        details: "TalkTalk, a UK telecommunications company, suffered a SQL injection attack that compromised personal data of 4 million customers. The attackers exploited a basic SQL injection vulnerability in the company's website. They used simple SQL injection techniques to bypass authentication and extract customer data including names, addresses, phone numbers, email addresses, and in some cases, financial information. The attack was particularly damaging because it used elementary SQL injection methods that should have been easily prevented with basic security measures.",
        impact: "4 million customers affected, £77 million total cost, significant reputational damage",
        technical: "The attackers used union-based SQL injection to extract data: ' UNION SELECT username, password FROM users-- which allowed them to dump entire database tables."
      },
      detectionTools: [
        { 
          name: "SQLMap", 
          use: "Automated SQL injection testing tool. Use 'sqlmap -u \"http://target.com/page?id=1\" --dbs' to detect and exploit SQL injection vulnerabilities. It can automatically identify vulnerable parameters, extract database schemas, and dump sensitive data."
        },
        { 
          name: "Burp Suite", 
          use: "Manual injection testing through the Intruder module. Capture requests, identify input parameters, then use payload lists with SQL injection patterns to test each parameter systematically. The Scanner also automatically detects injection points."
        },
        { 
          name: "OWASP ZAP", 
          use: "Free alternative for injection testing. Use the Active Scanner to automatically test for SQL, XSS, and command injection. The Manual Request Editor allows for custom injection payload testing against specific parameters."
        }
      ]
    },
    {
      id: 4,
      title: "A04 Insecure Design",
      severity: "High", 
      description: "A new category focusing on risks related to design flaws. Insecure design cannot be fixed by a perfect implementation as the design itself is flawed. It represents missing or ineffective control design.",
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
        details: "During the COVID-19 pandemic, Zoom faced multiple security issues rooted in insecure design decisions. The most notable was 'Zoombombing' - uninvited participants joining meetings. This occurred because Zoom's original design prioritized ease of use over security. Meetings had simple, predictable IDs, default settings allowed anyone to join, and there were insufficient host controls. The design didn't anticipate the security implications of mass public usage. Additionally, Zoom's client was designed to prioritize connectivity over security, sometimes routing calls through Chinese servers even for non-Chinese users.",
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
          name: "Manual Architecture Review", 
          use: "Human-led security architecture assessment. Review system designs, data flow diagrams, and business logic workflows to identify missing security controls, weak trust boundaries, and flawed security assumptions in the overall design."
        }
      ]
    },
    {
      id: 5,
      title: "A05 Security Misconfiguration",
      severity: "High",
      description: "Security misconfiguration is commonly a result of insecure default configurations, incomplete configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information.",
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
        },
        {
          name: "Framework Misconfigurations",
          explanation: "Application frameworks with debug mode enabled in production"
        }
      ],
      realExample: {
        scenario: "Capital One Data Breach (2019)",
        details: "Capital One suffered a breach affecting 106 million customers due to a misconfigured Web Application Firewall (WAF) on Amazon Web Services. The attacker, a former AWS employee, exploited the misconfigured WAF to perform Server-Side Request Forgery (SSRF) attacks. The WAF was misconfigured to allow access to metadata services, which provided credentials to access S3 buckets containing customer data. The breach occurred because the WAF had overly permissive rules and the application had excessive privileges to access AWS services.",
        impact: "106 million customers affected, $190 million in fines and legal costs",
        technical: "Misconfigured WAF allowed SSRF attacks against AWS metadata service (169.254.169.254), which returned temporary security credentials that were then used to access S3 buckets."
      },
      detectionTools: [
        { 
          name: "Nessus", 
          use: "Commercial vulnerability scanner that identifies configuration issues across networks and systems. Run credentialed scans to detect missing patches, weak passwords, unnecessary services, and policy violations. Provides detailed remediation guidance for each finding."
        },
        { 
          name: "OpenVAS", 
          use: "Open-source vulnerability management solution. Configure scan targets and credentials, then run comprehensive scans to identify system misconfigurations, outdated software, and security policy violations. Generates detailed reports with risk ratings."
        },
        { 
          name: "AWS Config", 
          use: "Cloud configuration compliance service. Set up Config Rules to automatically evaluate AWS resources against security best practices. It continuously monitors S3 bucket permissions, security group settings, and IAM policies, alerting on misconfigurations."
        }
      ]
    },
    {
      id: 6,
      title: "A06 Vulnerable and Outdated Components",
      severity: "High",
      description: "Components run with the same privileges as the application itself, so flaws in any component can result in serious impact. Such flaws may be accidental or intentional.",
      types: [
        {
          name: "Outdated Libraries",
          explanation: "Using old versions of libraries with known vulnerabilities"
        },
        {
          name: "Unpatched Systems",
          explanation: "Operating systems and software not updated with security patches"
        },
        {
          name: "Third-party Dependencies",
          explanation: "Vulnerable components in the application's dependency chain"
        }
      ],
      realExample: {
        scenario: "Apache Struts RCE (Equifax 2017)",
        details: "The Equifax breach was initially caused by a vulnerability in Apache Struts (CVE-2017-5638), a popular web application framework. The vulnerability allowed remote code execution through malicious Content-Type headers in HTTP requests. Apache had released a patch for this vulnerability in March 2017, but Equifax failed to apply it promptly. The attackers exploited this unpatched component to gain initial access to Equifax's systems in May 2017. From there, they moved laterally through the network, eventually accessing databases containing sensitive personal information.",
        impact: "Initial attack vector for the massive Equifax breach affecting 147 million people",
        technical: "The vulnerability was in the Jakarta Multipart parser used by Struts. Malicious Content-Type headers like 'Content-Type: %{#context[\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\"].addHeader(\"X-Test\",\"Struts2\")}.multipart/form-data' could execute arbitrary code."
      },
      detectionTools: [
        { 
          name: "OWASP Dependency-Check", 
          use: "Free tool that scans project dependencies for known vulnerabilities. Integrate into build pipelines with 'dependency-check --project MyApp --scan ./lib' to automatically identify vulnerable libraries and generate reports with CVE details and remediation advice."
        },
        { 
          name: "Snyk", 
          use: "Commercial dependency vulnerability scanner. Install via npm 'npm install -g snyk', then run 'snyk test' in your project directory to scan package.json/requirements.txt for vulnerable dependencies. Provides fix suggestions and automated pull requests."
        },
        { 
          name: "GitHub Dependabot", 
          use: "Automated dependency update service. Enable in GitHub repository settings to automatically scan for vulnerable dependencies and create pull requests with security updates. Provides real-time alerts for newly discovered vulnerabilities in your dependencies."
        }
      ]
    },
    {
      id: 7,
      title: "A07 Identification and Authentication Failures",
      severity: "High",
      description: "Previously known as Broken Authentication, this includes flaws related to user identity confirmation, authentication, and session management.",
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
        },
        {
          name: "Credential Stuffing",
          explanation: "Lack of protection against automated credential testing attacks"
        }
      ],
      realExample: {
        scenario: "Twitter Bitcoin Scam (2020)",
        details: "In July 2020, Twitter suffered a major security breach where attackers took control of high-profile accounts including Barack Obama, Elon Musk, and Bill Gates to promote a Bitcoin scam. The attack was facilitated by social engineering Twitter employees, but was made worse by authentication failures in Twitter's internal tools. The attackers convinced Twitter employees to provide access to internal account management tools. These tools had insufficient authentication controls - they relied primarily on basic login credentials without adequate multi-factor authentication for such powerful administrative functions.",
        impact: "130+ high-profile accounts compromised, significant reputational damage, SEC investigation",
        technical: "Internal admin tools lacked proper authentication controls, no adequate MFA for administrative functions, insufficient access controls on account management systems."
      },
      detectionTools: [
        { 
          name: "Hydra", 
          use: "Network login cracker for testing password strength. Use 'hydra -l admin -P passwords.txt http-post-form target.com' to perform brute force attacks against login forms, testing for weak passwords and account lockout mechanisms."
        },
        { 
          name: "Burp Suite Intruder", 
          use: "Built-in tool for testing authentication mechanisms. Configure payloads with common passwords or session tokens, then test login endpoints for brute force protection, session fixation, and authentication bypass vulnerabilities."
        },
        { 
          name: "OWASP ZAP", 
          use: "Free proxy tool with authentication testing capabilities. Use the Active Scanner to test for session management issues, weak password policies, and authentication bypass vulnerabilities. The Session Management feature helps analyze session tokens."
        }
      ]
    },
    {
      id: 8,
      title: "A08 Software and Data Integrity Failures",
      severity: "High",
      description: "A new category focusing on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity.",
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
        details: "The SolarWinds attack was one of the most sophisticated supply chain attacks in history. Attackers compromised SolarWinds' Orion software build system and injected malicious code called 'SUNBURST' into legitimate software updates. The malicious code was digitally signed with SolarWinds' legitimate certificates, making it appear trustworthy. When approximately 18,000 customers installed the infected updates, the malware provided backdoor access to their networks. The attack went undetected for months because the malicious code was carefully designed to blend in with normal network traffic and included checks to avoid detection in security researcher environments.",
        impact: "18,000+ organizations affected including US government agencies, months-long undetected access",
        technical: "Malicious code (SUNBURST) injected into SolarWinds.Orion.Core.BusinessLayer.dll, signed with legitimate certificates, used DNS for C2 communication to avoid detection."
      },
      detectionTools: [
        { 
          name: "SLSA Framework", 
          use: "Supply chain security framework for verifying software integrity. Implement SLSA levels in your build process to ensure source code integrity, build reproducibility, and provenance tracking. Helps prevent supply chain tampering."
        },
        { 
          name: "Sigstore", 
          use: "Open-source software signing service. Use 'cosign sign' to digitally sign container images and software artifacts, providing cryptographic proof of authenticity. Verify signatures with 'cosign verify' before deployment to detect tampering."
        },
        { 
          name: "in-toto", 
          use: "Supply chain security framework that provides end-to-end verification of software supply chains. Create metadata about each step in your build process, then verify the complete chain of custody from source to deployment."
        }
      ]
    },
    {
      id: 9,
      title: "A09 Security Logging and Monitoring Failures",
      severity: "Medium",
      description: "Previously known as Insufficient Logging & Monitoring, this category helps detect, escalate, and respond to active breaches.",
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
        details: "Marriott announced that attackers had been in their Starwood guest reservation database since 2014 - four years before detection. The breach affected up to 500 million guests and included names, addresses, phone numbers, email addresses, passport numbers, and encrypted payment card information. The attackers maintained persistent access for years because Marriott had inadequate logging and monitoring systems. They couldn't detect the unauthorized access, data exfiltration activities, or the installation of remote access tools. The breach was only discovered when the attackers tried to encrypt the database, triggering security alerts.",
        impact: "500 million guests affected, $28 million in fines, 4-year undetected presence",
        technical: "Insufficient network monitoring, no detection of lateral movement, inadequate database activity logging, poor anomaly detection systems."
      },
      detectionTools: [
        { 
          name: "Splunk", 
          use: "Enterprise log management and SIEM platform. Configure data inputs to collect logs from all systems, create dashboards for monitoring security events, and set up alerts for suspicious activities like failed logins or unusual data access patterns."
        },
        { 
          name: "ELK Stack (Elasticsearch, Logstash, Kibana)", 
          use: "Open-source log analysis platform. Use Logstash to collect and parse logs, Elasticsearch to store and index them, and Kibana to create visualizations and dashboards for monitoring security events and investigating incidents."
        },
        { 
          name: "Wazuh", 
          use: "Open-source security monitoring platform. Deploy agents across your infrastructure to collect security events, configure rules for detecting threats like brute force attacks or malware, and generate real-time alerts for security incidents."
        }
      ]
    },
    {
      id: 10,
      title: "A10 Server-Side Request Forgery",
      severity: "Medium",
      description: "SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL, allowing attackers to coerce applications to send crafted requests.",
      types: [
        {
          name: "Regular SSRF",
          explanation: "Direct server-side requests to unintended locations"
        },
        {
          name: "Blind SSRF",
          explanation: "SSRF where no response is returned to the attacker"
        },
        {
          name: "Semi-Blind SSRF",
          explanation: "Limited response information available to the attacker"
        }
      ],
      realExample: {
        scenario: "Capital One AWS Metadata Attack (2019)",
        details: "As mentioned in the misconfiguration example, the Capital One breach also involved SSRF exploitation. The attacker used SSRF to access AWS metadata services. By exploiting the misconfigured WAF, they sent requests to 169.254.169.254 (AWS metadata service) which returned temporary security credentials. These credentials were then used to access over 700 S3 buckets containing customer data. The SSRF attack was possible because the application didn't properly validate URLs in user input, allowing requests to internal AWS services.",
        impact: "Part of the larger Capital One breach affecting 106 million customers",
        technical: "SSRF payload: GET http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name] retrieved AWS temporary credentials which were then used for unauthorized S3 access."
      },
      detectionTools: [
        { 
          name: "Burp Suite", 
          use: "Manual SSRF testing through the Repeater module. Intercept requests with URL parameters, modify them to point to internal services (127.0.0.1, 169.254.169.254), and analyze responses to detect SSRF vulnerabilities. Use Collaborator for blind SSRF detection."
        },
        { 
          name: "SSRFmap", 
          use: "Automated SSRF exploitation tool. Run 'python3 ssrfmap.py -r request.txt -p url' to automatically test URL parameters for SSRF vulnerabilities, including checks for cloud metadata services, internal network access, and file system access."
        },
        { 
          name: "Gopherus", 
          use: "Tool for generating payloads to exploit SSRF vulnerabilities. Create payloads for various protocols (HTTP, Gopher, Dict) to interact with internal services through SSRF, helping to demonstrate the impact of the vulnerability."
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

  return (
    <>
      <div className="owasp-header">
        <h1>OWASP Top 10 - 2021</h1>
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
            <span className="stat-value">2021</span>
            <span className="stat-desc">Latest Version</span>
          </div>
        </div>
        <p>
          Stay updated with the latest security practices and regularly assess your applications 
          against these vulnerabilities. Remember: security is an ongoing process, not a one-time fix.
        </p>
      </div>
       <OWASPVulnerabilityFeed />
    </>
  );
}

export default OWASP;