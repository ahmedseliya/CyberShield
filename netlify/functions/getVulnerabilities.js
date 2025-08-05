const axios = require('axios');
const { initializeApp } = require('firebase/app');
const { getFirestore, collection, query, where, getDocs, addDoc } = require('firebase/firestore');

// Initialize Firebase with environment variables from Netlify dashboard
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID
};
const app = initializeApp(firebaseConfig);
const db = getFirestore(app);

exports.handler = async function (event, context) {
  const VULNCHECK_API_KEY = process.env.VULNCHECK_API_KEY;

  // Always include these headers for CORS!
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  };

  // Handle browser "preflight" (OPTIONS) requests
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: corsHeaders,
      body: 'OK'
    };
  }

  try {
    // Fetch data from VulnCheck API
    const response = await axios.get(
      "https://api.vulncheck.com/v3/index/nist-nvd2?size=100",
      {
        headers: {
          "Authorization": `Bearer ${VULNCHECK_API_KEY}`
        }
      }
    );

    // Write to Firestore if not present
    for (const item of response.data.data || []) {
      const cveId = item.cve?.id;
      if (!cveId) continue;

      const description = item.cve?.descriptions?.find(d => d.lang === 'en')?.value || 'No description available';
      const q = query(collection(db, 'vulnerabilities'), where('id', '==', cveId));
      const snap = await getDocs(q);

      if (snap.empty) {
        // Add severity/tech/category logic as you wish
        const severity = item.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || 'UNKNOWN';
        const tech = ['Node.js', 'React', 'PHP', 'Python', 'Java'].filter(
          t => description.toLowerCase().includes(t.toLowerCase())
        );
        const vulnDoc = {
          id: cveId,
          description: description,
          severity: severity,
          category: 'N/A', // You can add category logic if needed
          tech,
          timestamp: new Date(item.cve?.published || Date.now())
        };
        await addDoc(collection(db, 'vulnerabilities'), vulnDoc);
      }
    }

    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify(response.data)
    };

  } catch (error) {
    console.error('Error fetching or saving vulnerabilities:', error);
    return {
      statusCode: error.response?.status || 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: "Failed to fetch or save vulnerabilities." })
    };
  }
};
