const axios = require('axios');
const admin = require('firebase-admin');

// Initialize Firebase Admin SDK
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.applicationDefault(), // Make sure Netlify has access
    projectId: process.env.FIREBASE_PROJECT_ID
  });
}

const db = admin.firestore();

exports.handler = async function (event, context) {
  const VULNCHECK_API_KEY = process.env.VULNCHECK_API_KEY;

  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  };

  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: corsHeaders,
      body: 'OK'
    };
  }

  try {
    const response = await axios.get(
      "https://api.vulncheck.com/v3/index/nist-nvd2?size=100",
      {
        headers: {
          "Authorization": `Bearer ${VULNCHECK_API_KEY}`
        }
      }
    );

    for (const item of response.data.data || []) {
      const cveId = item.cve?.id;
      if (!cveId) continue;

      const description = item.cve?.descriptions?.find(d => d.lang === 'en')?.value || 'No description available';
      const severity = item.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || 'UNKNOWN';

      const existingDocs = await db
        .collection('vulnerabilities')
        .where('id', '==', cveId)
        .get();

      if (existingDocs.empty) {
        const tech = ['Node.js', 'React', 'PHP', 'Python', 'Java'].filter(
          t => description.toLowerCase().includes(t.toLowerCase())
        );

        const vulnDoc = {
          id: cveId,
          description,
          severity,
          category: 'N/A', // Will be categorized in frontend
          tech,
          timestamp: new Date(item.cve?.published || Date.now())
        };

        await db.collection('vulnerabilities').add(vulnDoc);
        console.log("Added new doc:", cveId);
      }
    }

    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify({ success: true })
    };

  } catch (error) {
    console.error('Function Error:', error.message);
    return {
      statusCode: error.response?.status || 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: "Failed to fetch or save vulnerabilities." })
    };
  }
};
