const functions = require('@netlify/functions');
const admin = require('firebase-admin');
const fetch = require('node-fetch');

// Decode Firebase service account
if (!admin.apps.length) {
  const serviceAccountJson = Buffer.from(process.env.SERVICE_ACCOUNT, 'base64').toString('utf8');
  const serviceAccount = JSON.parse(serviceAccountJson);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();

// New API Key for VulnCheck v3
const VULNCHECK_API_KEY = process.env.VULNCHECK_API_KEY;

// Updated VulnCheck v3 Endpoint (you may need to confirm this in your dashboard)
const VULNCHECK_URL = 'https://api.vulncheck.com/v3/vulnerabilities';

exports.handler = async (event, context) => {
  try {
    // Fetch vulnerabilities with updated headers and URL
    const res = await fetch(`${VULNCHECK_URL}?severity=HIGH,CRITICAL&limit=50`, {
      headers: {
        'Authorization': `Bearer ${VULNCHECK_API_KEY}`,
        'Accept': 'application/json'
      },
    });

    if (!res.ok) {
      throw new Error(`VulnCheck API Error: ${res.status} ${res.statusText}`);
    }

    const json = await res.json();
    const vulns = Array.isArray(json) ? json : json.data || [];

    const batch = db.batch();
    const coll = db.collection('vulnerabilities');

    for (const item of vulns) {
      const docId = `cve-${item.id || item.cve_id}`;
      const ref = coll.doc(docId);

      const data = {
        id: item.id || item.cve_id,
        description: item.description || '',
        severity: item.cvss?.severity?.toUpperCase() || item.severity?.toUpperCase() || 'UNKNOWN',
        timestamp: new Date(item.published || item.date || Date.now()),
        tech: item.products?.map(p => p.name?.toLowerCase()) || [],
      };

      batch.set(ref, data, { merge: true });
    }

    await batch.commit();

    return {
      statusCode: 200,
      body: JSON.stringify({ success: true, count: vulns.length }),
    };
  } catch (error) {
    console.error('Fetcher Error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, error: error.message }),
    };
  }
};
