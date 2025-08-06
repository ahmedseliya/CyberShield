// netlify/functions/getVulnerabilities.js
const functions = require('@netlify/functions');
const admin = require('firebase-admin');
const fetch = require('node-fetch');

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
};

if (!admin.apps.length) {
  const sa = JSON.parse(Buffer.from(process.env.SERVICE_ACCOUNT, 'base64').toString('utf8'));
  admin.initializeApp({ credential: admin.credential.cert(sa) });
}
 
const db = admin.firestore();
const VULNCHECK_API_KEY = process.env.VULNCHECK_API_KEY;
const VULNCHECK_URL = 'https://api.vulncheck.com/v3/index'; // or other index endpoint

exports.handler = async (event, context) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: '' };
  }
  try {
    const res = await fetch(`${VULNCHECK_URL}?limit=50`, {
      headers: { Authorization: `Bearer ${VULNCHECK_API_KEY}`, Accept: 'application/json' },
    });
    if (!res.ok) throw new Error(`VulnCheck API Error: ${res.status} ${res.statusText}`);
    const json = await res.json();
    const items = json.data || [];
    const batch = db.batch();
    const coll = db.collection('vulnerabilities');
    items.forEach(item => {
      const id = item.id || item.cve_id || item.CVE;
      if (!id) return;
      batch.set(coll.doc(`cve-${id}`), {
        id,
        description: item.summary || item.description || '',
        severity: (item.cvss?.severity || item.severity)?.toUpperCase() || 'UNKNOWN',
        timestamp: new Date(item.date || item.published || Date.now()),
        tech: Array.isArray(item.products) ? item.products.map(p => typeof p === 'string' ? p : p.name).map(t=>t.toLowerCase()) : [],
      }, { merge: true });
    });
    await batch.commit();
    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify({ success: true, count: items.length }),
    };
  } catch (err) {
    console.error('Fetcher Error:', err);
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ success: false, error: err.message }),
    };
  }
};
