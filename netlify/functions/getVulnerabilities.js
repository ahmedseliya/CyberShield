const functions = require('@netlify/functions');
const admin = require('firebase-admin');
const serviceAccount = require('../../firebase-service-account.json'); // path from functions/

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();

exports.handler = async (event, context) => {
  try {
    const data = {
      title: 'Test Entry',
      description: 'This is a test vulnerability',
      createdAt: new Date().toISOString(),
    };

    await db.collection('vulnerabilities').add(data);

    return {
      statusCode: 200,
      body: JSON.stringify({ success: true }),
    };
  } catch (error) {
    console.error('Firestore Error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, error: error.message }),
    };
  }
};
