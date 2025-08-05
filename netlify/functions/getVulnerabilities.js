const functions = require('@netlify/functions');
const admin = require('firebase-admin');

if (!admin.apps.length) {
  const serviceAccountJson = Buffer.from(process.env.SERVICE_ACCOUNT, 'base64').toString('utf8');
  const serviceAccount = JSON.parse(serviceAccountJson);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();

exports.handler = async (event, context) => {
  try {
    const data = {
      title: 'Test second',
      description: 'This is a second test vulnerability',
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
