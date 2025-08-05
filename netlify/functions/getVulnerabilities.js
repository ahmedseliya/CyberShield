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
    // OPTIONAL: Only for testing/demo: add a dummy entry each time
    /*
    const data = {
      title: 'Test Entry',
      description: 'This is a test vulnerability',
      createdAt: new Date().toISOString(),
    };

    await db.collection('vulnerabilities').add(data);
    */

    // ✅ FETCH data from Firestore
    const snapshot = await db.collection('vulnerabilities').orderBy('createdAt', 'desc').get();
    const vulnerabilities = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
    }));

    return {
      statusCode: 200,
      body: JSON.stringify({ success: true, data: vulnerabilities }),
    };
  } catch (error) {
    console.error('Firestore Error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, error: error.message }),
    };
  }
};
