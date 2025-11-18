// src/firebaseConfig.js
import { initializeApp } from "firebase/app";
import { getAuth } from 'firebase/auth';
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyBKnUIMEh4w-drmwNEx2nT_pRMLjR9m_gA",
  authDomain: "cybershield-40ca4.firebaseapp.com",
  databaseURL: "https://cybershield-40ca4-default-rtdb.firebaseio.com",
  projectId: "cybershield-40ca4",
  storageBucket: "cybershield-40ca4.appspot.com", // ✅ Corrected this line
  messagingSenderId: "572424733926",
  appId: "1:572424733926:web:107a91db893fb5d9e8a727"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// Export them - THIS IS WHAT YOU'RE MISSING
export { auth, db };
