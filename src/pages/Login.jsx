// Login.jsx
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { FaUser, FaLock, FaGoogle } from "react-icons/fa";
import { FiEye, FiEyeOff } from "react-icons/fi";
import { signInWithEmailAndPassword, sendPasswordResetEmail, sendEmailVerification, signInWithPopup, GoogleAuthProvider } from "firebase/auth";
import { doc, updateDoc, getDoc, setDoc } from "firebase/firestore";
import { auth, db } from "../firebaseConfig";
import AuthNav from "../components/AuthNav"; 
import { validateField, sanitizeInput } from "./validation";


function Login({ setIsLoggedIn }) {
  const [formData, setFormData] = useState({
    username: "",
    password: ""
  });
  const [errors, setErrors] = useState({});
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const navigate = useNavigate();

  // Custom rate limiting state
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [blockUntil, setBlockUntil] = useState(null);

  // Google Auth Provider
  const googleProvider = new GoogleAuthProvider();

  // Custom alert function
  const showRedAlert = (message) => {
    const alertBox = document.createElement('div');
    alertBox.className = 'custom-alert';
    alertBox.innerHTML = `
      <div class="alert-content">
        <span class="alert-message">${message}</span>
        <button class="alert-close">×</button>
      </div>
    `;
    document.body.appendChild(alertBox);

    // Add click event to close button
    const closeBtn = alertBox.querySelector('.alert-close');
    closeBtn.addEventListener('click', () => {
      alertBox.remove();
    });

    // Auto remove after 5 seconds
    setTimeout(() => {
      if (alertBox.parentElement) {
        alertBox.remove();
      }
    }, 5000);
  };

  // Check if user is temporarily blocked
  const isBlocked = () => {
    if (blockUntil && new Date() < blockUntil) {
      const secondsLeft = Math.ceil((blockUntil - new Date()) / 1000);
      showRedAlert(`⏳ Please wait ${secondsLeft} seconds before trying again.`);
      return true;
    }
    return false;
  };

  // ✅ ADDED: Check if username exists (same as in Signup.jsx)
  const checkUsernameExists = async (username) => {
    try {
      const userDoc = await getDoc(doc(db, "usernames", username.toLowerCase()));
      return userDoc.exists();
    } catch (error) {
      console.error("Error checking username:", error);
      return false;
    }
  };

  // ✅ FIXED: Google Sign In for Login
  const handleGoogleSignIn = async () => {
    setGoogleLoading(true);
    try {
      const result = await signInWithPopup(auth, googleProvider);
      const user = result.user;

      // ✅ FIRST check if user exists in Firestore
      const userDoc = await getDoc(doc(db, "users", user.uid));
      
      if (userDoc.exists()) {
        // ✅ User exists - update last login
        await updateDoc(doc(db, "users", user.uid), {
          lastLogin: new Date().toISOString()
        });
      } else {
        // ✅ User doesn't exist - create new user (first time login)
        console.log("🔄 Creating new user profile from login...");
        const username = user.displayName || user.email.split('@')[0];
        
        // Generate unique username if exists
        let finalUsername = username;
        let counter = 1;
        while (await checkUsernameExists(finalUsername)) {
          finalUsername = `${username}${counter}`;
          counter++;
        }

        const userData = {
          uid: user.uid,
          username: finalUsername,
          email: user.email,
          displayName: user.displayName,
          photoURL: user.photoURL,
          createdAt: new Date().toISOString(),
          lastLogin: new Date().toISOString(),
          isActive: true,
          emailVerified: user.emailVerified,
          provider: "google"
        };

        // Create user document
        await setDoc(doc(db, "users", user.uid), userData);
        
        // Store username mapping
        await setDoc(doc(db, "usernames", finalUsername.toLowerCase()), {
          uid: user.uid,
          createdAt: new Date().toISOString()
        });
        
        console.log("✅ New user created in Firestore from login");
      }

      // Set authentication state
      setIsLoggedIn(true);
      localStorage.setItem('isLoggedIn', 'true');
      localStorage.setItem('user', JSON.stringify({
        uid: user.uid,
        username: user.displayName || userDoc.data()?.username,
        email: user.email,
        photoURL: user.photoURL
      }));

      alert("✅ Login successful with Google!");
      navigate("/");

    } catch (error) {
      console.error("Google login error:", error);
      let errorMessage = "Google login failed. Please try again.";
      
      switch (error.code) {
        case 'auth/popup-closed-by-user':
          errorMessage = "Google login was cancelled.";
          break;
        case 'auth/popup-blocked':
          errorMessage = "Popup was blocked. Please allow popups for this site.";
          break;
        case 'auth/network-request-failed':
          errorMessage = "Network error. Please check your connection.";
          break;
        default:
          errorMessage = error.message;
      }
      
      alert(errorMessage);
    } finally {
      setGoogleLoading(false);
    }
  };

  const handleChange = (field, value) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
    
    // Real-time validation
    if (value.trim()) {
      const validation = validateField(field, value);
      if (!validation.isValid) {
        setErrors(prev => ({
          ...prev,
          [field]: validation.message
        }));
      } else {
        setErrors(prev => ({
          ...prev,
          [field]: ""
        }));
      }
    } else {
      setErrors(prev => ({
        ...prev,
        [field]: ""
      }));
    }
  };

  const handleForgotPassword = async () => {
  const email = prompt("Please enter your email address to reset your password:");
  
  if (!email) return;
  
  if (!email.includes('@') || !email.includes('.')) {
    showRedAlert("Please enter a valid email address.");
    return;
  }

  try {
    await sendPasswordResetEmail(auth, email);
    alert("📧 If an account exists with this email, you will receive password reset instructions in your inbox.");
  } catch (error) {
    console.error("Error sending reset email:", error);
    showRedAlert("There was an issue sending the reset email. Please try again.");
  }
};

  const findUserByUsername = async (username) => {
    try {
      // First, get the username mapping to find the user's UID
      const usernameDoc = await getDoc(doc(db, "usernames", username.toLowerCase()));
      
      if (usernameDoc.exists()) {
        const uid = usernameDoc.data().uid;
        
        // Then get the user document to get the email
        const userDoc = await getDoc(doc(db, "users", uid));
        
        if (userDoc.exists()) {
          return {
            uid: uid,
            email: userDoc.data().email
          };
        }
      }
      return null;
    } catch (error) {
      console.error("Error finding user:", error);
      return null;
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    
    // Check if temporarily blocked
    if (isBlocked()) {
      return;
    }

    setLoading(true);

    // Basic validation
    if (!formData.username.trim() || !formData.password.trim()) {
      showRedAlert("Please fill in all fields.");
      setLoading(false);
      return;
    }

    try {
      // Sanitize inputs
      const sanitizedUsername = sanitizeInput(formData.username);
      
      // Find user by username to get their email
      const userInfo = await findUserByUsername(sanitizedUsername);
      
      if (!userInfo) {
        // Increment failed attempts
        const newFailedAttempts = failedAttempts + 1;
        setFailedAttempts(newFailedAttempts);
        
        // Block for 30 seconds after 5 failed attempts
        if (newFailedAttempts >= 5) {
          const blockTime = new Date(Date.now() + 30000); // 30 seconds
          setBlockUntil(blockTime);
          showRedAlert("🔒 Too many failed attempts. Please try again in 30 seconds.");
        } else {
          showRedAlert("Invalid username or password.");
        }
        setLoading(false);
        return;
      }

      // Attempt login with email and password
      const userCredential = await signInWithEmailAndPassword(
        auth,
        userInfo.email,
        formData.password
      );

      const user = userCredential.user;

      // ✅ ADDED: Check if email is verified
      if (!user.emailVerified) {
        // Send verification email again
        await sendEmailVerification(user);
        alert("Please verify your email address before logging in.\n\n📧 We've sent a new verification email to your inbox.");
        
        // Sign them out since email isn't verified
        await auth.signOut();
        setLoading(false);
        return;
      }

      // Reset failed attempts on successful login
      setFailedAttempts(0);
      setBlockUntil(null);

      // Update last login timestamp
      await updateDoc(doc(db, "users", user.uid), {
        lastLogin: new Date().toISOString()
      });

      // Set authentication state
      setIsLoggedIn(true);
      
      // Store user info in localStorage if needed
      localStorage.setItem('isLoggedIn', 'true');
      localStorage.setItem('user', JSON.stringify({
        uid: user.uid,
        username: user.displayName,
        email: user.email
      }));

      alert("✅ Login successful!");
      navigate("/");

    } catch (error) {
      console.error("Login error:", error);
      
      // Increment failed attempts for Firebase errors too
      const newFailedAttempts = failedAttempts + 1;
      setFailedAttempts(newFailedAttempts);
      
      let errorMessage = "Login failed. Please try again.";
      
      switch (error.code) {
        case 'auth/user-not-found':
        case 'auth/wrong-password':
          errorMessage = "Invalid username or password.";
          // Block for 30 seconds after 5 failed attempts
          if (newFailedAttempts >= 5) {
            const blockTime = new Date(Date.now() + 30000); // 30 seconds
            setBlockUntil(blockTime);
            errorMessage = "🔒 Too many failed attempts. Please try again in 30 seconds.";
          }
          break;
        case 'auth/invalid-email':
          errorMessage = "Invalid credentials format.";
          break;
        case 'auth/too-many-requests':
          // Use our custom blocking instead of Firebase's long block
          const blockTime = new Date(Date.now() + 30000); // 30 seconds
          setBlockUntil(blockTime);
          errorMessage = "🔒 Too many failed attempts. Please try again in 30 seconds.";
          break;
        case 'auth/network-request-failed':
          errorMessage = "Network error. Please check your connection.";
          break;
        default:
          errorMessage = error.message;
      }
      
      showRedAlert(`❌ ${errorMessage}`);
      setErrors({});
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <AuthNav page="Login" />
      <div className="auth-wrapper">
        <div className="auth-left">
          <h2>Cyber Shield</h2>
          <form onSubmit={handleLogin}>
            <div className="input-group">
              <input
                type="text"
                placeholder="Username"
                value={formData.username}
                onChange={(e) => handleChange('username', e.target.value)}
                className={errors.username ? "error" : ""}
                required
                disabled={blockUntil && new Date() < blockUntil}
              />
              <i><FaUser /></i>
              {errors.username && <span className="error-message">{errors.username}</span>}
            </div>

            <div className="input-group">
              <input
                type={showPassword ? "text" : "password"}
                placeholder="Password"
                value={formData.password}
                onChange={(e) => handleChange('password', e.target.value)}
                className={`${errors.password ? "error" : ""} ${formData.password ? "has-value" : ""}`}
                required
                disabled={blockUntil && new Date() < blockUntil}
              />
              <i><FaLock /></i>
              <span
                className="toggle-password"
                onClick={() => setShowPassword(!showPassword)}
              >
               {showPassword ? <FiEye /> : <FiEyeOff />} 
              </span>
              {errors.password && <span className="error-message">{errors.password}</span>}
            </div>
 {/* ✅ ADDED: Google Sign In Button */}
          <div className="social-login">
            <button 
              type="button" 
              className="google-btn"
              onClick={handleGoogleSignIn}
              disabled={googleLoading}
            >
              <FaGoogle className="google-icon" />
              {googleLoading ? "Signing in..." : "Continue with Google"}
            </button>
            
            <div className="divider">
              <span>or</span>
            </div>
          </div>
            <button 
              type="submit" 
              disabled={loading || (blockUntil && new Date() < blockUntil)}
            >
              {loading ? "Logging in..." : "Login"}
            </button>
          </form>
          <p>
            Don't have an account? <Link to="/signup">Signup</Link>
          </p>
          <p style={{ marginTop: '-11px' }}>
            <Link to="#" onClick={handleForgotPassword}>Forgot Password?</Link>
          </p>
        </div>

        <div className="auth-right">
          <h2>LOGIN</h2>
          <p>Welcome back to Cyber Shield. Enter your credentials to continue.</p>
        </div>
      </div>
    </>
  );
}

export default Login;