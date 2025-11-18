// Signup.jsx
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { FaUser, FaLock, FaEnvelope, FaGoogle } from "react-icons/fa";
import { FiEye, FiEyeOff } from "react-icons/fi"; 
import { createUserWithEmailAndPassword, updateProfile, sendEmailVerification, signInWithPopup, GoogleAuthProvider } from "firebase/auth";
import { doc, setDoc, getDoc, updateDoc } from "firebase/firestore";
import { auth, db } from "../firebaseConfig";
import AuthNav from "../components/AuthNav";
import { validateField } from "./validation";

function Signup({ setIsLoggedIn }) {
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
    confirmPassword: ""
  });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false); 
  const [showConfirmPassword, setShowConfirmPassword] = useState(false); 
  const navigate = useNavigate();

  // Google Auth Provider
  const googleProvider = new GoogleAuthProvider();

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
    
    // Special check for confirm password
    if (field === 'password' && formData.confirmPassword) {
      if (value !== formData.confirmPassword) {
        setErrors(prev => ({
          ...prev,
          confirmPassword: "Passwords do not match."
        }));
      } else {
        setErrors(prev => ({
          ...prev,
          confirmPassword: ""
        }));
      }
    }
    
    if (field === 'confirmPassword' && formData.password) {
      if (value !== formData.password) {
        setErrors(prev => ({
          ...prev,
          confirmPassword: "Passwords do not match."
        }));
      } else {
        setErrors(prev => ({
          ...prev,
          confirmPassword: ""
        }));
      }
    }
  };

  const validateForm = () => {
    const newErrors = {};
    
    // Validate username
    const usernameValidation = validateField('username', formData.username);
    if (!usernameValidation.isValid) {
      newErrors.username = usernameValidation.message;
    }

    // Validate email
    const emailValidation = validateField('email', formData.email);
    if (!emailValidation.isValid) {
      newErrors.email = emailValidation.message;
    }

    // Validate password
    const passwordValidation = validateField('password', formData.password);
    if (!passwordValidation.isValid) {
      newErrors.password = passwordValidation.message;
    }

    // Validate confirm password
    if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = "Passwords do not match.";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const checkUsernameExists = async (username) => {
    try {
      const userDoc = await getDoc(doc(db, "usernames", username.toLowerCase()));
      return userDoc.exists();
    } catch (error) {
      console.error("Error checking username:", error);
      return false;
    }
  };

  // ✅ FIXED: Google Sign In - Auto login after signup
  const handleGoogleSignIn = async () => {
    setGoogleLoading(true);
    try {
      console.log("🔄 Starting Google signup...");
      
      // Step 1: Authenticate with Google
      const result = await signInWithPopup(auth, googleProvider);
      const user = result.user;
      console.log("✅ Google authentication successful:", user.email);

      // Step 2: Check if user exists in Firestore
      const userDoc = await getDoc(doc(db, "users", user.uid));
      
      if (!userDoc.exists()) {
        console.log("🔄 Creating new user profile...");
        // First time Google login - create user profile
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
        
        console.log("✅ New user created in Firestore");
      } else {
        console.log("ℹ️ User already exists, updating last login...");
        // Update last login for existing user
        await updateDoc(doc(db, "users", user.uid), {
          lastLogin: new Date().toISOString()
        });
      }

      // Step 3: Wait a moment for state to update properly
      await new Promise(resolve => setTimeout(resolve, 100));

      // Step 4: Set authentication state
      setIsLoggedIn(true);
      localStorage.setItem('isLoggedIn', 'true');
      localStorage.setItem('user', JSON.stringify({
        uid: user.uid,
        username: user.displayName || userDoc.data()?.username,
        email: user.email,
        photoURL: user.photoURL
      }));

      console.log("✅ Authentication state set successfully");

      // Step 5: Show success message and redirect
      alert("✅ Google signup successful! Welcome to Cyber Shield!");
      navigate("/");

    } catch (error) {
      console.error("❌ Google sign in error:", error);
      
      let errorMessage = "Google signup failed. Please try again.";
      
      switch (error.code) {
        case 'auth/popup-closed-by-user':
          errorMessage = "Google signup was cancelled.";
          break;
        case 'auth/popup-blocked':
          errorMessage = "Popup was blocked. Please allow popups for this site.";
          break;
        case 'auth/network-request-failed':
          errorMessage = "Network error. Please check your connection.";
          break;
        case 'auth/account-exists-with-different-credential':
          errorMessage = "An account already exists with this email. Please try logging in instead.";
          break;
        default:
          errorMessage = `Error: ${error.message}`;
      }
      
      alert(errorMessage);
    } finally {
      setGoogleLoading(false);
    }
  };

  const handleSignup = async (e) => {
    e.preventDefault();
    setLoading(true);

    if (!validateForm()) {
      setLoading(false);
      return;
    }

    try {
      // Check if username already exists
      const usernameExists = await checkUsernameExists(formData.username);
      if (usernameExists) {
        setErrors(prev => ({
          ...prev,
          username: "Username already taken. Please choose another one."
        }));
        setLoading(false);
        return;
      }

      // Create user in Firebase Auth
      const userCredential = await createUserWithEmailAndPassword(
        auth, 
        formData.email, 
        formData.password
      );
      
      const user = userCredential.user;

      // Update profile with username
      await updateProfile(user, {
        displayName: formData.username
      });

      // Send email verification
      await sendEmailVerification(user);
      
      // Store user data in Firestore
      const userData = {
        uid: user.uid,
        username: formData.username,
        email: formData.email,
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString(),
        isActive: true,
        emailVerified: false, // Track email verification status
        provider: "email" // Track signup method
      };

      // Create user document in 'users' collection
      await setDoc(doc(db, "users", user.uid), userData);

      // Store username mapping for uniqueness check
      await setDoc(doc(db, "usernames", formData.username.toLowerCase()), {
        uid: user.uid,
        createdAt: new Date().toISOString()
      });

      alert(`✅ Signup successful!\n\n📧 We've sent a verification email to ${formData.email}\n\nPlease check your inbox and verify your email address before logging in.`);
      navigate("/login");
      
    } catch (error) {
      console.error("Signup error:", error);
      let errorMessage = "Signup failed. Please try again.";
      
      switch (error.code) {
        case 'auth/email-already-in-use':
          errorMessage = "Email is already registered. Please use a different email or login.";
          break;
        case 'auth/weak-password':
          errorMessage = "Password is too weak. Please use a stronger password.";
          break;
        case 'auth/invalid-email':
          errorMessage = "Invalid email address format.";
          break;
        case 'auth/network-request-failed':
          errorMessage = "Network error. Please check your connection.";
          break;
        default:
          errorMessage = error.message;
      }
      
      alert(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <AuthNav page="Signup" />
      <div className="auth-wrapper">
        <div className="auth-left">
          <h2>Cyber Shield Signup</h2>
          <form onSubmit={handleSignup}>
            <div className="input-group">
              <input
                type="text"
                placeholder="Username"
                value={formData.username}
                onChange={(e) => handleChange('username', e.target.value)}
                className={errors.username ? "error" : ""}
                required
              />
              <i><FaUser /></i>
              {errors.username && <span className="error-message">{errors.username}</span>}
            </div>

            <div className="input-group">
              <input
                type="email"
                placeholder="Email"
                value={formData.email}
                onChange={(e) => handleChange('email', e.target.value)}
                className={errors.email ? "error" : ""}
                required
              />
              <i><FaEnvelope /></i>
              {errors.email && <span className="error-message">{errors.email}</span>}
            </div>

            <div className="input-group">
              <input
                type={showPassword ? "text" : "password"} 
                placeholder="Password"
                value={formData.password}
                onChange={(e) => handleChange('password', e.target.value)}
                className={`${errors.password ? "error" : ""} ${formData.password ? "has-value" : ""}`}
                required
              />
              <i><FaLock /></i>
              <span
                className="toggle-password"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? <FiEye  /> : <FiEyeOff />}    
              </span>
              {errors.password && <span className="error-message">{errors.password}</span>}
            </div>

            <div className="input-group">
              <input
                type={showConfirmPassword ? "text" : "password"}
                placeholder="Confirm Password"
                value={formData.confirmPassword}
                onChange={(e) => handleChange('confirmPassword', e.target.value)}
                className={`${errors.confirmPassword ? "error" : ""} ${formData.confirmPassword ? "has-value" : ""}`}
                required
              />
              <i><FaLock /></i>
              <span
                className="toggle-password"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              >
                {showConfirmPassword ? <FiEye /> : <FiEyeOff />}  
              </span>
              {errors.confirmPassword && <span className="error-message">{errors.confirmPassword}</span>}
            </div>
{/* ✅ Google Sign In Button */}
          <div className="social-login">
            <button 
              type="button" 
              className="google-btn"
              onClick={handleGoogleSignIn}
              disabled={googleLoading}
            >
              <FaGoogle className="google-icon" />
              {googleLoading ? "Signing up..." : "Continue with Google"}
            </button>
            
            <div className="divider">
              <span>or sign up with email</span>
            </div>
          </div>
            <button type="submit" disabled={loading}>
              {loading ? "Creating Account..." : "Signup with Email"}
            </button>
          </form>
          <p>
            Already have an account? <Link to="/login">Login</Link>
          </p>
        </div>

        <div className="auth-right">
          <h2>JOIN CYBER SHIELD</h2>
          <p>Start protecting your digital identity with us. Sign up and stay secure!</p>
        </div>
      </div>
    </>
  );
}

export default Signup;