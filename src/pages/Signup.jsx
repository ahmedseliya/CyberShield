import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { FaUser, FaLock, FaEnvelope } from "react-icons/fa";
import AuthNav from "../components/AuthNav";

function Signup({ setIsLoggedIn }) {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();

  const handleSignup = (e) => {
    e.preventDefault();

    if (username && email && password) {
      // Simulate success
      alert("Signup successful. Use your new credentials to log in.");
      navigate("/login");
    } else {
      alert("Please fill all fields.");
    }
  };

  return (
    <>
     <AuthNav page="Signup" /> 
      <div className="auth-wrapper">
        {/* Left Panel - Signup Form */}
        <div className="auth-left">
          <h2>Cyber Shield Signup</h2>
          <form onSubmit={handleSignup}>
            <div className="input-group">
              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
              <i><FaUser /></i>
            </div>

            <div className="input-group">
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
              <i><FaEnvelope /></i>
            </div>

            <div className="input-group">
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                   className={password ? "has-value" : ""}
                required
              />
              <i><FaLock /></i>
            </div>

            <button type="submit">Signup</button>
          </form>
          <p>
            Already have an account? <Link to="/login">Login</Link>
          </p>
        </div>

        {/* Right Panel - Welcome */}
        <div className="auth-right">
          <h2>JOIN CYBER SHIELD</h2>
          <p>Start protecting your digital identity with us. Sign up and stay secure!</p>
        </div>
      </div>
    </>
  );
}

export default Signup;
