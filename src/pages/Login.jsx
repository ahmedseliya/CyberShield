
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { FaUser, FaLock } from "react-icons/fa";
import { FiEye, FiEyeOff } from "react-icons/fi"; // 👁️ icons
import AuthNav from "../components/AuthNav";

function Login({ setIsLoggedIn }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false); // 👈 password toggle
  const navigate = useNavigate();

  const handleLogin = (e) => {
    e.preventDefault();
    if (username === "user" && password === "pass") {
      setIsLoggedIn(true);
      navigate("/");
    } else {
      alert("Invalid credentials. Try user/pass.");
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
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
              <i><FaUser /></i>
            </div>

            <div className="input-group">
              <input
                type={showPassword ? "text" : "password"}
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={password ? "has-value" : ""}
                required
              />
              <i><FaLock /></i>
              <span
                className="toggle-password"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? <FiEyeOff /> : <FiEye />}
              </span>
            </div>

            <button type="submit">Login</button>
          </form>
          <p>
            Don’t have an account? <Link to="/signup">Signup</Link>
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