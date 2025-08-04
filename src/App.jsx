import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { useState, useEffect } from "react";

import Home from "./pages/Home";
import OWASP from "./pages/OWASP";
import Glossary from "./pages/Glossary";
import Mitigation from "./pages/Mitigation";
import Alerts from "./pages/Alerts";
import Progress from "./pages/Progress";
import Simulations from "./pages/Simulations";
import Concepts from "./pages/CyberConcepts";
import SocialEngineering from "./pages/SocialEngineering";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import SearchBar from "./components/SearchBar";
import NavBar from "./components/NavBar"; // 👈 We'll move navbar into its own file

function App() {
  const [theme, setTheme] = useState("light");
  const [isLoggedIn, setIsLoggedIn] = useState(() => {
    return localStorage.getItem("auth") === "true"; // ✅ Persist login across refresh
  });

  useEffect(() => {
    document.body.setAttribute("data-theme", theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === "light" ? "dark" : "light"));
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    localStorage.setItem("auth", "false");
  };

  // 🔒 Show only login/signup if not logged in
  if (!isLoggedIn) {
    return (
      <Router>
        <Routes>
          <Route path="/signup" element={<Signup />} />
          <Route
            path="*"
            element={<Login setIsLoggedIn={setIsLoggedIn} />}
          />
        </Routes>
      </Router>
    );
  }

  // ✅ Show app when logged in
  return (
    <Router>
      <NavBar handleLogout={handleLogout} toggleTheme={toggleTheme} theme={theme} />
      <SearchBar />

      <div className="page-container">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/owasp" element={<OWASP />} />
          <Route path="/glossary" element={<Glossary />} />
          <Route path="/concepts" element={<Concepts />} />
          <Route path="/social-engineering" element={<SocialEngineering />} />
          <Route path="/simulations" element={<Simulations />} />
          <Route path="/mitigation" element={<Mitigation />} />
          <Route path="/progress" element={<Progress />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
