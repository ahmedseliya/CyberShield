import { NavLink } from "react-router-dom";

function NavBar({ toggleTheme, theme, handleLogout }) {
  return (
    <nav className="navbar">
      <h1 className="logo">CyberShield</h1>

      <ul className="nav-links">
        <li>
          <NavLink to="/" end className={({ isActive }) => isActive ? "nav-link active-link" : "nav-link"}>Home</NavLink>
        </li>
        <li>
          <NavLink to="/owasp" className={({ isActive }) => isActive ? "nav-link active-link" : "nav-link"}>OWASP</NavLink>
        </li>
        <li>
          <NavLink to="/glossary" className={({ isActive }) => isActive ? "nav-link active-link" : "nav-link"}>Glossary</NavLink>
        </li>
        <li>
          <NavLink to="/concepts" className={({ isActive }) => isActive ? "nav-link active-link" : "nav-link"}>Concepts</NavLink>
        </li>
        <li>
          <NavLink to="/social-engineering" className={({ isActive }) => isActive ? "nav-link active-link" : "nav-link"}>SE Attacks</NavLink>
        </li>
        <li>
          <NavLink to="/simulations" className={({ isActive }) => isActive ? "nav-link active-link" : "nav-link"}>Simulations</NavLink>
        </li>
        <li>
          <NavLink to="/mitigation" className={({ isActive }) => isActive ? "nav-link active-link" : "nav-link"}>Mitigation</NavLink>
        </li>
        <li>
          <NavLink to="/progress" className={({ isActive }) => isActive ? "nav-link active-link" : "nav-link"}>Quizzes</NavLink>
        </li>
        <li>
          <NavLink to="/alerts" className={({ isActive }) => isActive ? "nav-link active-link" : "nav-link"}>Alerts</NavLink>
        </li>
      </ul>

      <div className="theme-switcher">
  <button className="logout-btn" onClick={handleLogout}>
    Logout
  </button>
  <button className="theme-btn" onClick={toggleTheme}>
    {theme === "light" ? "🌞" : "🌙"}
  </button>
</div>

    </nav>
  );
}

export default NavBar;
