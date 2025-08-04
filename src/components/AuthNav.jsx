// components/AuthNav.jsx
function AuthNav({ page = "Login" }) {
  return (
    <nav className="auth-navbar">
      <div className="auth-brand">CyberShield</div>
      <div className="auth-page-title">{page}</div>
    </nav>
  );
}

export default AuthNav;



