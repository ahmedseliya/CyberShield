
import { Link } from "react-router-dom";
import {
  FaBug, FaShieldAlt, FaBrain,
  FaQuestionCircle, FaUserSecret,
  FaBook, FaLaptopCode, FaBell
} from "react-icons/fa";

function Home() {
  return (
    <div className="home-container">
      {/* Hero Section */}
      <section className="hero">
        <h1>
          Welcome to <span className="highlight">CyberShield</span>
        </h1>
        <p>
          Your interactive hub for mastering cybersecurity skills, vulnerabilities, and defense mechanisms.
        </p>
        <Link to="/owasp" className="cta-button">Start Learning</Link>
      </section>

      {/* Features Overview */}
      <section className="features">
        <h2>Explore Our Modules</h2>
        <div className="feature-grid">
          <Link to="/owasp" className="feature-card">
            <FaBug className="icon"/>
            <h3>OWASP Top 10</h3>
            <p>Learn the top web vulnerabilities with real-world attack & defense examples.</p>
          </Link>

          <Link to="/alerts" className="feature-card">
              <FaBell className="icon"/>
              <h3>Cyber Alerts</h3>
              <p>Stay informed with real-time updates about active threats and breaches.</p>
            </Link>

          <Link to="/progress" className="feature-card">
            <FaQuestionCircle className="icon"/>
            <h3>Quizzes</h3>
            <p>Test and reinforce your knowledge with interactive quizzes.</p>
          </Link>

          <Link to="/glossary" className="feature-card">
            <FaBook className="icon"/>
            <h3>Glossary</h3>
            <p>Quick reference to cybersecurity terms, jargon, and acronyms.</p>
          </Link>
        </div>
      </section>
      
      {/* Why CyberShield Section */}
<section className="why-cyber">
  <h2>Why CyberShield?</h2>
  <ul>
    <li>✅ Covers OWASP, Social Engineering, and Mitigation</li>
    <li>🧠 Learn, Test, and Simulate Real-World Attacks</li>
    <li>🔐 Constantly Updated With Latest Threat Intelligence</li>
    <li>📚 Built-in Glossary & Hands-on Labs</li>
    <li>🎯 Suitable for Students, Professionals, and Enthusiasts</li>
  </ul>
</section>

{/* Testimonials */}
<section className="testimonials">
  <h2>What Our Users Say</h2>
  <div className="testimonial-list">
    <blockquote>
      “CyberShield helped me understand OWASP in the simplest and most hands-on way.”
      <span>- Riya, Junior Pentester</span>
    </blockquote>
    <blockquote>
      “A great tool for our team’s internal upskilling program. Quizzes are top-notch.”
      <span>- Rajiv, Security Lead</span>
    </blockquote>
  </div>
</section>
    </div>
  );
}

export default Home;
