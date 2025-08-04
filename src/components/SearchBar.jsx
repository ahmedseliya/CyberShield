import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { FaSearch } from "react-icons/fa";

function SearchBar() {
  const [query, setQuery] = useState("");
  const navigate = useNavigate();

  const handleSearch = (e) => {
    e.preventDefault();
    const lowerQuery = query.toLowerCase().trim();

    const routeMap = {
      "home": "/",
      "owasp": "/owasp",
      "glossary": "/glossary",
      "concepts": "/concepts",
      "simulations": "/simulations",
      "mitigation": "/mitigation",
      "quizzes": "/progress",
      "alerts": "/alerts",
      "socialengineering": "/social-engineering"
    };

    const match = Object.entries(routeMap).find(([key]) => key === lowerQuery);
    if (match) {
      navigate(match[1]);
      setQuery("");
    } else {
      alert(`No results for "${query}". Try something like: OWASP, Mitigation, Quizzes, etc.`);
    }
  };

  return (
    <form className="search-bar" onSubmit={handleSearch}>
      <input
        type="text"
        placeholder="Search sections..."
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      <button type="submit" className="search-icon">
        <FaSearch />
      </button>
    </form>
  );
}

export default SearchBar;
