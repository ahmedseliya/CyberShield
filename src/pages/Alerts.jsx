import OWASPVulnerabilityFeed from './OWASPVulnerabilityFeed';

function Alerts() {
  return (
    <div className="page">
      <h2 style={{
        fontSize: '2.8rem',
        fontWeight: '700',
        color: '#1e293b',
        marginBottom: '0.75rem',
        textAlign: 'center',
        letterSpacing: '-0.02em',
        background: 'linear-gradient(135deg, #0f172a 0%, #334155 100%)',
        WebkitBackgroundClip: 'text',
        WebkitTextFillColor: 'transparent',
        backgroundClip: 'text'
      }}>Security Alerts</h2>
      
      <p style={{
        fontSize: '1.2rem',
        color: '#475569',
        textAlign: 'center',
        marginBottom: '2rem',
        maxWidth: '600px',
        marginLeft: 'auto',
        marginRight: 'auto',
        lineHeight: '1.6',
        fontWeight: '400'
      }}>Real-time CVE alerts with severity scoring and OWASP classification</p>
      
      <OWASPVulnerabilityFeed/>
    </div>
  );
}

export default Alerts;