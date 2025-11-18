import React, { useState, useEffect } from 'react';
import { 
  Brain, Trophy, Target, Award, TrendingUp, 
  BookOpen, Zap, Shield, Code, Lock, Database,
  ChevronRight, Play, CheckCircle, XCircle, Clock,
  BarChart3, Layers, Search, Filter, Star
} from 'lucide-react';


function Progress() {
  const [activeTab, setActiveTab] = useState('quizzes');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedDifficulty, setSelectedDifficulty] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [userProgress, setUserProgress] = useState({
    totalQuizzes: 45,
    completed: 23,
    score: 78,
    streak: 5,
    badges: 8,
    rank: 'Security Analyst',
    xp: 2340
  });

  const categories = [
    { id: 'all', name: 'All Categories', icon: Layers, color: '#6366f1' },
    { id: 'network', name: 'Network Security', icon: Shield, color: '#3b82f6' },
    { id: 'web', name: 'Web Security', icon: Code, color: '#8b5cf6' },
    { id: 'crypto', name: 'Cryptography', icon: Lock, color: '#ec4899' },
    { id: 'threats', name: 'Threats & Attacks', icon: Target, color: '#ef4444' },
    { id: 'tools', name: 'Security Tools', icon: Database, color: '#10b981' },
    { id: 'compliance', name: 'Compliance', icon: BookOpen, color: '#f59e0b' }
  ];

  const quizzes = [
    {
      id: 1,
      title: 'SQL Injection Fundamentals',
      category: 'web',
      difficulty: 'intermediate',
      questions: 15,
      duration: 20,
      completed: true,
      score: 87,
      certification: 'CEH',
      threat: 'high',
      attempts: 2
    },
    {
      id: 2,
      title: 'Network Protocol Analysis',
      category: 'network',
      difficulty: 'advanced',
      questions: 20,
      duration: 30,
      completed: true,
      score: 92,
      certification: 'CISSP',
      threat: 'medium',
      attempts: 1
    },
    {
      id: 3,
      title: 'AES Encryption Basics',
      category: 'crypto',
      difficulty: 'beginner',
      questions: 10,
      duration: 15,
      completed: false,
      certification: 'Security+',
      threat: 'low'
    },
    {
      id: 4,
      title: 'Ransomware Attack Patterns',
      category: 'threats',
      difficulty: 'intermediate',
      questions: 18,
      duration: 25,
      completed: true,
      score: 75,
      certification: 'CEH',
      threat: 'critical',
      attempts: 3
    },
    {
      id: 5,
      title: 'Metasploit Framework',
      category: 'tools',
      difficulty: 'advanced',
      questions: 25,
      duration: 40,
      completed: false,
      certification: 'OSCP',
      threat: 'high'
    },
    {
      id: 6,
      title: 'GDPR Compliance Essentials',
      category: 'compliance',
      difficulty: 'intermediate',
      questions: 12,
      duration: 20,
      completed: true,
      score: 95,
      certification: 'CISM',
      threat: 'low',
      attempts: 1
    },
    {
      id: 7,
      title: 'XSS Attack Prevention',
      category: 'web',
      difficulty: 'intermediate',
      questions: 15,
      duration: 20,
      completed: false,
      certification: 'CEH',
      threat: 'high'
    },
    {
      id: 8,
      title: 'Firewall Configuration',
      category: 'network',
      difficulty: 'beginner',
      questions: 10,
      duration: 15,
      completed: true,
      score: 88,
      certification: 'Security+',
      threat: 'medium',
      attempts: 1
    }
  ];

  const achievements = [
    { id: 1, name: 'First Steps', icon: Star, unlocked: true, description: 'Complete your first quiz' },
    { id: 2, name: 'Perfect Score', icon: Trophy, unlocked: true, description: 'Score 100% on any quiz' },
    { id: 3, name: 'Week Warrior', icon: Zap, unlocked: true, description: '7-day learning streak' },
    { id: 4, name: 'Threat Hunter', icon: Target, unlocked: false, description: 'Complete all threat quizzes' },
    { id: 5, name: 'Crypto Master', icon: Lock, unlocked: false, description: 'Master cryptography category' },
    { id: 6, name: 'Tool Expert', icon: Database, unlocked: true, description: 'Complete 5 tool quizzes' }
  ];

  const recentActivity = [
    { quiz: 'GDPR Compliance Essentials', score: 95, date: '2 hours ago', category: 'compliance' },
    { quiz: 'Ransomware Attack Patterns', score: 75, date: '1 day ago', category: 'threats' },
    { quiz: 'Network Protocol Analysis', score: 92, date: '2 days ago', category: 'network' }
  ];

  const filteredQuizzes = quizzes.filter(quiz => {
    const matchesCategory = selectedCategory === 'all' || quiz.category === selectedCategory;
    const matchesDifficulty = selectedDifficulty === 'all' || quiz.difficulty === selectedDifficulty;
    const matchesSearch = quiz.title.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesCategory && matchesDifficulty && matchesSearch;
  });

  const getDifficultyColor = (difficulty) => {
    switch(difficulty) {
      case 'beginner': return '#10b981';
      case 'intermediate': return '#f59e0b';
      case 'advanced': return '#ef4444';
      default: return '#6b7280';
    }
  };

  const getThreatColor = (threat) => {
    switch(threat) {
      case 'critical': return '#dc2626';
      case 'high': return '#ef4444';
      case 'medium': return '#f59e0b';
      case 'low': return '#10b981';
      default: return '#6b7280';
    }
  };

  return (
    <div className="progress-page">
      {/* Header Section */}
      <div className="progress-header">
        <div className="header-content">
          <h1 className="page-title">
            <Brain className="title-icon" />
            Cybersecurity Quizzes & Progress
          </h1>
          <p className="page-subtitle">
            Test your knowledge, track your progress, and master cybersecurity concepts
          </p>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'linear-gradient(135deg, #6366f1, #8b5cf6)' }}>
            <Trophy />
          </div>
          <div className="stat-content">
            <h3>{userProgress.completed}/{userProgress.totalQuizzes}</h3>
            <p>Quizzes Completed</p>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'linear-gradient(135deg, #10b981, #059669)' }}>
            <Target />
          </div>
          <div className="stat-content">
            <h3>{userProgress.score}%</h3>
            <p>Average Score</p>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'linear-gradient(135deg, #f59e0b, #d97706)' }}>
            <Zap />
          </div>
          <div className="stat-content">
            <h3>{userProgress.streak} Days</h3>
            <p>Learning Streak</p>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'linear-gradient(135deg, #ec4899, #db2777)' }}>
            <Award />
          </div>
          <div className="stat-content">
            <h3>{userProgress.badges}</h3>
            <p>Badges Earned</p>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="nav-tabs">
        <button 
          className={`tab-btn ${activeTab === 'quizzes' ? 'active' : ''}`}
          onClick={() => setActiveTab('quizzes')}
        >
          <BookOpen size={18} />
          Available Quizzes
        </button>
        <button 
          className={`tab-btn ${activeTab === 'progress' ? 'active' : ''}`}
          onClick={() => setActiveTab('progress')}
        >
          <BarChart3 size={18} />
          My Progress
        </button>
        <button 
          className={`tab-btn ${activeTab === 'achievements' ? 'active' : ''}`}
          onClick={() => setActiveTab('achievements')}
        >
          <Award size={18} />
          Achievements
        </button>
      </div>

      {/* Quizzes Tab */}
      {activeTab === 'quizzes' && (
        <div className="quizzes-section">
          {/* Filters */}
          <div className="filters-container">
            <div className="search-box">
              <Search size={20} />
              <input 
                type="text" 
                placeholder="Search quizzes..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>

            <div className="filter-group">
              <Filter size={18} />
              <select 
                value={selectedDifficulty}
                onChange={(e) => setSelectedDifficulty(e.target.value)}
              >
                <option value="all">All Difficulties</option>
                <option value="beginner">Beginner</option>
                <option value="intermediate">Intermediate</option>
                <option value="advanced">Advanced</option>
              </select>
            </div>
          </div>

          {/* Category Pills */}
          <div className="category-pills">
            {categories.map(cat => {
              const Icon = cat.icon;
              return (
                <button
                  key={cat.id}
                  className={`category-pill ${selectedCategory === cat.id ? 'active' : ''}`}
                  onClick={() => setSelectedCategory(cat.id)}
                  style={selectedCategory === cat.id ? { 
                    background: `${cat.color}20`,
                    borderColor: cat.color,
                    color: cat.color 
                  } : {}}
                >
                  <Icon size={16} />
                  {cat.name}
                </button>
              );
            })}
          </div>

          {/* Quiz Cards */}
          <div className="quiz-grid">
            {filteredQuizzes.map(quiz => {
              const categoryData = categories.find(c => c.id === quiz.category);
              const Icon = categoryData?.icon || BookOpen;
              
              return (
                <div key={quiz.id} className="quiz-card">
                  {quiz.completed && (
                    <div className="completion-badge">
                      <CheckCircle size={16} />
                      Completed
                    </div>
                  )}
                  
                  <div className="quiz-header">
                    <div className="quiz-icon" style={{ background: `${categoryData?.color}20`, color: categoryData?.color }}>
                      <Icon size={24} />
                    </div>
                    <div className="threat-badge" style={{ background: `${getThreatColor(quiz.threat)}20`, color: getThreatColor(quiz.threat) }}>
                      {quiz.threat}
                    </div>
                  </div>

                  <h3 className="quiz-title">{quiz.title}</h3>
                  
                  <div className="quiz-meta">
                    <span className="meta-item">
                      <BookOpen size={14} />
                      {quiz.questions} questions
                    </span>
                    <span className="meta-item">
                      <Clock size={14} />
                      {quiz.duration} min
                    </span>
                  </div>

                  <div className="quiz-tags">
                    <span className="tag" style={{ background: `${getDifficultyColor(quiz.difficulty)}20`, color: getDifficultyColor(quiz.difficulty) }}>
                      {quiz.difficulty}
                    </span>
                    <span className="tag certification-tag">{quiz.certification}</span>
                  </div>

                  {quiz.completed && (
                    <div className="quiz-score">
                      <div className="score-bar">
                        <div className="score-fill" style={{ width: `${quiz.score}%`, background: quiz.score >= 80 ? '#10b981' : quiz.score >= 60 ? '#f59e0b' : '#ef4444' }}></div>
                      </div>
                      <span className="score-text">{quiz.score}% - {quiz.attempts} attempt(s)</span>
                    </div>
                  )}

                  <button className="quiz-btn">
                    <Play size={16} />
                    {quiz.completed ? 'Retake Quiz' : 'Start Quiz'}
                    <ChevronRight size={16} />
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Progress Tab */}
      {activeTab === 'progress' && (
        <div className="progress-section">
          <div className="progress-grid">
            {/* Rank Card */}
            <div className="progress-card rank-card">
              <h3>Your Rank</h3>
              <div className="rank-display">
                <Shield size={48} />
                <div>
                  <h2>{userProgress.rank}</h2>
                  <p>{userProgress.xp} XP</p>
                </div>
              </div>
              <div className="xp-progress">
                <div className="xp-bar">
                  <div className="xp-fill" style={{ width: '65%' }}></div>
                </div>
                <span>1660 XP to Security Expert</span>
              </div>
            </div>

            {/* Category Progress */}
            <div className="progress-card">
              <h3>Category Mastery</h3>
              <div className="category-progress-list">
                {categories.slice(1).map(cat => {
                  const Icon = cat.icon;
                  const progress = Math.floor(Math.random() * 100);
                  return (
                    <div key={cat.id} className="category-progress-item">
                      <div className="progress-header">
                        <Icon size={18} style={{ color: cat.color }} />
                        <span>{cat.name}</span>
                      </div>
                      <div className="progress-bar-container">
                        <div className="progress-bar">
                          <div className="progress-fill" style={{ width: `${progress}%`, background: cat.color }}></div>
                        </div>
                        <span className="progress-percent">{progress}%</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Recent Activity */}
            <div className="progress-card">
              <h3>Recent Activity</h3>
              <div className="activity-list">
                {recentActivity.map((activity, idx) => (
                  <div key={idx} className="activity-item">
                    <div className="activity-icon">
                      {activity.score >= 80 ? <CheckCircle size={20} /> : <XCircle size={20} />}
                    </div>
                    <div className="activity-content">
                      <h4>{activity.quiz}</h4>
                      <p>Score: {activity.score}% • {activity.date}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Achievements Tab */}
      {activeTab === 'achievements' && (
        <div className="achievements-section">
          <div className="achievements-grid">
            {achievements.map(achievement => {
              const Icon = achievement.icon;
              return (
                <div key={achievement.id} className={`achievement-card ${achievement.unlocked ? 'unlocked' : 'locked'}`}>
                  <div className="achievement-icon">
                    <Icon size={32} />
                  </div>
                  <h3>{achievement.name}</h3>
                  <p>{achievement.description}</p>
                  {achievement.unlocked && (
                    <div className="unlocked-badge">
                      <CheckCircle size={16} />
                      Unlocked
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

export default Progress;