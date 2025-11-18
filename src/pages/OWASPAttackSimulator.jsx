// OWASPAttackSimulator.js
import React, { useState, useEffect } from 'react';
import { db } from '../firebaseConfig';
import { collection, getDocs, doc, getDoc, setDoc } from 'firebase/firestore';
import { getAuth, onAuthStateChanged, signInWithEmailAndPassword, createUserWithEmailAndPassword } from 'firebase/auth';

const OWASPAttackSimulator = () => {
  const [currentScenario, setCurrentScenario] = useState(null);
  const [currentStep, setCurrentStep] = useState(0);
  const [role, setRole] = useState(null);
  const [gameHistory, setGameHistory] = useState([]);
  const [showExplanation, setShowExplanation] = useState(false);
  const [scenarios, setScenarios] = useState({});
  const [loading, setLoading] = useState(true);
  const [randomizedChoices, setRandomizedChoices] = useState([]);
  const [currentDay, setCurrentDay] = useState(1);
  const [nextRefreshTime, setNextRefreshTime] = useState(null);
  const [timeRemaining, setTimeRemaining] = useState('');
  const [user, setUser] = useState(null);
  const [userLoading, setUserLoading] = useState(true);
  const [completedRoles, setCompletedRoles] = useState({});
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showLogin, setShowLogin] = useState(false);

  // Initialize Auth
  const auth = getAuth();

  // Listen for auth state changes
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (user) => {
      setUser(user);
      if (user) {
        // Load user's completed roles
        const userCompletedRoles = await getCompletedRoles();
        setCompletedRoles(userCompletedRoles);
      }
      setUserLoading(false);
    });
    return unsubscribe;
  }, []);

  // Get completed roles from Firestore (user-based)
  const getCompletedRoles = async () => {
    if (!user) return {};
    
    try {
      const userDoc = await getDoc(doc(db, 'users', user.uid));
      return userDoc.exists() ? userDoc.data().completedRoles || {} : {};
    } catch (error) {
      console.error('Error getting completed roles:', error);
      return {};
    }
  };

  // Mark role as completed in Firestore
  const markRoleCompleted = async (scenarioKey, completedRole) => {
    if (!user) return;
    
    try {
      const completed = await getCompletedRoles();
      if (!completed[scenarioKey]) {
        completed[scenarioKey] = [];
      }
      if (!completed[scenarioKey].includes(completedRole)) {
        completed[scenarioKey].push(completedRole);
        
        // Update in Firestore
        await setDoc(doc(db, 'users', user.uid), {
          completedRoles: completed
        }, { merge: true });
        
        // Update local state
        setCompletedRoles(completed);
      }
    } catch (error) {
      console.error('Error marking role completed:', error);
    }
  };

  // Check if role is completed
  const isRoleCompleted = (scenarioKey, checkRole) => {
    return completedRoles[scenarioKey] && completedRoles[scenarioKey].includes(checkRole);
  };

  // Calculate next refresh time (next midnight)
  const calculateNextRefresh = () => {
    const now = new Date();
    const nextRefresh = new Date(now);
    nextRefresh.setDate(nextRefresh.getDate() + 1);
    nextRefresh.setHours(0, 0, 0, 0);
    return nextRefresh;
  };

  // Format time remaining
  const formatTimeRemaining = (diff) => {
    if (diff <= 0) {
      return '00:00:00';
    }
    
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((diff % (1000 * 60)) / 1000);
    
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
  };

  // Get current day based on user's start date - MODIFIED VERSION
 // Get current day based on user's start date - FIXED VERSION
const calculateCurrentDay = async () => {
  if (!user) return 1;
  
  try {
    const userDoc = await getDoc(doc(db, 'users', user.uid));
    
    if (userDoc.exists()) {
      const userData = userDoc.data();
      const startDate = userData.startDate;
      
      // If startDate exists, calculate days from start date
      if (startDate) {
        const start = new Date(startDate);
        const today = new Date();
        const diffTime = Math.abs(today - start);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        return diffDays;
      }
    }
    
    // New user - set start date to today
    const today = new Date().toDateString();
    await setDoc(doc(db, 'users', user.uid), {
      startDate: today,
      completedRoles: {}
    }, { merge: true });
    
    return 1; // Day 1 for new users
  } catch (error) {
    console.error('Error calculating current day:', error);
    return 1;
  }
};
  // Update timer every second
  useEffect(() => {
    if (!nextRefreshTime) return;

    const timer = setInterval(() => {
      const now = new Date();
      const diff = nextRefreshTime - now;
      
      // Update the time remaining display
      setTimeRemaining(formatTimeRemaining(diff));
    }, 1000);

    return () => clearInterval(timer);
  }, [nextRefreshTime]);

  // Fetch scenarios and setup day system
  useEffect(() => {
    const fetchScenarios = async () => {
      if (userLoading) return; // Wait for auth to resolve
      
      try {
        // Calculate current day based on user's start date
        const calculatedDay = user ? await calculateCurrentDay() : 1;
        
        // Check if we have stored scenarios
        const storedScenarios = localStorage.getItem('scenariosData');
        
        if (storedScenarios) {
          // Use stored scenarios
          setScenarios(JSON.parse(storedScenarios));
          setCurrentDay(calculatedDay);
          const refreshTime = calculateNextRefresh();
          setNextRefreshTime(refreshTime);
          setTimeRemaining(formatTimeRemaining(refreshTime - new Date()));
          setLoading(false);
        } else {
          // Fetch fresh data from Firestore
          const querySnapshot = await getDocs(collection(db, 'challenges'));
          const scenariosData = {};
          
          querySnapshot.forEach((doc) => {
            scenariosData[doc.id] = doc.data();
          });
          
          setScenarios(scenariosData);
          
          // Store in localStorage for performance
          localStorage.setItem('scenariosData', JSON.stringify(scenariosData));
          
          // Set current day based on user's progress
          setCurrentDay(calculatedDay);
          
          const refreshTime = calculateNextRefresh();
          setNextRefreshTime(refreshTime);
          setTimeRemaining(formatTimeRemaining(refreshTime - new Date()));
          setLoading(false);
        }
      } catch (error) {
        console.error('Error fetching scenarios:', error);
        setLoading(false);
      }
    };

    fetchScenarios();
  }, [user, userLoading]);

  // Function to get scenarios for current day (ALWAYS STARTS FROM LOWEST IDs)
  const getCurrentDayScenarios = () => {
    const sortedScenarios = getSortedScenarios();
    const totalScenarios = sortedScenarios.length;
    
    if (totalScenarios === 0) return [];
    
    const totalDays = Math.ceil(totalScenarios / 4);
    
    // Cycle through scenarios starting from lowest IDs
    const actualDay = ((currentDay - 1) % totalDays) + 1;
    
    const startIndex = (actualDay - 1) * 4;
    const dayScenarios = sortedScenarios.slice(startIndex, startIndex + 4);
    
    // Sort the 4 cards by OWASP category (A01, A02, A03, etc.) before displaying
    return dayScenarios.sort((a, b) => {
      const aCategory = a[1].vulnerability || '';
      const bCategory = b[1].vulnerability || '';
      return aCategory.localeCompare(bCategory);
    });
  };

  // Function to sort scenarios by ID (LOWEST FIRST)
  const getSortedScenarios = () => {
    const scenariosArray = Object.entries(scenarios);
    
    // Sort by ID, putting lowest IDs first
    return scenariosArray.sort((a, b) => {
      const aId = parseInt(a[1].id) || 9999;
      const bId = parseInt(b[1].id) || 9999;
      return aId - bId;
    });
  };

  // Function to shuffle array randomly (Fisher-Yates algorithm)
  const shuffleArray = (array) => {
    const shuffled = [...array];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
  };

  const startScenario = (scenarioKey, selectedRole) => {
    if (isRoleCompleted(scenarioKey, selectedRole)) return;
    
    setCurrentScenario(scenarioKey);
    setRole(selectedRole);
    setCurrentStep(0);
    setGameHistory([]);
    setShowExplanation(false);
    
    const scenario = scenarios[scenarioKey];
    if (scenario && scenario[selectedRole]) {
      const firstStepChoices = scenario[selectedRole].story[0]?.choices || [];
      setRandomizedChoices(shuffleArray(firstStepChoices));
    }
  };

  const makeChoice = (choice) => {
    const historyEntry = {
      step: currentStep,
      choice: choice.text,
      correct: choice.correct,
      feedback: choice.feedback
    };
    
    setGameHistory([...gameHistory, historyEntry]);
    setShowExplanation(true);
    
    if (choice.correct) {
      setTimeout(() => {
        setShowExplanation(false);
        if (choice.nextStep !== undefined) {
          setCurrentStep(choice.nextStep);
          const scenario = scenarios[currentScenario];
          if (scenario && scenario[role]) {
            const nextStepChoices = scenario[role].story[choice.nextStep]?.choices || [];
            setRandomizedChoices(shuffleArray(nextStepChoices));
          }
        }
      }, 3000);
    } else {
      setTimeout(() => {
        setShowExplanation(false);
      }, 3000);
    }
  };

  const resetGame = () => {
    setCurrentScenario(null);
    setCurrentStep(0);
    setRole(null);
    setGameHistory([]);
    setShowExplanation(false);
    setRandomizedChoices([]);
  };

  const handleLogin = async () => {
    try {
      await signInWithEmailAndPassword(auth, email, password);
      setShowLogin(false);
    } catch (error) {
      // If login fails, try to create new account
      try {
        await createUserWithEmailAndPassword(auth, email, password);
        setShowLogin(false);
      } catch (signUpError) {
        console.error('Authentication error:', signUpError);
        alert('Authentication failed. Please try again.');
      }
    }
  };

  const handleLogout = async () => {
    await auth.signOut();
    setCompletedRoles({});
  };

  const renderLoginSection = () => (
    <div className="login-section">
      <div className="login-card">
        <h3>🔐 Login to Continue Your Journey</h3>
        <p>Sign in to save your progress across all devices</p>
        <input 
          type="email" 
          placeholder="Email" 
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="login-input"
        />
        <input 
          type="password" 
          placeholder="Password" 
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="login-input"
        />
        <button onClick={handleLogin} className="login-btn">
          Login / Sign Up
        </button>
        <button onClick={() => setShowLogin(false)} className="back-btn">
          Back to Challenges
        </button>
      </div>
    </div>
  );

  const renderScenarioSelection = () => {
    if (loading) {
      return (
        <div className="scenario-selection">
          <h1 className="main-title">OWASP Attack Scenario Simulator</h1>
          <p>Loading challenges...</p>
        </div>
      );
    }

    const currentDayScenarios = getCurrentDayScenarios();

    return (
      <div className="scenario-selection">
        {/* Main Title Card - ONLY wraps the title section */}
        <div className="main-title-card">
          <h1 className="main-title">OWASP Attack Scenario Simulator</h1>
          <p className="subtitle">Choose your path: Attack or Defend</p>
        </div>
        
        {/* Daily Challenges Card */}
        <div className="daily-header">
          <div className="daily-title-section">
            <div className="daily-icon">📅</div>
            <div>
              <h3 className="daily-title">Daily Challenges: Day {currentDay}</h3>
              <p className="daily-subtitle">Complete today's 4 challenges</p>
            </div>
          </div>
          <div className="timer-section">
            <div className="timer-label">Next challenges in</div>
            <div className="timer">{timeRemaining}</div>
          </div>
        </div>
        
        {/* Scenarios Grid */}
        <div className="scenarios-grid">
          {currentDayScenarios.map(([key, scenario]) => (
            <div key={key} className="scenario-card">
              <div className="scenario-header">
                <h3>{scenario.title}</h3>
                <span className={`difficulty-badge ${scenario.difficulty.toLowerCase()}`}>
                  {scenario.difficulty}
                </span>
              </div>
              <p className="vulnerability-type">{scenario.vulnerability}</p>
              <p className="scenario-id">ID: {scenario.id}</p>
              
              <div className="role-buttons">
                <button 
                  className={`role-btn attacker-btn ${isRoleCompleted(key, 'attacker') ? 'disabled' : ''}`}
                  onClick={() => startScenario(key, 'attacker')}
                  disabled={isRoleCompleted(key, 'attacker')}
                >
                  {isRoleCompleted(key, 'attacker') ? '🎯 Completed' : '🎯 Play as Attacker'}
                </button>
                <button 
                  className={`role-btn defender-btn ${isRoleCompleted(key, 'defender') ? 'disabled' : ''}`}
                  onClick={() => startScenario(key, 'defender')}
                  disabled={isRoleCompleted(key, 'defender')}
                >
                  {isRoleCompleted(key, 'defender') ? '🛡️ Completed' : '🛡️ Play as Defender'}
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Show message if no scenarios for today */}
        {currentDayScenarios.length === 0 && (
          <div className="no-scenarios">
            <h3>🎉 All Challenges Completed! 🎉</h3>
            <p>You've finished all available challenges. Great job!</p>
            <div className="timer">
              Come back tomorrow for more challenges!
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderGameplay = () => {
    const scenario = scenarios[currentScenario];
    if (!scenario) return null;

    const roleData = scenario[role];
    const currentStory = roleData.story[currentStep];

    if (!currentStory) return null;

    const isComplete = currentStory.choices.length === 0;

    // Mark as completed when scenario is finished
    if (isComplete && !showExplanation) {
      markRoleCompleted(currentScenario, role);
    }

    return (
      <div className="gameplay-container">
        <div className="game-header">
          <div className="game-info">
            <h2>{scenario.title}</h2>
            <span className={`role-badge ${role}`}>
              {role === 'attacker' ? '🎯 Attacker' : '🛡️ Defender'}
            </span>
          </div>
          <div className="progress-display">
            Step {currentStep + 1} of {roleData.story.length}
          </div>
        </div>

        <div className="story-section">
          <p className="story-text">{currentStory.text}</p>
        </div>

        {!isComplete && !showExplanation && (
          <div className="choices-container">
            {randomizedChoices.map((choice, index) => (
              <button
                key={index}
                className="choice-btn"
                onClick={() => makeChoice(choice)}
              >
                {choice.text}
              </button>
            ))}
          </div>
        )}

        {showExplanation && gameHistory.length > 0 && (
          <div className={`explanation-box ${gameHistory[gameHistory.length - 1].correct ? 'correct' : 'incorrect'}`}>
            <h4>
              {gameHistory[gameHistory.length - 1].correct ? '✓ Correct! Moving to next step...' : '✗ Incorrect - Try Again'}
            </h4>
            <p>{gameHistory[gameHistory.length - 1].feedback}</p>
            {!gameHistory[gameHistory.length - 1].correct && (
              <p className="try-again">Please select the correct answer to continue.</p>
            )}
          </div>
        )}

        {isComplete && (
          <div className="completion-box">
            <h3>🎉 Scenario Complete!</h3>
            <p>You've successfully completed this {role === 'attacker' ? 'attack' : 'defense'} scenario.</p>
            <div className="completion-actions">
              <button className="action-btn primary" onClick={resetGame}>
                Back to Challenges
              </button>
            </div>
          </div>
        )}

        {gameHistory.length > 0 && (
          <div className="history-section">
            <h4>Your Journey</h4>
            {gameHistory.map((entry, index) => (
              <div key={index} className={`history-item ${entry.correct ? 'correct' : 'incorrect'}`}>
                <span className="history-choice">{entry.choice}</span>
                <span className="history-status">
                  {entry.correct ? '✓' : '✗'}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  if (showLogin) {
    return renderLoginSection();
  }

  return (
    <div className="security-scenario-simulator">
      {!currentScenario ? renderScenarioSelection() : renderGameplay()}
    </div>
  );
};

export default OWASPAttackSimulator;