import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Shield, Brain, CheckCircle, XCircle, Target, Clock, AlertCircle, RefreshCw, Home } from 'lucide-react';
import { auth, db } from '../firebaseConfig';
import { signInWithPopup, GoogleAuthProvider, signOut } from 'firebase/auth';
import { 
  doc, getDoc, setDoc, updateDoc, serverTimestamp,
  collection, query, where, getDocs, deleteDoc 
} from 'firebase/firestore';

const provider = new GoogleAuthProvider();

function Progress() {
  const [user, setUser] = useState(null);
  const [todayQuiz, setTodayQuiz] = useState(null);
  const [userAttempt, setUserAttempt] = useState(null);
  const [answers, setAnswers] = useState({});
  const [showResults, setShowResults] = useState(false);
  const [score, setScore] = useState(0);
  const [loading, setLoading] = useState(true);
  const [quizStatus, setQuizStatus] = useState('checking');
  const [userStats, setUserStats] = useState(null);
  const [currentQuizVersion, setCurrentQuizVersion] = useState(null);
  const [isCheckingNewQuiz, setIsCheckingNewQuiz] = useState(false);
  const [viewMode, setViewMode] = useState('quiz'); // 'quiz' or 'results'
  
  // Use ref to track if we're already loading
  const isLoadingRef = useRef(false);
  const checkIntervalRef = useRef(null);

  // Check authentication and load quiz
  useEffect(() => {
    const unsubscribe = auth.onAuthStateChanged(async (currentUser) => {
      setUser(currentUser);
      
      if (currentUser) {
        await loadUserData(currentUser);
      } else {
        setLoading(false);
      }
    });
    
    return () => {
      unsubscribe();
      if (checkIntervalRef.current) {
        clearInterval(checkIntervalRef.current);
      }
    };
  }, []);

  // Function to load user data
  const loadUserData = async (currentUser) => {
    if (isLoadingRef.current) return;
    
    isLoadingRef.current = true;
    setLoading(true);
    
    const today = new Date().toISOString().split('T')[0];
    
    try {
      console.log(`📅 Loading quiz for date: ${today}`);
      
      // 1. Load today's quiz
      const quizRef = doc(db, 'dailyQuizzes', today);
      const quizSnap = await getDoc(quizRef);
      
      if (!quizSnap.exists()) {
        console.log('❌ No quiz found for today');
        setQuizStatus('not_available');
        setLoading(false);
        isLoadingRef.current = false;
        return;
      }
      
      const quizData = quizSnap.data();
      console.log(`✅ Quiz found with ${quizData.questions?.length || 0} questions`);
      
      // Create a unique quiz version ID
      const quizGeneratedAt = quizData.generatedAt?.toDate?.() || quizData.generatedAt;
      const quizVersion = `${today}_${quizGeneratedAt ? quizGeneratedAt.getTime() : Date.now()}`;
      
      // Only update if version changed
      if (quizVersion !== currentQuizVersion) {
        setCurrentQuizVersion(quizVersion);
        setTodayQuiz(quizData);
      }
      
      // 2. Check if user already attempted THIS VERSION
      const userAttemptRef = doc(db, 'userAttempts', `${currentUser.uid}_${quizVersion}`);
      const userAttemptSnap = await getDoc(userAttemptRef);
      
      if (userAttemptSnap.exists()) {
        console.log('📝 User has already attempted this version');
        setUserAttempt(userAttemptSnap.data());
        setQuizStatus('completed');
        setViewMode('results'); // Show results by default if attempt exists
      } else {
        console.log('🆕 User has NOT attempted this quiz version yet');
        setQuizStatus('available');
        setViewMode('quiz'); // Show quiz by default if no attempt
      }
      
      // 3. Load user stats
      const userStatsRef = doc(db, 'users', currentUser.uid);
      const userStatsSnap = await getDoc(userStatsRef);
      
      if (userStatsSnap.exists()) {
        setUserStats(userStatsSnap.data());
      }
      
    } catch (error) {
      console.error('❌ Error loading data:', error);
      setQuizStatus('error');
    } finally {
      setLoading(false);
      isLoadingRef.current = false;
    }
  };

  // Function to check for new quiz - OPTIMIZED
  const checkForNewQuiz = useCallback(async (silent = false) => {
    if (!user || isLoadingRef.current) return;
    
    if (!silent) {
      setIsCheckingNewQuiz(true);
    }
    
    const today = new Date().toISOString().split('T')[0];
    const quizRef = doc(db, 'dailyQuizzes', today);
    
    try {
      const quizSnap = await getDoc(quizRef);
      
      if (quizSnap.exists()) {
        const quizData = quizSnap.data();
        const quizGeneratedAt = quizData.generatedAt?.toDate?.() || quizData.generatedAt;
        const newQuizVersion = `${today}_${quizGeneratedAt ? quizGeneratedAt.getTime() : Date.now()}`;
        
        // Only update if version is different
        if (newQuizVersion !== currentQuizVersion) {
          console.log('🎉 New quiz detected!');
          
          // Update version and quiz data
          setCurrentQuizVersion(newQuizVersion);
          setTodayQuiz(quizData);
          
          // Check if user already attempted this new version
          const userAttemptRef = doc(db, 'userAttempts', `${user.uid}_${newQuizVersion}`);
          const userAttemptSnap = await getDoc(userAttemptRef);
          
          if (userAttemptSnap.exists()) {
            setUserAttempt(userAttemptSnap.data());
            setQuizStatus('completed');
            setViewMode('results');
          } else {
            // Reset for new quiz
            setUserAttempt(null);
            setAnswers({});
            setQuizStatus('available');
            setViewMode('quiz');
          }
        }
      }
    } catch (error) {
      console.error('Error checking for new quiz:', error);
    } finally {
      if (!silent) {
        setIsCheckingNewQuiz(false);
      }
    }
  }, [user, currentQuizVersion]);

  // Start auto-check interval only when needed
  useEffect(() => {
    if (!user || checkIntervalRef.current) return;
    
    // Only check if quiz is completed (user already submitted)
    if (quizStatus === 'completed') {
      checkIntervalRef.current = setInterval(() => {
        checkForNewQuiz(true); // Silent check
      }, 30000); // Check every 30 seconds instead of 10
    }
    
    return () => {
      if (checkIntervalRef.current) {
        clearInterval(checkIntervalRef.current);
        checkIntervalRef.current = null;
      }
    };
  }, [user, quizStatus, checkForNewQuiz]);

  // Manual refresh
  const handleManualRefresh = async () => {
    if (isLoadingRef.current) return;
    
    setIsCheckingNewQuiz(true);
    await checkForNewQuiz(false);
    setIsCheckingNewQuiz(false);
  };

  // Handle answer selection
  const handleAnswerSelect = (questionIndex, optionIndex) => {
    setAnswers(prev => ({
      ...prev,
      [questionIndex]: optionIndex
    }));
  };

  // Submit quiz - FIXED LOGIC - CHANGED FROM 10 TO 6
  const handleSubmit = async () => {
    if (!user || !todayQuiz || !currentQuizVersion || Object.keys(answers).length !== 6) return;
    
    if (isLoadingRef.current) return;
    isLoadingRef.current = true;
    
    // Calculate score - FIXED: Check the actual correct property
    let correctAnswers = 0;
    const answerDetails = [];
    
    todayQuiz.questions.forEach((question, index) => {
      const selectedOptionIndex = answers[index];
      const selectedOption = question.options[selectedOptionIndex];
      
      // FIX: Directly check if the selected option has correct: true
      let isCorrect = selectedOption?.correct === true;
      
      if (isCorrect) correctAnswers++;
      
      // Find the correct option text
      let correctOptionText = '';
      let correctOptionIndex = -1;
      
      // Find which option has correct: true
      question.options.forEach((opt, idx) => {
        if (opt.correct === true) {
          correctOptionText = opt.text;
          correctOptionIndex = idx;
        }
      });
      
      answerDetails.push({
        questionId: question.id || index,
        questionText: question.question,
        selectedOption: selectedOptionIndex,
        selectedText: selectedOption?.text || 'Not answered',
        correctOptionIndex: correctOptionIndex, // Store correct index
        correctOptionText: correctOptionText,
        isCorrect: isCorrect,
        explanation: question.explanation,
        category: question.category,
        difficulty: question.difficulty
      });
    });
    
    const finalScore = correctAnswers;
    setScore(finalScore);
    
    const today = new Date().toISOString().split('T')[0];
    
    try {
      // Save user attempt - CHANGED FROM 10 TO 6
      const attemptId = `${user.uid}_${currentQuizVersion}`;
      await setDoc(doc(db, 'userAttempts', attemptId), {
        userId: user.uid,
        userEmail: user.email,
        userName: user.displayName,
        date: today,
        quizDate: todayQuiz.date,
        quizVersion: currentQuizVersion,
        answers: answerDetails,
        score: finalScore,
        totalQuestions: 6, // CHANGED FROM 10 TO 6
        submittedAt: serverTimestamp(),
        timeTaken: new Date().toISOString()
      });
      
      // Update quiz statistics
      const quizRef = doc(db, 'dailyQuizzes', today);
      await updateDoc(quizRef, {
        totalAttempts: (todayQuiz.totalAttempts || 0) + 1,
        [`userAttempts.${user.uid}`]: serverTimestamp()
      });
      
      // Update user statistics
      await updateUserStats(user.uid, finalScore);
      
      // Set user attempt and switch to results view - CHANGED FROM 10 TO 6
      const userAttemptData = {
        userId: user.uid,
        userEmail: user.email,
        userName: user.displayName,
        date: today,
        quizDate: todayQuiz.date,
        quizVersion: currentQuizVersion,
        answers: answerDetails,
        score: finalScore,
        totalQuestions: 6, // CHANGED FROM 10 TO 6
        submittedAt: new Date(),
        timeTaken: new Date().toISOString()
      };
      
      setUserAttempt(userAttemptData);
      setQuizStatus('completed');
      setViewMode('results'); // Switch to results view
      
    } catch (error) {
      console.error('Error saving quiz results:', error);
    } finally {
      isLoadingRef.current = false;
    }
  };

  // Update user statistics
  const updateUserStats = async (userId, score) => {
    const today = new Date().toISOString().split('T')[0];
    
    const userRef = doc(db, 'users', userId);
    const userSnap = await getDoc(userRef);
    
    if (userSnap.exists()) {
      const userData = userSnap.data();
      
      await updateDoc(userRef, {
        totalPoints: (userData.totalPoints || 0) + score,
        totalQuizzes: (userData.totalQuizzes || 0) + 1,
        averageScore: ((userData.totalPoints || 0) + score) / ((userData.totalQuizzes || 0) + 1),
        lastPlayed: today,
        lastScore: score,
        lastQuizVersion: currentQuizVersion,
        updatedAt: serverTimestamp()
      });
      
      setUserStats(prev => ({
        ...prev,
        totalPoints: (prev?.totalPoints || 0) + score,
        totalQuizzes: (prev?.totalQuizzes || 0) + 1,
        lastScore: score
      }));
      
    } else {
      await setDoc(userRef, {
        email: user.email,
        name: user.displayName || user.email.split('@')[0],
        totalPoints: score,
        totalQuizzes: 1,
        averageScore: score,
        lastPlayed: today,
        lastScore: score,
        lastQuizVersion: currentQuizVersion,
        joinedAt: serverTimestamp()
      });
      
      setUserStats({
        totalPoints: score,
        totalQuizzes: 1,
        lastScore: score
      });
    }
  };

  // Login with Google
  const handleLogin = async () => {
    try {
      await signInWithPopup(auth, provider);
    } catch (error) {
      console.error('Login error:', error);
    }
  };

  // Logout
  const handleLogout = async () => {
    try {
      await signOut(auth);
      setUser(null);
      setTodayQuiz(null);
      setUserAttempt(null);
      setAnswers({});
      setQuizStatus('checking');
      setViewMode('quiz');
      setCurrentQuizVersion(null);
      if (checkIntervalRef.current) {
        clearInterval(checkIntervalRef.current);
        checkIntervalRef.current = null;
      }
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  // Function to delete attempt
  const deleteMyAttempt = async () => {
    if (!user || !currentQuizVersion) return;
    
    try {
      const attemptId = `${user.uid}_${currentQuizVersion}`;
      const attemptRef = doc(db, 'userAttempts', attemptId);
      await deleteDoc(attemptRef);
      
      console.log('🗑️ Deleted your attempt for this quiz version');
      
      setUserAttempt(null);
      setAnswers({});
      setQuizStatus('available');
      setViewMode('quiz'); // Switch back to quiz view
      
    } catch (error) {
      console.error('Error deleting attempt:', error);
    }
  };

  // FIXED: Switch between quiz and results view
  const handleViewResults = () => {
    setViewMode('results');
    window.scrollTo({
      top: 0,
      behavior: 'smooth'
    });
  };

  const handleViewQuiz = () => {
    setViewMode('quiz');
    window.scrollTo({
      top: 0,
      behavior: 'smooth'
    });
  };

  // Render loading screen
  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-content">
          <Shield className="loading-icon" size={64} />
          <h2>Loading Daily Challenge...</h2>
          <p>Fetching today's cybersecurity questions</p>
          <div className="loading-spinner"></div>
        </div>
      </div>
    );
  }

  // Render login screen
  if (!user) {
    return (
      <div className="login-container">
        <div className="login-card">
          <Shield className="login-icon" size={80} color="#3b82f6" />
          <h1>🔐 Daily Cybersecurity Challenge</h1>
          <p className="login-subtitle">Test your security knowledge with AI-generated questions!</p>
          
          <button onClick={handleLogin} className="login-button">
            <img src="https://www.google.com/favicon.ico" alt="Google" className="google-icon" />
            Sign in with Google to Continue
          </button>
          
          <div className="features-list">
            <div className="feature-item">
              <CheckCircle size={18} color="#10b981" />
              <span>New questions every time</span>
            </div>
            <div className="feature-item">
              <CheckCircle size={18} color="#10b981" />
              <span>Track your progress</span>
            </div>
            <div className="feature-item">
              <CheckCircle size={18} color="#10b981" />
              <span>Detailed explanations</span>
            </div>
          </div>
          
          <p className="login-note">
            Questions are AI-generated. New sets can be created anytime!
          </p>
        </div>
      </div>
    );
  }

  // Render quiz not available
  if (quizStatus === 'not_available') {
    return (
      <div className="quiz-status-container">
        <div className="quiz-status-card">
          <Clock size={64} color="#f59e0b" />
          <h2>Today's Quiz Not Ready Yet</h2>
          <p>Waiting for quiz to be generated...</p>
          
          <button 
            onClick={handleManualRefresh} 
            className="refresh-button"
            disabled={isCheckingNewQuiz}
          >
            {isCheckingNewQuiz ? (
              <>
                <div className="small-spinner"></div>
                Checking...
              </>
            ) : (
              <>
                <RefreshCw size={16} />
                Check for Quiz
              </>
            )}
          </button>
        </div>
      </div>
    );
  }

  // Show quiz dashboard
  if (viewMode === 'quiz') {
    return (
      <div className="quiz-container">
        {/* Header */}
        <header className="quiz-header">
          <div className="header-left">
            <Shield size={32} color="#3b82f6" />
            <div className="header-text">
              <h1>Cybersecurity Challenge</h1>
              <p className="quiz-date">
                {new Date().toLocaleDateString('en-US', { 
                  weekday: 'long', 
                  year: 'numeric', 
                  month: 'long', 
                  day: 'numeric' 
                })}
              </p>
            </div>
          </div>
          
          <div className="user-section">
            <div className="user-info">
              <span className="user-email">{user.email}</span>
              {userStats && (
                <div className="user-stats-summary">
                  <span className="user-points">⭐ {userStats.totalPoints || 0} points</span>
                  <span className="user-quizzes">📊 {userStats.totalQuizzes || 0} quizzes</span>
                </div>
              )}
            </div>
            <div className="header-actions">
              {quizStatus === 'completed' && (
                <button 
                  onClick={handleViewResults}
                  className="view-results-button"
                >
                  <CheckCircle size={14} />
                  View Results
                </button>
              )}
              <button 
                onClick={handleManualRefresh} 
                className="refresh-button small"
                disabled={isCheckingNewQuiz}
              >
                {isCheckingNewQuiz ? (
                  <div className="small-spinner"></div>
                ) : (
                  <>
                    <RefreshCw size={14} />
                    Refresh
                  </>
                )}
              </button>
              <button onClick={handleLogout} className="logout-button">
                Logout
              </button>
            </div>
          </div>
        </header>

        {/* Quiz Info */}
        <div className="quiz-info-card">
          <div className="quiz-info-header">
            <Target size={24} />
            <h3>{
              quizStatus === 'completed' 
                ? 'Quiz Completed - View Results Above' 
                : 'New Challenge Available!'
            }</h3>
          </div>
          
          {quizStatus === 'completed' ? (
            <div className="completed-quiz-info">
              <p>You have already completed this quiz. Click "View Results" above to see your score.</p>
              <div className="quiz-status-banner completed">
                <CheckCircle size={20} />
                <span>Quiz Submitted - Score: {userAttempt?.score || 0}/6</span> {/* CHANGED FROM 10 TO 6 */}
              </div>
            </div>
          ) : (
            <>
              <p>Complete all 6 cybersecurity questions. New quiz sets can be generated anytime.</p> {/* CHANGED FROM 10 TO 6 */}
              
              <div className="quiz-stats">
                <div className="stat-item">
                  <span className="stat-label">Total Attempts Today:</span>
                  <span className="stat-value">{todayQuiz?.totalAttempts || 0}</span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">Your Total Quizzes:</span>
                  <span className="stat-value">{userStats?.totalQuizzes || 0}</span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">Average Score:</span>
                  <span className="stat-value">{userStats?.averageScore?.toFixed(1) || 'N/A'}</span>
                </div>
              </div>
              
              <div className="quiz-version-info">
                <span className="version-label">Quiz Version:</span>
                <code className="version-code">
                  {currentQuizVersion ? currentQuizVersion.substring(0, 20) + '...' : 'Loading...'}
                </code>
              </div>
            </>
          )}
        </div>

        {/* Only show questions if quiz is NOT completed */}
        {quizStatus !== 'completed' && (
          <>
            {/* Questions */}
            <div className="questions-container">
              {todayQuiz?.questions.map((question, index) => (
                <QuestionCard
                  key={`${currentQuizVersion}_${index}`}
                  question={question}
                  index={index}
                  selectedAnswer={answers[index]}
                  onAnswerSelect={handleAnswerSelect}
                />
              ))}
            </div>

            {/* Submit Section */}
            <div className="submit-section">
              <div className="progress-container">
                <div className="progress-bar">
                  <div 
                    className="progress-fill"
                    style={{ width: `${(Object.keys(answers).length / 6) * 100}%` }} 
                  ></div>
                </div>
                <p className="progress-text">
                  {Object.keys(answers).length} / 6 questions answered {/* CHANGED FROM 10 TO 6 */}
                </p>
              </div>
              
              <button
                onClick={handleSubmit}
                disabled={Object.keys(answers).length !== 6} 
                className={`submit-button ${Object.keys(answers).length === 6 ? 'active' : ''}`} 
              >
                <Brain size={20} />
                Submit Answers
              </button>
            </div>
          </>
        )}

        {/* If quiz is completed but in quiz view, show retake option */}
        {quizStatus === 'completed' && (
          <div className="retake-section">
            <div className="retake-info">
              <p>Want to try again? Delete your attempt to retake this quiz.</p>
              <button onClick={deleteMyAttempt} className="delete-attempt-button">
                Delete Attempt & Retake Quiz
              </button>
            </div>
          </div>
        )}
      </div>
    );
  }

  // Show results screen
  if (viewMode === 'results') {
    return (
      <ResultsScreen 
        quiz={todayQuiz} 
        attempt={userAttempt} 
        user={user} 
        userStats={userStats}
        onRefresh={handleManualRefresh}
        quizVersion={currentQuizVersion}
        onDeleteAttempt={deleteMyAttempt}
        isCheckingNewQuiz={isCheckingNewQuiz}
        onBackToDashboard={handleViewQuiz} // Goes back to quiz view
      />
    );
  }

  return null;
}

// Question Card Component
function QuestionCard({ question, index, selectedAnswer, onAnswerSelect }) {
  return (
    <div className="question-card">
      <div className="question-header">
        <span className="question-number">Question {index + 1}</span>
        <div className="question-tags">
          <span className={`difficulty-badge ${question.difficulty}`}>
            {question.difficulty}
          </span>
          <span className="category-tag">{question.category}</span>
        </div>
      </div>
      
      <h3 className="question-text">{question.question}</h3>
      
      <div className="options-grid">
        {question.options.map((option, optIndex) => (
          <div
            key={optIndex}
            className={`option-card ${selectedAnswer === optIndex ? 'selected' : ''}`}
            onClick={() => onAnswerSelect(index, optIndex)}
          >
            <div className="option-marker">
              {String.fromCharCode(65 + optIndex)}
            </div>
            <div className="option-text">{option.text}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// Results Screen Component - FIXED
function ResultsScreen({ quiz, attempt, user, userStats, onRefresh, quizVersion, onDeleteAttempt, isCheckingNewQuiz, onBackToDashboard }) {
  const [expandedQuestions, setExpandedQuestions] = useState({});

  const toggleExplanation = (index) => {
    setExpandedQuestions(prev => ({
      ...prev,
      [index]: !prev[index]
    }));
  };

  const percentage = Math.round((attempt.score / attempt.totalQuestions) * 100);
  const correctCount = attempt.answers.filter(a => a.isCorrect).length;
  const incorrectCount = attempt.totalQuestions - correctCount;

  // FIX: Get correct answer text directly from attempt data
  const getCorrectAnswerText = (answer) => {
    return answer.correctOptionText || 'Correct answer not found';
  };

  return (
    <div className="results-container">
      {/* Header */}
      <header className="results-header">
        <div className="results-title">
          <Shield size={40} color="#3b82f6" />
          <div>
            <h1>Quiz Results</h1>
            <p className="results-date">
              Completed on {new Date(attempt.date).toLocaleDateString('en-US', { 
                month: 'long', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
              })}
            </p>
          </div>
        </div>
        
        <div className="user-results-info">
          <span className="user-email">{attempt.userEmail}</span>
          <div className="results-actions-header">
            <button 
              onClick={onRefresh} 
              className="refresh-button small"
              disabled={isCheckingNewQuiz}
            >
              {isCheckingNewQuiz ? (
                <>
                  <div className="small-spinner"></div>
                  Checking...
                </>
              ) : (
                <>
                  <RefreshCw size={14} />
                  Check for New Quiz
                </>
              )}
            </button>
          </div>
        </div>
      </header>

      {/* Score Card */}
      <div className="score-card">
        <div className="score-display">
          <div className="score-circle">
            <span className="score-number">{attempt.score}</span>
            <span className="score-total">/{attempt.totalQuestions}</span>
          </div>
          <div className="score-details">
            <h2>{percentage}% Correct</h2>
            <p className="score-message">
              {percentage >= 90 ? 'Outstanding! 🏆' :
               percentage >= 80 ? 'Excellent! 🎯' :
               percentage >= 70 ? 'Great Job! 👍' :
               percentage >= 60 ? 'Good Effort! 💪' :
               'Keep Learning! 📚'}
            </p>
            
            <div className="score-breakdown">
              <div className="breakdown-item correct">
                <CheckCircle size={16} />
                <span>{correctCount} Correct</span>
              </div>
              <div className="breakdown-item incorrect">
                <XCircle size={16} />
                <span>{incorrectCount} Incorrect</span>
              </div>
            </div>
          </div>
        </div>
        
        <div className="user-stats">
          <div className="stat-box">
            <span className="stat-label">Total Points</span>
            <span className="stat-value">⭐ {userStats?.totalPoints || attempt.score}</span>
          </div>
          <div className="stat-box">
            <span className="stat-label">Total Quizzes</span>
            <span className="stat-value">📊 {userStats?.totalQuizzes || 1}</span>
          </div>
          <div className="stat-box">
            <span className="stat-label">Average Score</span>
            <span className="stat-value">📈 {userStats?.averageScore?.toFixed(1) || attempt.score}</span>
          </div>
          <div className="stat-box">
            <span className="stat-label">Last Played</span>
            <span className="stat-value">🕒 Today</span>
          </div>
        </div>
      </div>

      {/* Question Review - FIXED */}
      <div className="review-section">
        <h3 className="review-title">Review Your Answers</h3>
        
        {attempt.answers.map((answer, index) => (
          <div 
            key={index} 
            className={`review-card ${answer.isCorrect ? 'correct' : 'incorrect'}`}
          >
            <div className="review-header">
              <div className="review-question-info">
                <div className="question-number-badge">Q{index + 1}</div>
                <div>
                  <h4>{answer.questionText}</h4>
                  <div className="question-meta">
                    <span className="category-badge">{answer.category}</span>
                    <span className={`difficulty-badge ${answer.difficulty}`}>
                      {answer.difficulty}
                    </span>
                  </div>
                </div>
              </div>
              
              <div className={`answer-status ${answer.isCorrect ? 'correct' : 'incorrect'}`}>
                {answer.isCorrect ? (
                  <>
                    <CheckCircle size={20} />
                    <span>Correct</span>
                  </>
                ) : (
                  <>
                    <XCircle size={20} />
                    <span>Incorrect</span>
                  </>
                )}
              </div>
            </div>

            <div className="answer-comparison">
              <div className="answer-row">
                <span className="answer-label">Your Answer:</span>
                <span className={`user-answer ${answer.isCorrect ? 'correct' : 'incorrect'}`}>
                  {String.fromCharCode(65 + answer.selectedOption)}. {answer.selectedText}
                </span>
              </div>
              
              {!answer.isCorrect && (
                <div className="answer-row">
                  <span className="answer-label">Correct Answer:</span>
                  <span className="correct-answer">
                    {getCorrectAnswerText(answer)}
                  </span>
                </div>
              )}
            </div>

            <button
              className="explanation-toggle"
              onClick={() => toggleExplanation(index)}
            >
              <Brain size={16} />
              {expandedQuestions[index] ? 'Hide Explanation' : 'Show Explanation'}
            </button>

            {expandedQuestions[index] && (
              <div className="explanation-box">
                <strong>Explanation:</strong>
                <p>{answer.explanation}</p>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Action Buttons */}
      <div className="results-actions">
        <button 
          className="home-button"
          onClick={onBackToDashboard} // Goes back to quiz view smoothly
        >
          <Home size={18} />
          Back to Quiz Dashboard
        </button>
        
        <div className="secondary-actions">
          <button 
            onClick={onRefresh} 
            className="refresh-button"
            disabled={isCheckingNewQuiz}
          >
            {isCheckingNewQuiz ? (
              <>
                <div className="small-spinner"></div>
                Checking...
              </>
            ) : (
              <>
                <RefreshCw size={16} />
                Check for New Quiz
              </>
            )}
          </button>
          <button onClick={onDeleteAttempt} className="delete-attempt-button">
            Delete This Attempt
          </button>
        </div>
      </div>
    </div>
  );
}

export default Progress;