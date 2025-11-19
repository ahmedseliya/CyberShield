import React, { useState, useEffect } from 'react';
import { Search, BookmarkPlus, BookmarkCheck, Download, ChevronUp, ChevronDown, Shuffle, Info, X, Plus, Edit, Play, Copy } from 'lucide-react';
import { db } from '../firebaseConfig';
import { collection, getDocs, addDoc, serverTimestamp, doc, getDoc, setDoc, updateDoc } from 'firebase/firestore';
import { auth } from '../firebaseConfig';
import jsPDF from 'jspdf';
import { GoogleGenerativeAI } from '@google/generative-ai';

// 🔑 YOUR GEMINI API KEY
const GEMINI_API_KEY = 'AIzaSyCl7aaCyhPiR_s-zr5cjWH0akCxqmfuSG4';

// Initialize Google AI client
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });

function Glossary() {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [selectedLetter, setSelectedLetter] = useState('All');
  const [expandedTerms, setExpandedTerms] = useState(new Set());
  const [bookmarkedTerms, setBookmarkedTerms] = useState(new Set());
  const [showScrollButton, setShowScrollButton] = useState(false);
  const [isAtBottom, setIsAtBottom] = useState(false);
  const [dailyTerm, setDailyTerm] = useState(null);
  const [flashcardMode, setFlashcardMode] = useState(false);
  const [flippedCards, setFlippedCards] = useState(new Set());
  const [glossaryData, setGlossaryData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [currentUser, setCurrentUser] = useState(null);
  
  // User Contribution States
  const [showSuggestionModal, setShowSuggestionModal] = useState(false);
  const [suggestionType, setSuggestionType] = useState('new'); // 'new' or 'edit'
  const [editingTerm, setEditingTerm] = useState(null);
  const [suggestionForm, setSuggestionForm] = useState({
    term: '',
    definition: '',
    example: '',
    category: '',
    commonMistake: '',
    relatedTerms: ''
  });

  // AI Simulation States
  const [showSimulationModal, setShowSimulationModal] = useState(false);
  const [selectedTermForSimulation, setSelectedTermForSimulation] = useState(null);
  const [simulationScenario, setSimulationScenario] = useState('');
  const [simulationChoices, setSimulationChoices] = useState([]);
  const [userChoice, setUserChoice] = useState(null);
  const [simulationResult, setSimulationResult] = useState('');
  const [simulationLoading, setSimulationLoading] = useState(false);
  const [correctAnswerIndex, setCorrectAnswerIndex] = useState(null);

  // 🔄 Load user data from Firestore
  const loadUserData = async (userId) => {
    try {
      const userDataRef = doc(db, 'userGlossaryData', userId);
      const userDataSnap = await getDoc(userDataRef);
      
      if (userDataSnap.exists()) {
        const userData = userDataSnap.data();
        console.log('📚 Loaded user data from Firestore:', userData);
        
        // Convert bookmarks array to Set
        if (userData.bookmarks) {
          const bookmarkedIds = new Set(userData.bookmarks.map(bookmark => String(bookmark.termId)));
          setBookmarkedTerms(bookmarkedIds);
        } else {
          setBookmarkedTerms(new Set());
        }
        
        // Return API call data
        return userData.apiCalls || {};
      } else {
        // Initialize user data in Firestore
        await setDoc(userDataRef, {
          bookmarks: [],
          apiCalls: {},
          createdAt: serverTimestamp(),
          lastUpdated: serverTimestamp()
        });
        setBookmarkedTerms(new Set());
        return {};
      }
    } catch (error) {
      console.error('Error loading user data:', error);
      setBookmarkedTerms(new Set());
      return {};
    }
  };

  // 🔄 Save user data to Firestore
  const saveUserData = async (bookmarksData, apiCallsData) => {
    if (!currentUser) return;
    
    try {
      const userDataRef = doc(db, 'userGlossaryData', currentUser.uid);
      await updateDoc(userDataRef, {
        bookmarks: bookmarksData,
        apiCalls: apiCallsData,
        lastUpdated: serverTimestamp()
      });
      console.log('💾 Saved user data to Firestore');
    } catch (error) {
      console.error('Error saving user data:', error);
    }
  };

  // 🔄 Get user-specific API call count
  const getDailyCallCount = async (termId) => {
    if (!currentUser) return 0;
    
    try {
      const userDataRef = doc(db, 'userGlossaryData', currentUser.uid);
      const userDataSnap = await getDoc(userDataRef);
      
      if (userDataSnap.exists()) {
        const userData = userDataSnap.data();
        const apiCalls = userData.apiCalls || {};
        const today = new Date().toDateString();
        return apiCalls[today]?.[termId] || 0;
      }
      return 0;
    } catch (error) {
      console.error('Error reading call count:', error);
      return 0;
    }
  };

  // 🔄 Increment user-specific API call count
  const incrementDailyCallCount = async (termId) => {
    if (!currentUser) return 0;
    
    try {
      const userDataRef = doc(db, 'userGlossaryData', currentUser.uid);
      const userDataSnap = await getDoc(userDataRef);
      
      let apiCalls = {};
      if (userDataSnap.exists()) {
        apiCalls = userDataSnap.data().apiCalls || {};
      }
      
      const today = new Date().toDateString();
      if (!apiCalls[today]) {
        apiCalls[today] = {};
      }
      
      apiCalls[today][termId] = (apiCalls[today][termId] || 0) + 1;
      
      // Save updated API calls
      await updateDoc(userDataRef, {
        apiCalls: apiCalls,
        lastUpdated: serverTimestamp()
      });
      
      return apiCalls[today][termId];
    } catch (error) {
      console.error('Error updating call count:', error);
      return 1;
    }
  };

  // 🔄 Check if term has reached daily limit
  const hasReachedDailyLimit = async (termId) => {
    const callCount = await getDailyCallCount(termId);
    return callCount >= 2;
  };

  // Get current user
  useEffect(() => {
    const unsubscribe = auth.onAuthStateChanged(async (user) => {
      setCurrentUser(user);
      if (user) {
        console.log('👤 User logged in:', user.uid);
        // Load user-specific data from Firestore
        await loadUserData(user.uid);
      } else {
        console.log('👤 No user logged in');
        setBookmarkedTerms(new Set());
      }
    });
    return () => unsubscribe();
  }, []);

  // Fetch data from Firebase
  useEffect(() => {
    const fetchGlossaryData = async () => {
      try {
        const querySnapshot = await getDocs(collection(db, 'glossary'));
        const terms = [];
        querySnapshot.forEach((doc) => {
          terms.push({ id: doc.id, ...doc.data() });
        });
        
        // Sort by term name for consistency
        terms.sort((a, b) => a.term.localeCompare(b.term));
        setGlossaryData(terms);
        
        // Set random daily term
        if (terms.length > 0) {
          const randomIndex = Math.floor(Math.random() * terms.length);
          setDailyTerm(terms[randomIndex]);
        }
        
        setLoading(false);
      } catch (error) {
        console.error('Error fetching glossary data:', error);
        setLoading(false);
      }
    };

    fetchGlossaryData();

    // Scroll listener
    const handleScroll = () => {
      const scrollTop = window.scrollY;
      const windowHeight = window.innerHeight;
      const documentHeight = document.documentElement.scrollHeight;
      
      // Check if user is at the bottom
      const atBottom = scrollTop + windowHeight >= documentHeight - 100;
      setIsAtBottom(atBottom);
      
      // Show button if scrolled more than 300px from top OR not at bottom
      setShowScrollButton(scrollTop > 300 || !atBottom);
    };
    
    window.addEventListener('scroll', handleScroll);
    // Initial check
    handleScroll();
    
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // User Contribution Functions
  const openNewSuggestionModal = () => {
    setSuggestionType('new');
    setSuggestionForm({
      term: '',
      definition: '',
      example: '',
      category: '',
      commonMistake: '',
      relatedTerms: ''
    });
    setShowSuggestionModal(true);
  };

  const openEditSuggestionModal = (term) => {
    setSuggestionType('edit');
    setEditingTerm(term);
    setSuggestionForm({
      term: term.term,
      definition: term.definition,
      example: term.example || '',
      category: term.category,
      commonMistake: term.commonMistake || '',
      relatedTerms: term.relatedTerms ? term.relatedTerms.join(', ') : ''
    });
    setShowSuggestionModal(true);
  };

  const closeSuggestionModal = () => {
    setShowSuggestionModal(false);
    setEditingTerm(null);
  };

  const handleSuggestionInputChange = (e) => {
    const { name, value } = e.target;
    setSuggestionForm(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const submitSuggestion = async () => {
    if (!currentUser) {
      alert('Please login to submit suggestions');
      return;
    }

    // Basic validation
    if (!suggestionForm.term.trim() || !suggestionForm.definition.trim() || !suggestionForm.category.trim()) {
      alert('Please fill in at least Term, Definition, and Category fields');
      return;
    }

    try {
      const suggestionData = {
        type: suggestionType,
        originalTermId: suggestionType === 'edit' ? editingTerm.id : null,
        term: suggestionForm.term.trim(),
        definition: suggestionForm.definition.trim(),
        example: suggestionForm.example.trim(),
        category: suggestionForm.category.trim(),
        commonMistake: suggestionForm.commonMistake.trim(),
        relatedTerms: suggestionForm.relatedTerms.split(',').map(term => term.trim()).filter(term => term),
        suggestedBy: {
          uid: currentUser.uid,
          email: currentUser.email,
          displayName: currentUser.displayName || currentUser.email
        },
        status: 'pending', // pending, approved, rejected
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp()
      };

      // Add to Firestore in a new collection called 'suggestions'
      await addDoc(collection(db, 'suggestions'), suggestionData);
      
      alert(`Thank you! Your ${suggestionType === 'new' ? 'new term suggestion' : 'edit suggestion'} has been submitted for review.`);
      closeSuggestionModal();
      
    } catch (error) {
      console.error('Error submitting suggestion:', error);
      alert('Error submitting suggestion. Please try again.');
    }
  };

  // 🔄 AI Simulation Functions with Gemini AI SDK
  const openSimulationModal = async (term) => {
    setSelectedTermForSimulation(term);
    setShowSimulationModal(true);
    setSimulationLoading(true);
    setUserChoice(null);
    setSimulationResult('');
    setCorrectAnswerIndex(null);

    const termId = term.id;
    const reachedLimit = await hasReachedDailyLimit(termId);
    
    // Check if reached daily limit FIRST
    if (reachedLimit) {
      console.log('🚫 Daily limit reached for:', term.term);
      
      // Even if limit reached, try to use cached version (session storage cache)
      const cached = sessionStorage.getItem(`simulation_${termId}`);
      if (cached) {
        try {
          const simulation = JSON.parse(cached);
          // Check if cache is less than 24 hours old
          if (Date.now() - simulation.timestamp < 24 * 60 * 60 * 1000) {
            console.log('📦 Using cached simulation for:', term.term);
            setSimulationScenario(simulation.data.scenario);
            setSimulationChoices(simulation.data.choices);
            setCorrectAnswerIndex(simulation.data.correctAnswer);
            setSimulationResult(simulation.data.explanation);
            setSimulationLoading(false);
            return;
          }
        } catch (error) {
          console.error('Error reading cache:', error);
        }
      }

      // No cache and limit reached - show fallback
      const fallbackData = {
        scenario: `You encounter a cybersecurity situation related to ${term.term}. ${term.definition} What do you do?`,
        choices: [
          "Ignore it and continue with your work",
          "Investigate carefully following security protocols", 
          "Share the information with colleagues immediately",
          "Report to the security team and follow procedures"
        ],
        correctAnswer: 3,
        explanation: "✅ Correct! Always report security incidents to the proper authorities. Following established procedures ensures the situation is handled correctly and prevents further damage."
      };
      
      setSimulationScenario(fallbackData.scenario);
      setSimulationChoices(fallbackData.choices);
      setCorrectAnswerIndex(fallbackData.correctAnswer);
      setSimulationResult(fallbackData.explanation);
      setSimulationLoading(false);
      return;
    }

    // If under limit, ALWAYS call Gemini API for fresh scenario
    try {
      const callCount = await getDailyCallCount(termId);
      console.log('🚀 Calling Gemini API for:', term.term, `(Call ${callCount + 1}/2 today)`);
      
      const prompt = `
You are a cybersecurity expert creating interactive learning simulations. Create a realistic scenario for the cybersecurity term: "${term.term}"

TERM DEFINITION: ${term.definition}

Create an interactive scenario with:
1. A realistic cybersecurity scenario description (2-3 sentences)
2. Four multiple-choice options where only one is the correct cybersecurity practice
3. The correct answer index (0-3) - RANDOMIZE this position each time
4. Detailed explanation of why the correct answer is right and others are wrong

IMPORTANT: In your explanation, DO NOT reference specific letters (A, B, C, D) or positions. Instead, describe why the correct approach is best and why the others are wrong based on their merits.

Return ONLY valid JSON in this exact format:
{
  "scenario": "Realistic scenario description here...",
  "choices": ["Option A", "Option B", "Option C", "Option D"],
  "correctAnswer": 0,
  "explanation": "Detailed explanation here WITHOUT letter references..."
}

Make the scenario realistic and educational. Focus on practical cybersecurity practices. IMPORTANT: Randomize the correctAnswer index (0-3) so it's not always the first option.
`;

      const result = await model.generateContent(prompt);
      const response = await result.response;
      const content = response.text();
      
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        let simulationData = JSON.parse(jsonMatch[0]);
        
        // ✅ RANDOMIZE the correct answer position
        const originalCorrectAnswer = simulationData.correctAnswer;
        const randomizedCorrectAnswer = Math.floor(Math.random() * 4); // 0-3
        
        // If the randomized position is different from original, swap the choices
        if (randomizedCorrectAnswer !== originalCorrectAnswer) {
          const temp = simulationData.choices[originalCorrectAnswer];
          simulationData.choices[originalCorrectAnswer] = simulationData.choices[randomizedCorrectAnswer];
          simulationData.choices[randomizedCorrectAnswer] = temp;
          simulationData.correctAnswer = randomizedCorrectAnswer;
          
          console.log('🔄 Randomized correct answer position from', originalCorrectAnswer, 'to', randomizedCorrectAnswer);
        }
        
        // ✅ Clean the explanation to remove any letter references that might conflict
        let cleanExplanation = simulationData.explanation
          .replace(/Option [A-D]/gi, 'This approach')
          .replace(/[A-D]\)/gi, '')
          .replace(/choice [A-D]/gi, 'this choice')
          .replace(/answer [A-D]/gi, 'the correct approach');
        
        simulationData.explanation = cleanExplanation;
        
        // ✅ CACHE THE NEW RESPONSE in session storage (device-specific cache)
        const cache = {
          data: simulationData,
          timestamp: Date.now()
        };
        sessionStorage.setItem(`simulation_${termId}`, JSON.stringify(cache));
        
        // ✅ INCREMENT API CALL COUNT in Firestore
        await incrementDailyCallCount(termId);
        
        console.log('💾 New scenario cached for:', term.term);
        
        setSimulationScenario(simulationData.scenario);
        setSimulationChoices(simulationData.choices);
        setCorrectAnswerIndex(simulationData.correctAnswer);
        setSimulationResult(simulationData.explanation);
      } else {
        throw new Error('Invalid response format from AI');
      }
    } catch (error) {
      console.error('Error generating simulation with AI:', error);
      // Enhanced fallback simulation - don't count fallbacks toward limit
      const createFallbackScenario = (term) => {
        const baseChoices = [
          "Ignore it and continue with your work",
          "Investigate carefully following security protocols", 
          "Share the information with colleagues immediately",
          "Report to the security team and follow procedures"
        ];
        
        // Always keep "Report to security team" as the correct answer, but randomize its position
        const correctAnswerPosition = Math.floor(Math.random() * 4);
        
        // Create shuffled choices while keeping the correct answer logic consistent
        const shuffledChoices = [...baseChoices];
        if (correctAnswerPosition !== 3) {
          // Swap the correct answer to random position
          [shuffledChoices[correctAnswerPosition], shuffledChoices[3]] = 
          [shuffledChoices[3], shuffledChoices[correctAnswerPosition]];
        }
        
        return {
          scenario: `You encounter a cybersecurity situation related to ${term.term}. ${term.definition} What do you do?`,
          choices: shuffledChoices,
          correctAnswer: correctAnswerPosition,
          explanation: "Always report security incidents to the proper authorities. Following established procedures ensures the situation is handled correctly and prevents further damage."
        };
      };

      const fallbackData = createFallbackScenario(term);
      
      setSimulationScenario(fallbackData.scenario);
      setSimulationChoices(fallbackData.choices);
      setCorrectAnswerIndex(fallbackData.correctAnswer);
      setSimulationResult(fallbackData.explanation);
    }
    setSimulationLoading(false);
  };

  const handleChoiceSelect = (choiceIndex) => {
    setUserChoice(choiceIndex);
    
    if (choiceIndex === correctAnswerIndex) {
      setSimulationResult(`✅ Correct! ${simulationResult}`);
    } else {
      // Get the correct answer letter for display
      const correctAnswerLetter = String.fromCharCode(65 + correctAnswerIndex);
      setSimulationResult(`❌ Incorrect. The correct answer was ${correctAnswerLetter}. ${simulationResult}`);
    }
  };

  const closeSimulationModal = () => {
    setShowSimulationModal(false);
    setSelectedTermForSimulation(null);
    setSimulationScenario('');
    setSimulationChoices([]);
    setUserChoice(null);
    setSimulationResult('');
    setCorrectAnswerIndex(null);
  };

  // Copy to Clipboard Function
  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      alert('Copied to clipboard!');
    } catch (err) {
      console.error('Failed to copy: ', err);
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      alert('Copied to clipboard!');
    }
  };

  const categories = ['All', ...new Set(glossaryData.map(item => item.category))];
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');

  const filteredTerms = glossaryData.filter(item => {
    const matchesSearch = item.term.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         item.definition.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = selectedCategory === 'All' || item.category === selectedCategory;
    const matchesLetter = selectedLetter === 'All' || item.term[0].toUpperCase() === selectedLetter;
    return matchesSearch && matchesCategory && matchesLetter;
  });

  const toggleExpand = (id) => {
    const newExpanded = new Set(expandedTerms);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedTerms(newExpanded);
  };

  // Helper function to normalize ID for comparison
  const normalizeId = (id) => {
    return String(id).trim();
  };

  const toggleBookmark = async (termId) => {
    if (!currentUser) {
      alert('Please login to bookmark terms');
      return;
    }

    try {
      const normalizedTermId = normalizeId(termId);
      
      // Get current user data
      const userDataRef = doc(db, 'userGlossaryData', currentUser.uid);
      const userDataSnap = await getDoc(userDataRef);
      
      let bookmarks = [];
      let apiCalls = {};
      
      if (userDataSnap.exists()) {
        const userData = userDataSnap.data();
        bookmarks = userData.bookmarks || [];
        apiCalls = userData.apiCalls || {};
      }
      
      // Check if bookmark exists
      const existingBookmarkIndex = bookmarks.findIndex(bookmark => 
        normalizeId(bookmark.termId) === normalizedTermId
      );

      if (existingBookmarkIndex !== -1) {
        // Remove bookmark
        bookmarks.splice(existingBookmarkIndex, 1);
        setBookmarkedTerms(prev => {
          const newSet = new Set(prev);
          newSet.delete(normalizedTermId);
          console.log('✅ Bookmark removed, new set:', Array.from(newSet));
          return newSet;
        });
      } else {
        // Add bookmark
        const term = glossaryData.find(t => normalizeId(t.id) === normalizedTermId);
        if (term) {
          const newBookmark = {
            termId: normalizedTermId,
            term: term.term,
            definition: term.definition,
            example: term.example,
            category: term.category,
            icon: term.icon,
            bookmarkedAt: new Date().toISOString()
          };
          bookmarks.push(newBookmark);
          setBookmarkedTerms(prev => {
            const newSet = new Set(prev);
            newSet.add(normalizedTermId);
            console.log('✅ Bookmark added, new set:', Array.from(newSet));
            return newSet;
          });
        }
      }
      
      // Save to Firestore
      await saveUserData(bookmarks, apiCalls);
      
    } catch (error) {
      console.error('Bookmark error:', error);
      alert('Error saving bookmark. Please try again.');
    }
  };

  // Separate function specifically for removing bookmarks from the bookmarked section
  const removeBookmark = async (termId, e) => {
    if (e) {
      e.stopPropagation();
    }
    
    const normalizedTermId = normalizeId(termId);
    console.log('🗑️ Removing bookmark for term:', normalizedTermId);
    
    if (!currentUser) {
      alert('Please login to manage bookmarks');
      return;
    }

    try {
      // Get current user data
      const userDataRef = doc(db, 'userGlossaryData', currentUser.uid);
      const userDataSnap = await getDoc(userDataRef);
      
      let bookmarks = [];
      let apiCalls = {};
      
      if (userDataSnap.exists()) {
        const userData = userDataSnap.data();
        bookmarks = userData.bookmarks || [];
        apiCalls = userData.apiCalls || {};
      }
      
      // Remove bookmark
      const updatedBookmarks = bookmarks.filter(bookmark => 
        normalizeId(bookmark.termId) !== normalizedTermId
      );
      
      // Update state immediately
      setBookmarkedTerms(prev => {
        const newSet = new Set(prev);
        newSet.delete(normalizedTermId);
        console.log('✅ Bookmark removed from state, new set:', Array.from(newSet));
        return newSet;
      });
      
      // Save to Firestore
      await saveUserData(updatedBookmarks, apiCalls);
      
    } catch (error) {
      console.error('Error removing bookmark:', error);
      alert('Error removing bookmark. Please try again.');
    }
  };

  const toggleFlipCard = (id) => {
    const newFlipped = new Set(flippedCards);
    if (newFlipped.has(id)) {
      newFlipped.delete(id);
    } else {
      newFlipped.add(id);
    }
    setFlippedCards(newFlipped);
  };

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const scrollToBottom = () => {
    window.scrollTo({ top: document.documentElement.scrollHeight, behavior: 'smooth' });
  };

  const handleScrollButtonClick = () => {
    if (isAtBottom) {
      scrollToTop();
    } else {
      scrollToBottom();
    }
  };

  const downloadPDF = () => {
    try {
      // Create new PDF document
      const pdf = new jsPDF();
      
      // Set title
      pdf.setFontSize(20);
      pdf.setTextColor(40, 40, 40);
      pdf.text('Cybersecurity Glossary', 20, 30);
      
      // Set subtitle
      pdf.setFontSize(12);
      pdf.setTextColor(100, 100, 100);
      pdf.text('Your comprehensive guide to cybersecurity terminology', 20, 40);
      
      // Add date
      const today = new Date().toLocaleDateString();
      pdf.text(`Generated on: ${today}`, 20, 50);
      
      let yPosition = 70;
      let pageNumber = 1;
      
      // Add terms to PDF
      pdf.setFontSize(14);
      pdf.setTextColor(40, 40, 40);
      
      filteredTerms.forEach((term, index) => {
        // Check if we need a new page
        if (yPosition > 250) {
          pdf.addPage();
          pageNumber++;
          yPosition = 30;
          
          // Add page header
          pdf.setFontSize(10);
          pdf.setTextColor(100, 100, 100);
          pdf.text(`Page ${pageNumber} - Cybersecurity Glossary`, 20, 20);
          pdf.setFontSize(14);
          pdf.setTextColor(40, 40, 40);
        }
        
        // Clean the term name - remove icons/special characters
        const cleanTerm = term.term.replace(/[^\x00-\x7F]/g, '').trim() || term.term;
        
        // Term name
        pdf.setFont(undefined, 'bold');
        pdf.text(`• ${cleanTerm}`, 20, yPosition);
        
        // Category
        pdf.setFont(undefined, 'normal');
        pdf.setFontSize(10);
        pdf.setTextColor(80, 80, 80);
        pdf.text(`Category: ${term.category}`, 20, yPosition + 7);
        
        // Definition
        pdf.setFontSize(11);
        pdf.setTextColor(40, 40, 40);
        
        // Clean definition text
        const cleanDefinition = term.definition.replace(/[^\x00-\x7F]/g, ' ').trim() || term.definition;
        
        // Split definition into multiple lines if too long
        const definitionLines = pdf.splitTextToSize(`Definition: ${cleanDefinition}`, 170);
        pdf.text(definitionLines, 20, yPosition + 15);
        
        let definitionHeight = definitionLines.length * 6;
        
        // Example if it exists
        if (term.example) {
          // Clean example text
          const cleanExample = term.example.replace(/[^\x00-\x7F]/g, ' ').trim() || term.example;
          const exampleLines = pdf.splitTextToSize(`Example: ${cleanExample}`, 170);
          pdf.text(exampleLines, 20, yPosition + 15 + definitionHeight);
          yPosition += 15 + definitionHeight + (exampleLines.length * 6) + 10;
        } else {
          yPosition += 15 + definitionHeight + 10;
        }
        
        // Add separator line
        pdf.setDrawColor(200, 200, 200);
        pdf.line(20, yPosition - 5, 190, yPosition - 5);
        
        yPosition += 5;
      });
      
      // Add bookmarks section if there are bookmarks
      if (bookmarkedTerms.size > 0 && !flashcardMode) {
        if (yPosition > 200) {
          pdf.addPage();
          pageNumber++;
          yPosition = 30;
        }
        
        pdf.setFontSize(16);
        pdf.setTextColor(40, 40, 40);
        pdf.setFont(undefined, 'bold');
        pdf.text('Your Bookmarked Terms', 20, yPosition);
        yPosition += 15;
        
        glossaryData
          .filter(term => {
            const isBookmarked = Array.from(bookmarkedTerms).some(bookmarkId => 
              normalizeId(bookmarkId) === normalizeId(term.id)
            );
            return isBookmarked;
          })
          .forEach(term => {
            if (yPosition > 250) {
              pdf.addPage();
              pageNumber++;
              yPosition = 30;
            }
            
            // Clean term name for bookmarks too
            const cleanTerm = term.term.replace(/[^\x00-\x7F]/g, '').trim() || term.term;
            
            pdf.setFontSize(12);
            pdf.setFont(undefined, 'bold');
            pdf.text(`• ${cleanTerm}`, 25, yPosition);
            
            pdf.setFont(undefined, 'normal');
            pdf.setFontSize(10);
            
            // Clean definition for bookmarks
            const cleanDefinition = term.definition.replace(/[^\x00-\x7F]/g, ' ').trim() || term.definition;
            const definitionLines = pdf.splitTextToSize(cleanDefinition, 160);
            pdf.text(definitionLines, 25, yPosition + 7);
            
            yPosition += 7 + (definitionLines.length * 5) + 5;
          });
      }
      
      // Save the PDF
      pdf.save('cybersecurity-glossary.pdf');
      
    } catch (error) {
      console.error('Error generating PDF:', error);
      alert('Error generating PDF. Please try again.');
    }
  };

  const shuffleDailyTerm = () => {
    if (glossaryData.length > 0) {
      const randomIndex = Math.floor(Math.random() * glossaryData.length);
      setDailyTerm(glossaryData[randomIndex]);
    }
  };

  if (loading) {
    return (
      <div className="glossary-container">
        <div className="loading">Loading glossary terms...</div>
      </div>
    );
  }

  return (
    <div className="glossary-container">

      {/* Header */}
      <header className="glossary-header">
        <h1>Cybersecurity Glossary</h1>
        <p>Your comprehensive guide to cybersecurity terminology</p>
        {!currentUser && (
          <div className="login-notice">
            🔐 <a href="/login">Login</a> to save your bookmarks and suggest new terms
          </div>
        )}
      </header>

      {/* Daily Term Highlight */}
      {dailyTerm && (
        <div className="daily-term">
          <div className="daily-term-header">
            <h3>
              <span className="icon">{dailyTerm.icon}</span>
              Term of the Day: {dailyTerm.term}
            </h3>
            <button onClick={shuffleDailyTerm} className="shuffle-btn">
              <Shuffle size={18} />
            </button>
          </div>
          <p className="daily-definition">{dailyTerm.definition}</p>
          <div className="did-you-know">
            <Info size={16} />
            <span><strong>Did You Know?</strong> {dailyTerm.commonMistake}</span>
          </div>
        </div>
      )}

      {/* Search Bar */}
      <div className="search-container1">
        <Search className="search-icon1" size={20} />
        <input
          type="text"
          placeholder="Search cybersecurity terms..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="search-input1"
        />
      </div>

      {/* Controls */}
      <div className="controls">
        <div className="control-buttons">
          <button 
            className={`mode-btn ${!flashcardMode ? 'active' : ''}`}
            onClick={() => setFlashcardMode(false)}
          >
            List View
          </button>
          <button 
            className={`mode-btn ${flashcardMode ? 'active' : ''}`}
            onClick={() => setFlashcardMode(true)}
          >
            Flashcard Mode
          </button>
          <button className="download-btn" onClick={downloadPDF}>
            <Download size={18} />
            Download PDF
          </button>
          
          {/* User Contribution Buttons */}
          {currentUser && (
            <>
              <button 
                className="contribute-btn new-term-btn"
                onClick={openNewSuggestionModal}
                title="Suggest New Term"
              >
                <Plus size={18} />
                Suggest New Term
              </button>
            </>
          )}
        </div>
      </div>

      {/* Sticky Navigation */}
      <nav className="sticky-nav">
        {/* Category Filters */}
        <div className="category-filters">
          {categories.map(cat => (
            <button
              key={cat}
              className={`filter-btn ${selectedCategory === cat ? 'active' : ''}`}
              onClick={() => setSelectedCategory(cat)}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Alphabet Index */}
        <div className="alphabet-index">
          <button
            className={`letter-btn ${selectedLetter === 'All' ? 'active' : ''}`}
            onClick={() => setSelectedLetter('All')}
          >
            All
          </button>
          {alphabet.map(letter => (
            <button
              key={letter}
              className={`letter-btn ${selectedLetter === letter ? 'active' : ''}`}
              onClick={() => setSelectedLetter(letter)}
            >
              {letter}
            </button>
          ))}
        </div>
      </nav>

      {/* Terms List / Flashcards */}
      <div className={flashcardMode ? 'flashcard-grid' : 'terms-list'}>
        {filteredTerms.map(term => (
          flashcardMode ? (
            <div
              key={term.id}
              className={`flashcard ${flippedCards.has(term.id) ? 'flipped' : ''}`}
              onClick={() => toggleFlipCard(term.id)}
            >
              <div className="flashcard-inner">
                <div className="flashcard-front">
                  <span className="card-icon">{term.icon}</span>
                  <h3>{term.term}</h3>
                  <span className="category-badge">{term.category}</span>
                  <p className="flip-hint">Click to flip</p>
                </div>
                <div className="flashcard-back">
                  <p>{term.definition}</p>
                  <div className="example-box">
                    <strong>Example:</strong> {term.example}
                  </div>
                  
                  {/* NEW: Copy and Simulation buttons in flashcards */}
                  <div className="flashcard-actions">
                    <button 
                      className="copy-btn"
                      onClick={(e) => {
                        e.stopPropagation();
                        copyToClipboard(term.definition);
                      }}
                      title="Copy definition"
                    >
                      <Copy size={14} />
                      Copy
                    </button>
                    
                    <button 
                      className="simulate-btn"
                      onClick={(e) => {
                        e.stopPropagation();
                        openSimulationModal(term);
                      }}
                      title={`Practice with AI simulation`}
                    >
                      <Play size={14} />
                      Practice
                    </button>
                    
                    {currentUser && (
                      <button 
                        className="suggest-edit-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          openEditSuggestionModal(term);
                        }}
                      >
                        <Edit size={14} />
                        Suggest Edit
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div key={term.id} className="term-card">
              <div className="term-header" onClick={() => toggleExpand(term.id)}>
                <div className="term-title">
                  <span className="term-icon">{term.icon}</span>
                  <h3>{term.term}</h3>
                  <span className="category-badge">{term.category}</span>
                </div>
                <div className="term-actions">
                  {/* NEW: Copy button in list view */}
                  <button
                    className="copy-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      copyToClipboard(term.definition);
                    }}
                    title="Copy definition"
                  >
                    <Copy size={16} />
                  </button>
                  
                  {/* NEW: Simulation button in list view */}
                  <button
                    className="simulate-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      openSimulationModal(term);
                    }}
                    title={`Practice with AI simulation`}
                  >
                    <Play size={16} />
                  </button>
                  
                  {currentUser && (
                    <button
                      className="edit-suggestion-btn"
                      onClick={(e) => {
                        e.stopPropagation();
                        openEditSuggestionModal(term);
                      }}
                      title="Suggest Edit"
                    >
                      <Edit size={16} />
                    </button>
                  )}
                  <button
                    className="bookmark-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleBookmark(term.id);
                    }}
                    title={currentUser ? "Bookmark this term" : "Login to bookmark"}
                  >
                    {Array.from(bookmarkedTerms).some(bookmarkId => 
                      normalizeId(bookmarkId) === normalizeId(term.id)
                    ) ? 
                      <BookmarkCheck size={20} color="#ff6b6b" /> : 
                      <BookmarkPlus size={20} />
                    }
                  </button>
                </div>
              </div>

              {expandedTerms.has(term.id) && (
                <div className="term-content">
                  <div className="definition-header">
                    <p className="definition">{term.definition}</p>
                    {/* NEW: Copy button in expanded view */}
                    <button
                      className="copy-definition-btn"
                      onClick={() => copyToClipboard(term.definition)}
                      title="Copy definition"
                    >
                      <Copy size={14} />
                    </button>
                  </div>
                  
                  <div className="example-section">
                    <h4>Example Usage:</h4>
                    <p>{term.example}</p>
                  </div>

                  <div className="related-terms">
                    <h4>Related Terms:</h4>
                    <div className="tags">
                      {term.relatedTerms.map((related, idx) => (
                        <span key={idx} className="tag">{related}</span>
                      ))}
                    </div>
                  </div>

                  <div className="common-mistake">
                    <h4>⚠️ Common Mistake:</h4>
                    <p>{term.commonMistake}</p>
                  </div>
                </div>
              )}
            </div>
          )
        ))}
      </div>

      {filteredTerms.length === 0 && (
        <div className="no-results">
          <p>No terms found matching your criteria.</p>
          {currentUser && (
            <button 
              className="contribute-btn"
              onClick={openNewSuggestionModal}
            >
              <Plus size={18} />
              Be the first to suggest this term!
            </button>
          )}
        </div>
      )}

      {/* Bookmarked Terms Section */}
      {bookmarkedTerms.size > 0 && !flashcardMode && (
        <div className="bookmarked-section">
          <h2>📚 Your Bookmarked Terms ({bookmarkedTerms.size})</h2>

          <div className="bookmarked-list">
            {glossaryData
              .filter(term => {
                const isBookmarked = Array.from(bookmarkedTerms).some(bookmarkId => 
                  normalizeId(bookmarkId) === normalizeId(term.id)
                );
                console.log(`📖 Checking term ${term.id} (${term.term}): ${isBookmarked}`);
                return isBookmarked;
              })
              .map(term => (
                <div key={term.id} className="bookmark-item">
                  <button 
                    className="bookmark-remove"
                    onClick={(e) => removeBookmark(term.id, e)}
                    title="Remove bookmark"
                  >
                    <X size={18} />
                  </button>
                  
                  <div className="bookmark-header">
                    <span className="bookmark-icon">{term.icon}</span>
                    <strong className="bookmark-term">{term.term}</strong>
                  </div>
                  <div className="bookmark-content">
                    <p><strong>Definition:</strong> {term.definition}</p>
                    <p><strong>Example:</strong> {term.example}</p>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Suggestion Modal */}
      {showSuggestionModal && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h2>
                {suggestionType === 'new' ? 'Suggest New Term' : 'Suggest Edit'}
                {suggestionType === 'edit' && `: ${editingTerm.term}`}
              </h2>
              <button className="close-btn" onClick={closeSuggestionModal}>
                <X size={24} />
              </button>
            </div>
            
            <div className="modal-body">
              <p className="modal-description">
                {suggestionType === 'new' 
                  ? 'Suggest a new cybersecurity term to be added to the glossary. Your suggestion will be reviewed by our team.'
                  : 'Suggest improvements to this term definition. Your edits will be reviewed by our team.'
                }
              </p>
              
              <div className="form-group">
                <label>Term *</label>
                <input
                  type="text"
                  name="term"
                  value={suggestionForm.term}
                  onChange={handleSuggestionInputChange}
                  placeholder="Enter the term name"
                  disabled={suggestionType === 'edit'}
                />
              </div>
              
              <div className="form-group">
                <label>Definition *</label>
                <textarea
                  name="definition"
                  value={suggestionForm.definition}
                  onChange={handleSuggestionInputChange}
                  placeholder="Enter the definition"
                  rows="3"
                />
              </div>
              
              <div className="form-group">
                <label>Example Usage</label>
                <textarea
                  name="example"
                  value={suggestionForm.example}
                  onChange={handleSuggestionInputChange}
                  placeholder="Enter an example of how this term is used"
                  rows="2"
                />
              </div>
              
              <div className="form-group">
                <label>Category *</label>
                <input
                  type="text"
                  name="category"
                  value={suggestionForm.category}
                  onChange={handleSuggestionInputChange}
                  placeholder="e.g., Network Security, Cryptography, etc."
                />
              </div>
              
              <div className="form-group">
                <label>Common Mistake</label>
                <textarea
                  name="commonMistake"
                  value={suggestionForm.commonMistake}
                  onChange={handleSuggestionInputChange}
                  placeholder="Common misunderstandings about this term"
                  rows="2"
                />
              </div>
              
              <div className="form-group">
                <label>Related Terms</label>
                <input
                  type="text"
                  name="relatedTerms"
                  value={suggestionForm.relatedTerms}
                  onChange={handleSuggestionInputChange}
                  placeholder="Enter related terms separated by commas"
                />
              </div>
            </div>
            
            <div className="modal-footer">
              <button className="cancel-btn" onClick={closeSuggestionModal}>
                Cancel
              </button>
              <button className="submit-btn" onClick={submitSuggestion}>
                Submit Suggestion
              </button>
            </div>
          </div>
        </div>
      )}

      {/* NEW: AI Simulation Modal */}
      {showSimulationModal && (
        <div className="modal-overlay2">
          <div className="modal-content2 simulation-modal">
            <div className="modal-header2">
              <h2>🎯 AI Security Simulation: {selectedTermForSimulation?.term}</h2>
              <button className="close-btn2" onClick={closeSimulationModal}>
                <X size={24} />
              </button>
            </div>
            
            <div className="modal-body">
              {simulationLoading ? (
                <div className="simulation-loading">
                  <p>🔄 AI is creating a realistic scenario for you...</p>
                </div>
              ) : (
                <>
                  <div className="scenario-box">
                    <h3>📋 Scenario:</h3>
                    <p>{simulationScenario}</p>
                  </div>

                  <div className="choices-container">
                    <h3>🔍 What would you do?</h3>
                    <div className="choices-list">
                      {simulationChoices.map((choice, index) => (
                        <button
                          key={index}
                          className={`choice-btn ${userChoice === index ? 'selected' : ''}`}
                          onClick={() => handleChoiceSelect(index)}
                          disabled={userChoice !== null}
                        >
                          <span className="choice-letter">
                            {String.fromCharCode(65 + index)}
                          </span>
                          {choice}
                        </button>
                      ))}
                    </div>
                  </div>

                  {userChoice !== null && (
                    <div className="result-box">
                      <h3>💡 Feedback:</h3>
                      <p>{simulationResult}</p>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Single Scroll Button (Toggles between Up/Down) */}
      {showScrollButton && (
        <button 
          className="scroll-toggle-btn" 
          onClick={handleScrollButtonClick}
          title={isAtBottom ? "Scroll to top" : "Scroll to bottom"}
        >
          {isAtBottom ? <ChevronUp size={24} /> : <ChevronDown size={24} />}
        </button>
      )}
    </div>
  );
}

export default Glossary;