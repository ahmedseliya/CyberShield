// repomix-api/server.js - FIXED VERSION
const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const util = require('util');
const app = express();

const execPromise = util.promisify(exec);

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'Repomix Bridge API',
    timestamp: new Date().toISOString()
  });
});

// Main endpoint to pack repositories
app.post('/analyze', async (req, res) => {
  try {
    const { url, format = 'text', include = 'code', excludePatterns, maxSize = 500000 } = req.body;
    
    if (!url) {
      return res.status(400).json({ 
        error: 'Repository URL is required',
        example: 'https://github.com/username/repository'
      });
    }

    console.log(`📦 Processing repository: ${url}`);
    
    // Create a unique temporary directory
    const tempDir = path.join(__dirname, 'temp', Date.now().toString());
    fs.mkdirSync(tempDir, { recursive: true });
    
    // ✅ FIXED: Remove --format parameter, use --style instead
    // Build repomix command
    const cmd = [
      'npx',
      'repomix',
      `--remote=${url}`,
      `--output=${path.join(tempDir, 'output.txt')}`,
      `--include=${include}`,
      '--style=detailed',  // ✅ CHANGED FROM --format=text
      '--quiet',
      '--no-progress'
    ];
    
    // Add exclude patterns if provided
    if (excludePatterns && Array.isArray(excludePatterns)) {
      excludePatterns.forEach(pattern => {
        cmd.push(`--exclude=${pattern}`);
      });
    } else {
      // Default exclusions
      cmd.push('--exclude=node_modules');
      cmd.push('--exclude=dist');
      cmd.push('--exclude=build');
      cmd.push('--exclude=.git');
      cmd.push('--exclude=*.log');
      cmd.push('--exclude=*.lock');
    }
    
    console.log(`🔧 Running command: ${cmd.join(' ')}`);
    
    // Execute repomix
    const { stdout, stderr } = await execPromise(cmd.join(' '), {
      cwd: tempDir,
      timeout: 300000, // 5 minute timeout
      maxBuffer: 10 * 1024 * 1024 // 10MB buffer
    });
    
    if (stderr && !stderr.includes('warning')) {
      console.error('Repomix stderr:', stderr);
    }
    
    // Read the output file
    const outputPath = path.join(tempDir, 'output.txt');
    if (!fs.existsSync(outputPath)) {
      throw new Error('Repomix failed to generate output');
    }
    
    let content = fs.readFileSync(outputPath, 'utf-8');
    
    // Extract file count from repomix output
    const fileMatch = content.match(/Analyzed (\d+) files?/i);
    const fileCount = fileMatch ? parseInt(fileMatch[1]) : 0;
    
    // Extract dependencies from the content
    const dependencies = extractDependencies(content);
    
    // Extract file structure
    const fileStructure = extractFileStructure(content);
    
    // Generate summary
    const summary = generateSummary(content, fileCount);
    
    // If content is too large, truncate it
    if (content.length > maxSize) {
      console.log(`📊 Content truncated from ${content.length} to ${maxSize} characters`);
      content = content.substring(0, maxSize) + '\n\n... (truncated for analysis)';
    }
    
    // Clean up temporary directory
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch (cleanupError) {
      console.warn('Could not clean up temp directory:', cleanupError.message);
    }
    
    console.log(`✅ Successfully analyzed repository: ${fileCount} files, ${dependencies.length} dependencies`);
    
    res.json({
      success: true,
      rawText: content,
      dependencies,
      fileStructure: fileStructure.slice(0, 100), // Limit to 100 files
      fileCount,
      summary,
      metadata: {
        repository: url,
        analyzedAt: new Date().toISOString(),
        contentLength: content.length
      }
    });
    
  } catch (error) {
    console.error('❌ Repomix analysis error:', error);
    
    res.status(500).json({
      success: false,
      error: error.message,
      details: 'Failed to analyze repository with Repomix',
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Helper function to extract dependencies
function extractDependencies(content) {
  const dependencies = [];
  
  // Try to find package.json
  const packageJsonMatch = content.match(/File: .*package\.json[\s\S]*?```json\s*([\s\S]*?)```/i);
  if (packageJsonMatch) {
    try {
      const packageJson = JSON.parse(packageJsonMatch[1].trim());
      
      if (packageJson.dependencies) {
        Object.entries(packageJson.dependencies).forEach(([name, version]) => {
          dependencies.push({
            ecosystem: 'npm',
            name,
            version: version.replace(/^\^|~/, ''),
            source: 'package.json',
            confirmed: true
          });
        });
      }
      
      if (packageJson.devDependencies) {
        Object.entries(packageJson.devDependencies).forEach(([name, version]) => {
          dependencies.push({
            ecosystem: 'npm',
            name,
            version: version.replace(/^\^|~/, ''),
            source: 'package.json (dev)',
            confirmed: true
          });
        });
      }
    } catch (e) {
      // Silent fail for JSON parsing
    }
  }
  
  // Try to find requirements.txt
  const requirementsMatch = content.match(/File: .*requirements\.txt[\s\S]*?```txt\s*([\s\S]*?)```/i);
  if (requirementsMatch) {
    const requirementsContent = requirementsMatch[1];
    const lines = requirementsContent.split('\n');
    
    lines.forEach((line) => {
      const cleanLine = line.trim();
      if (cleanLine && !cleanLine.startsWith('#')) {
        const match = cleanLine.match(/^([a-zA-Z0-9-_\[\]]+)([=<>!~]=?)?([0-9a-zA-Z.-]*)/);
        if (match && match[1]) {
          dependencies.push({
            ecosystem: 'PyPI',
            name: match[1],
            version: match[3] || 'unknown',
            source: 'requirements.txt',
            confirmed: true
          });
        }
      }
    });
  }
  
  // Remove duplicates
  const uniqueDeps = [];
  const seen = new Set();
  
  dependencies.forEach(dep => {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueDeps.push(dep);
    }
  });
  
  return uniqueDeps;
}

// Helper function to extract file structure
function extractFileStructure(content) {
  const files = [];
  const lines = content.split('\n');
  
  for (const line of lines) {
    const fileMatch = line.match(/File:\s*(.+)/i);
    if (fileMatch) {
      const fileName = fileMatch[1].trim();
      if (fileName && !fileName.includes('node_modules') && !fileName.includes('.git/')) {
        files.push(fileName);
      }
    }
  }
  
  return files;
}

// Helper function to generate summary
function generateSummary(content, fileCount) {
  const hasReact = content.includes('import React') || content.includes('from "react"');
  const hasVue = content.includes('Vue.component') || content.includes('new Vue(');
  const hasAngular = content.includes('@angular') || content.includes('@Component');
  const hasExpress = content.includes('express()') || content.includes('require(\'express\')');
  const hasDjango = content.includes('django') || content.includes('from django');
  const hasFlask = content.includes('flask') || content.includes('Flask(');
  const hasSpring = content.includes('@SpringBootApplication') || content.includes('import org.springframework');
  const hasNode = content.includes('require(') || content.includes('module.exports');
  const hasPython = content.includes('def ') || content.includes('import ') && content.includes('.py');
  const hasJava = content.includes('public class') || content.includes('.java');
  
  let techStack = [];
  if (hasReact) techStack.push('React');
  if (hasVue) techStack.push('Vue.js');
  if (hasAngular) techStack.push('Angular');
  if (hasExpress) techStack.push('Express.js');
  if (hasDjango) techStack.push('Django');
  if (hasFlask) techStack.push('Flask');
  if (hasSpring) techStack.push('Spring Boot');
  if (hasNode) techStack.push('Node.js');
  if (hasPython) techStack.push('Python');
  if (hasJava) techStack.push('Java');
  
  const stack = techStack.length > 0 ? techStack.join(' + ') : 'Unknown technology stack';
  
  return `${stack} application with ${fileCount} files analyzed via Repomix`;
}

// Handle 404
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    availableEndpoints: {
      'GET /health': 'Health check',
      'POST /analyze': 'Analyze a repository',
      parameters: {
        url: 'Repository URL (required)',
        include: 'What to include (code/all)',
        excludePatterns: 'Array of patterns to exclude'
      }
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Repomix Bridge API running on port ${PORT}`);
  console.log(`🌐 Health check: http://localhost:${PORT}/health`);
  console.log(`📦 Analyze endpoint: POST http://localhost:${PORT}/analyze`);
});