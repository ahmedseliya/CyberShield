const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { pack } = require('repomix'); 
const app = express();

app.use(cors());
app.use(express.json());

const GLOBAL_TEMP_DIR = '/tmp/repomix-analysis';
if (!fs.existsSync(GLOBAL_TEMP_DIR)) {
  fs.mkdirSync(GLOBAL_TEMP_DIR, { recursive: true });
}

// ✅ Health Check Route
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    service: 'cybershield-repomix-api',
    timestamp: new Date().toISOString() 
  });
});

app.post('/analyze', async (req, res) => {
  let workDir = '';
  try {
    const { url, maxSize = 500000 } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });

    workDir = path.join(GLOBAL_TEMP_DIR, Date.now().toString());
    fs.mkdirSync(workDir, { recursive: true });
    
    console.log(`🚀 Starting Analysis: ${url}`);
    const outputPath = path.join(workDir, 'output.txt');

    // ✅ FIXED CONFIG: Changed style to 'plain' and simplified structure
    await pack([workDir], {
      remote: url,
      output: {
        filePath: outputPath,
        style: 'plain', // 'detailed' was causing the crash
        removeComments: false,
        removeEmptyLines: false,
        showLineNumbers: false,
        copyToClipboard: false,
      },
      include: [], 
      ignore: {
        useDefaultPatterns: true,
        useGitignore: true,
        customPatterns: ['node_modules', 'dist', 'build', '.git']
      },
      security: {
        enableSecurityCheck: true
      },
      quiet: true
    });

    if (!fs.existsSync(outputPath)) {
      throw new Error('Repomix failed to generate output file.');
    }
    
    let content = fs.readFileSync(outputPath, 'utf-8');
    
    // Calculate stats
    const fileCount = (content.match(/File:/gi) || []).length;
    const dependencies = extractDeps(content);
    
    // Handle truncation if file is too large
    if (content.length > maxSize) {
      content = content.substring(0, maxSize) + '\n\n... (content truncated for size)';
    }
    
    // Cleanup temporary directory
    fs.rmSync(workDir, { recursive: true, force: true });
    
    res.json({
      success: true,
      rawText: content,
      fileCount,
      dependencies,
      metadata: { 
        repository: url, 
        analyzedAt: new Date().toISOString(),
        style: 'plain'
      }
    });
    
  } catch (error) {
    console.error('❌ Repomix Error:', error);
    if (workDir && fs.existsSync(workDir)) {
      try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (e) {}
    }
    res.status(500).json({ 
      success: false, 
      error: error.message,
      tip: "Ensure the repository is public and the URL is correct."
    });
  }
});

function extractDeps(content) {
  const deps = [];
  // Regex to find package.json content within the repomix output
  const pkgMatch = content.match(/package\.json[\s\S]*?({[\s\S]*?})/i);
  if (pkgMatch) {
    try {
      const pkg = JSON.parse(pkgMatch[1].trim());
      const all = { ...pkg.dependencies, ...pkg.devDependencies };
      Object.entries(all).forEach(([name, ver]) => {
        deps.push({ name, version: ver.toString(), ecosystem: 'npm' });
      });
    } catch (e) {
      console.log("Parsing dependencies failed, skipping...");
    }
  }
  return deps;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Bridge Online on port ${PORT}`));