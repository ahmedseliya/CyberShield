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
    
    console.log(`🚀 Starting Analysis for: ${url}`);
    const outputPath = path.join(workDir, 'output.txt');

    // ✅ FIXED: Changed [workDir] to [] so it pulls from the remote URL properly
    await pack([], {
      remote: url,
      output: {
        filePath: outputPath,
        style: 'plain',
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
        enableSecurityCheck: false 
      },
      tokenCount: {
        encoding: 'o200k_base' 
      },
      quiet: false // Changed to false so you can see the cloning progress in Render logs
    });

    if (!fs.existsSync(outputPath)) {
      throw new Error('Repomix failed to generate output file.');
    }
    
    let content = fs.readFileSync(outputPath, 'utf-8');
    
    // ✅ Improved Regex to count files in 'plain' style
    const fileCount = (content.match(/^File: /gm) || []).length;
    const dependencies = extractDeps(content);
    
    if (content.length > maxSize) {
      content = content.substring(0, maxSize) + '\n\n... (content truncated)';
    }
    
    // Clean up
    fs.rmSync(workDir, { recursive: true, force: true });
    
    res.json({
      success: true,
      rawText: content,
      fileCount: fileCount || 0,
      dependencies,
      metadata: { repository: url, analyzedAt: new Date().toISOString() }
    });
    
  } catch (error) {
    console.error('❌ Repomix Error Trace:', error);
    if (workDir && fs.existsSync(workDir)) {
      try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (e) {}
    }
    res.status(500).json({ 
      success: false, 
      error: error.message,
      details: "Repomix internal error. This usually happens with specific repo structures."
    });
  }
});

function extractDeps(content) {
  const deps = [];
  const pkgMatch = content.match(/package\.json[\s\S]*?({[\s\S]*?})/i);
  if (pkgMatch) {
    try {
      const pkg = JSON.parse(pkgMatch[1].trim());
      const all = { ...pkg.dependencies, ...pkg.devDependencies };
      Object.entries(all).forEach(([name, ver]) => {
        deps.push({ name, version: ver.toString(), ecosystem: 'npm' });
      });
    } catch (e) {}
  }
  return deps;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Bridge Online on port ${PORT}`));