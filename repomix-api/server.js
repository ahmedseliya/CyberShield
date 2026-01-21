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

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.post('/analyze', async (req, res) => {
  let workDir = '';
  try {
    const { url, maxSize = 500000 } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });

    workDir = path.join(GLOBAL_TEMP_DIR, Date.now().toString());
    fs.mkdirSync(workDir, { recursive: true });
    
    console.log(`🚀 Repomix starts: ${url}`);
    const outputPath = path.join(workDir, 'output.txt');

    // ✅ SIMPLIFIED CONFIG
    // Removed 'include: []' which was likely causing the 0-file result
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
      ignore: {
        useDefaultPatterns: true,
        customPatterns: ['node_modules', 'dist', 'build', '.git']
      },
      tokenCount: {
        encoding: 'o200k_base' 
      },
      quiet: false 
    });

    if (!fs.existsSync(outputPath)) {
      throw new Error('Repomix output file not found.');
    }
    
    let content = fs.readFileSync(outputPath, 'utf-8');
    
    // ✅ Better detection for "plain" style
    // The plain style usually labels files like: "File: src/App.js"
    const fileCount = (content.match(/File: /g) || []).length;
    const dependencies = extractDeps(content);
    
    console.log(`📊 Result: Found ${fileCount} files in output.`);

    if (content.length > maxSize) {
      content = content.substring(0, maxSize) + '\n\n... (content truncated)';
    }
    
    fs.rmSync(workDir, { recursive: true, force: true });
    
    res.json({
      success: true,
      rawText: content,
      fileCount: fileCount || 0,
      dependencies,
      metadata: { repository: url, analyzedAt: new Date().toISOString() }
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    if (workDir && fs.existsSync(workDir)) {
      try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (e) {}
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

function extractDeps(content) {
  const deps = [];
  // Look for the package.json section in the text
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
app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));