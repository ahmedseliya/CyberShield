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

app.post('/analyze', async (req, res) => {
  let workDir = '';
  try {
    const { url, maxSize = 500000 } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });

    workDir = path.join(GLOBAL_TEMP_DIR, Date.now().toString());
    fs.mkdirSync(workDir, { recursive: true });
    
    console.log(`🚀 Starting Full-Config Analysis: ${url}`);
    const outputPath = path.join(workDir, 'output.txt');

    // ✅ Providing the FULL config object to prevent "undefined" property crashes
    await pack([workDir], {
      remote: url,
      output: {
        filePath: outputPath,
        style: 'detailed',
        removeComments: false,
        removeEmptyLines: false,
        showLineNumbers: false,
        topFilesLength: 10,
        copyToClipboard: false,
      },
      include: [], 
      ignore: {
        useDefaultPatterns: true, // This fixes your specific error
        useGitignore: true,
        customPatterns: ['node_modules', 'dist', '.git']
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
    const fileCount = (content.match(/File:/gi) || []).length;
    const dependencies = extractDeps(content);
    
    if (content.length > maxSize) {
      content = content.substring(0, maxSize) + '\n\n... (content truncated)';
    }
    
    fs.rmSync(workDir, { recursive: true, force: true });
    
    res.json({
      success: true,
      rawText: content,
      fileCount,
      dependencies,
      metadata: { repository: url, analyzedAt: new Date().toISOString() }
    });
    
  } catch (error) {
    console.error('❌ Final Error Trace:', error);
    if (workDir && fs.existsSync(workDir)) {
      try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (e) {}
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

function extractDeps(content) {
  const deps = [];
  const pkgMatch = content.match(/package\.json[\s\S]*?```json\s*([\s\S]*?)```/i);
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

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Bridge Online on portssssss ${PORT}`));