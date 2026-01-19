const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { pack } = require('repomix'); 
const app = express();

app.use(cors());
app.use(express.json());

// Use /tmp for reliable write access on Render
const GLOBAL_TEMP_DIR = '/tmp/repomix-analysis';
if (!fs.existsSync(GLOBAL_TEMP_DIR)) {
  fs.mkdirSync(GLOBAL_TEMP_DIR, { recursive: true });
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'Repomix Bridge API' });
});

app.post('/analyze', async (req, res) => {
  let workDir = '';
  try {
    const { url, include = 'code', maxSize = 500000 } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });

    workDir = path.join(GLOBAL_TEMP_DIR, Date.now().toString());
    fs.mkdirSync(workDir, { recursive: true });
    
    console.log(`🚀 Starting Library Analysis for: ${url}`);

    const outputPath = path.join(workDir, 'output.txt');

    // ✅ FIXED: Pass [workDir] as an array, and match the library's config structure
    await pack([workDir], {
      remote: url,
      output: {
        filePath: outputPath,
        style: 'detailed',
        removeComments: false,
        removeEmptyLines: false,
        topFilesLength: 10,
        showLineNumbers: false,
        copyToClipboard: false,
      },
      include: [include],
      quiet: true
    });

    if (!fs.existsSync(outputPath)) {
      throw new Error('Repomix failed to generate output file.');
    }
    
    let content = fs.readFileSync(outputPath, 'utf-8');
    const fileCount = (content.match(/File:/gi) || []).length;
    
    // Extract dependencies for your OSV analysis
    const dependencies = extractDeps(content);
    
    // Safety truncation for AI analysis
    if (content.length > maxSize) {
      content = content.substring(0, maxSize) + '\n\n... (content truncated)';
    }
    
    // Cleanup temporary files
    try {
        fs.rmSync(workDir, { recursive: true, force: true });
    } catch (cleanupErr) {
        console.warn('Cleanup warning:', cleanupErr.message);
    }
    
    res.json({
      success: true,
      rawText: content,
      fileCount,
      dependencies,
      metadata: { repository: url, analyzedAt: new Date().toISOString() }
    });
    
  } catch (error) {
    console.error('❌ Analysis Error:', error.message);
    if (workDir && fs.existsSync(workDir)) {
        try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (e) {}
    }
    
    res.status(500).json({
      success: false,
      error: error.message,
      details: "Check if the repo is public. The analysis may have failed during the clone process."
    });
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
        deps.push({ name, version: ver.toString().replace(/[^\d.]/g, ''), ecosystem: 'npm' });
      });
    } catch (e) {}
  }
  return deps;
}

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Bridge Online on port ${PORT}`));