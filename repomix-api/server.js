const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { pack } = require('repomix'); // ✅ Use the direct pack function
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

    // ✅ DIRECT API CALL (No more "Command failed" errors)
    // This runs the logic directly inside Node.js
    const result = await pack(workDir, {
      remote: url,
      output: {
        filePath: path.join(workDir, 'output.txt'),
        style: 'detailed',
      },
      include: [include],
      quiet: true
    });

    const outputPath = path.join(workDir, 'output.txt');
    
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
    fs.rmSync(workDir, { recursive: true, force: true });
    
    res.json({
      success: true,
      rawText: content,
      fileCount,
      dependencies,
      metadata: { repository: url, analyzedAt: new Date().toISOString() }
    });
    
  } catch (error) {
    console.error('❌ Analysis Error:', error.message);
    if (workDir && fs.existsSync(workDir)) fs.rmSync(workDir, { recursive: true, force: true });
    
    res.status(500).json({
      success: false,
      error: error.message,
      details: "Ensure the repo is public. Large repos may hit Render's RAM limits."
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
        deps.push({ name, version: ver.replace(/[^\d.]/g, ''), ecosystem: 'npm' });
      });
    } catch (e) {}
  }
  return deps;
}

const PORT = process.env.PORT || 10000; // Render uses 10000 by default
app.listen(PORT, () => console.log(`🚀 Bridge Online on port ${PORT}`));