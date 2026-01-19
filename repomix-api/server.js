const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { runCli } = require('repomix'); // ✅ Import the direct API
const app = express();

app.use(cors());
app.use(express.json());

// Use /tmp for reliable write access on Render
const GLOBAL_TEMP_DIR = '/tmp/repomix-analysis';
if (!fs.existsSync(GLOBAL_TEMP_DIR)) {
  fs.mkdirSync(GLOBAL_TEMP_DIR, { recursive: true });
}

app.post('/analyze', async (req, res) => {
  let workDir = '';
  try {
    const { url, include = 'code', maxSize = 500000 } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });

    workDir = path.join(GLOBAL_TEMP_DIR, Date.now().toString());
    fs.mkdirSync(workDir, { recursive: true });
    
    const outputPath = path.join(workDir, 'output.txt');

    console.log(`🚀 Starting internal analysis for: ${url}`);

    // ✅ Using the library API instead of child_process.exec
    // We pass the arguments as an array just like the CLI
    await runCli([
      '--remote', url,
      '--output', outputPath,
      '--include', include,
      '--style', 'detailed',
      '--quiet'
    ]);

    if (!fs.existsSync(outputPath)) {
      throw new Error('Repomix failed to generate output. The repository might be private or too large.');
    }
    
    let content = fs.readFileSync(outputPath, 'utf-8');
    const fileCount = (content.match(/File:/gi) || []).length;
    
    // Extract basic dependencies for your OSV check
    const dependencies = extractDeps(content);
    
    // Context window protection
    if (content.length > maxSize) {
      content = content.substring(0, maxSize) + '\n\n... (content truncated)';
    }
    
    // Cleanup
    fs.rmSync(workDir, { recursive: true, force: true });
    
    res.json({
      success: true,
      rawText: content,
      fileCount,
      dependencies,
      metadata: { repository: url, analyzedAt: new Date().toISOString() }
    });
    
  } catch (error) {
    console.error('❌ Internal Analysis Error:', error.message);
    if (workDir && fs.existsSync(workDir)) fs.rmSync(workDir, { recursive: true, force: true });
    
    res.status(500).json({
      success: false,
      error: error.message,
      details: "Check if the repo is public. Large repos may hit Render's free RAM limits."
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Bridge Online on port ${PORT}`));