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

// ✅ FIX 1: Use /tmp for Render environments
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

    // Create unique subfolder in /tmp
    workDir = path.join(GLOBAL_TEMP_DIR, Date.now().toString());
    fs.mkdirSync(workDir, { recursive: true });
    
    const outputPath = path.join(workDir, 'output.txt');
    const repomixBin = path.join(__dirname, 'node_modules', '.bin', 'repomix');

    // ✅ FIX 2: Simplified command structure
    // We run inside workDir and ensure paths are quoted
    const cmd = `"${repomixBin}" --remote "${url}" --output "${outputPath}" --include "${include}" --style detailed --quiet`;

    console.log(`🚀 Executing in /tmp: ${cmd}`);
    
    // Execute with increased buffer and timeout
    const { stdout, stderr } = await execPromise(cmd, {
      timeout: 300000,
      maxBuffer: 20 * 1024 * 1024, // 20MB
      cwd: workDir // Set current working directory to the temp folder
    });

    if (!fs.existsSync(outputPath)) {
      console.error('STDOUT:', stdout);
      console.error('STDERR:', stderr);
      throw new Error('Repomix failed to generate output. Check logs.');
    }
    
    let content = fs.readFileSync(outputPath, 'utf-8');
    
    // Basic Metadata Extraction
    const fileCount = (content.match(/File:/gi) || []).length;
    const dependencies = extractDependencies(content);
    
    // Truncate if too large for Gemini/AI
    if (content.length > maxSize) {
      content = content.substring(0, maxSize) + '\n\n... (content truncated)';
    }
    
    // Cleanup
    fs.rmSync(workDir, { recursive: true, force: true });
    
    res.json({
      success: true,
      rawText: content,
      dependencies,
      fileCount,
      metadata: { repository: url, analyzedAt: new Date().toISOString() }
    });
    
  } catch (error) {
    console.error('❌ Detailed Error:', error);
    if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
    
    res.status(500).json({
      success: false,
      error: error.message,
      details: "Check if the Git URL is public and the repo isn't too large."
    });
  }
});

function extractDependencies(content) {
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
app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));