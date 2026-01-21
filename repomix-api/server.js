const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
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

    // 1. Setup paths
    const timestamp = Date.now().toString();
    workDir = path.join(GLOBAL_TEMP_DIR, timestamp);
    const repoDir = path.join(workDir, 'repo');
    fs.mkdirSync(repoDir, { recursive: true });
    
    console.log(`🚀 STARTING CLI ANALYSIS: ${url}`);

    // 2. Clone the repo manually
    console.log(`📦 Cloning...`);
    execSync(`git clone --depth 1 ${url} .`, { cwd: repoDir, stdio: 'inherit' });

    // 3. Run Repomix via CLI (npx)
    // This avoids all the "undefined property" library bugs!
    console.log(`🛠️ Running Repomix CLI...`);
    const outputPath = path.join(workDir, 'repomix-output.txt');
    
    // Commands: --style plain, --output to specific file, --no-security-check to save time
    execSync(`npx repomix . --style plain --output ${outputPath} --no-security-check`, { 
      cwd: repoDir, 
      stdio: 'inherit' 
    });

    if (!fs.existsSync(outputPath)) {
      throw new Error('Repomix CLI failed to generate output.');
    }
    
    let content = fs.readFileSync(outputPath, 'utf-8');
    
    // 4. Extract Data
    const fileCount = (content.match(/File: /g) || []).length;
    const dependencies = extractDeps(content);
    
    console.log(`✅ DONE! Found ${fileCount} files.`);

    if (content.length > maxSize) {
      content = content.substring(0, maxSize) + '\n\n... (content truncated)';
    }
    
    // 5. Cleanup
    try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (e) {}
    
    res.json({
      success: true,
      rawText: content,
      fileCount: fileCount || 0,
      dependencies,
      metadata: { repository: url, analyzedAt: new Date().toISOString() }
    });
    
  } catch (error) {
    console.error('❌ CRITICAL ERROR:', error.message);
    if (workDir && fs.existsSync(workDir)) {
      try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (e) {}
    }
    res.status(500).json({ 
      success: false, 
      error: error.message,
      details: "CLI execution failed. Check Render logs for git/npx errors."
    });
  }
});

function extractDeps(content) {
  const deps = [];
  // This looks for the package.json header and then grabs the JSON block following it
  const pkgSection = content.match(/package\.json[\s\S]*?({[\s\S]*?"dependencies"[\s\S]*?})/i);
  
  if (pkgSection) {
    try {
      // Clean up the match to ensure it's valid JSON
      const pkg = JSON.parse(pkgSection[1].trim());
      const all = { ...pkg.dependencies, ...pkg.devDependencies };
      
      Object.entries(all).forEach(([name, ver]) => {
        // Clean version strings like "^1.2.3" to "1.2.3"
        const cleanVer = ver.toString().replace(/[\^~]/g, '');
        deps.push({ name, version: cleanVer, ecosystem: 'npm' });
      });
      console.log(`📦 Extracted ${deps.length} dependencies for OSV check.`);
    } catch (e) {
      console.log("⚠️ Could not parse package.json content for dependencies.");
    }
  }
  return deps;
}

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Bridge Online on port ${PORT}`));