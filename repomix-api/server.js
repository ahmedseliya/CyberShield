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

// Ensure temp directory exists at startup
const GLOBAL_TEMP_DIR = path.join(__dirname, 'temp');
if (!fs.existsSync(GLOBAL_TEMP_DIR)) {
    fs.mkdirSync(GLOBAL_TEMP_DIR, { recursive: true });
}

app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'Repomix Bridge API', timestamp: new Date().toISOString() });
});

app.post('/analyze', async (req, res) => {
    let tempDir = '';
    try {
        const { url, format = 'text', include = 'code', excludePatterns, maxSize = 500000 } = req.body;
        
        if (!url) {
            return res.status(400).json({ error: 'Repository URL is required' });
        }

        tempDir = path.join(GLOBAL_TEMP_DIR, Date.now().toString());
        fs.mkdirSync(tempDir, { recursive: true });
        
        const outputPath = path.join(tempDir, 'output.txt');
        
        // Use the absolute path to the node_modules binary
        const repomixBinary = path.join(__dirname, 'node_modules', '.bin', 'repomix');
        
        const cmd = [
            `"${repomixBinary}"`,
            `--remote "${url}"`,
            `--output "${outputPath}"`,
            `--include "${include}"`,
            '--style detailed',
            '--quiet'
        ].join(' ');

        console.log(`🚀 Executing: ${cmd}`);
        
        // Increase timeout to 5 minutes for larger repos
        const { stderr } = await execPromise(cmd, {
            timeout: 300000, 
            maxBuffer: 15 * 1024 * 1024 
        });

        if (stderr) console.warn('Repomix Stderr:', stderr);
        
        if (!fs.existsSync(outputPath)) {
            throw new Error('Repomix failed to generate output file.');
        }
        
        let content = fs.readFileSync(outputPath, 'utf-8');
        
        const patterns = Array.isArray(excludePatterns) ? excludePatterns : ['node_modules', 'dist', '.git'];
        content = filterExcludedContent(content, patterns);
        
        const fileCount = (content.match(/File:/gi) || []).length;
        const dependencies = extractDependencies(content);
        const fileStructure = extractFileStructure(content);
        const summary = generateSummary(content, fileCount);
        
        if (content.length > maxSize) {
            content = content.substring(0, maxSize) + '\n\n... (truncated)';
        }
        
        // Cleanup after success
        fs.rmSync(tempDir, { recursive: true, force: true });
        
        res.json({
            success: true,
            rawText: content,
            dependencies,
            fileStructure: fileStructure.slice(0, 100),
            fileCount,
            summary,
            metadata: { repository: url, analyzedAt: new Date().toISOString() }
        });
        
    } catch (error) {
        console.error('❌ Error:', error.message);
        if (tempDir && fs.existsSync(tempDir)) {
            try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (e) {}
        }
        
        res.status(500).json({
            success: false,
            error: error.message,
            details: 'Repomix execution failed. Ensure the repo is public.'
        });
    }
});

// --- HELPER FUNCTIONS ---

function filterExcludedContent(content, excludePatterns) {
    const lines = content.split('\n');
    const filteredLines = [];
    let skipCurrentFile = false;
    
    for (const line of lines) {
        const fileMatch = line.match(/File:\s*(.+)/i);
        if (fileMatch) {
            const currentFile = fileMatch[1].trim();
            skipCurrentFile = excludePatterns.some(p => currentFile.includes(p));
            if (!skipCurrentFile) filteredLines.push(line);
        } else if (!skipCurrentFile) {
            filteredLines.push(line);
        }
    }
    return filteredLines.join('\n');
}

function extractDependencies(content) {
    const dependencies = [];
    const packageJsonMatch = content.match(/File: .*package\.json[\s\S]*?```json\s*([\s\S]*?)```/i);
    if (packageJsonMatch) {
        try {
            const pkg = JSON.parse(packageJsonMatch[1].trim());
            const combine = { ...pkg.dependencies, ...pkg.devDependencies };
            Object.entries(combine).forEach(([name, ver]) => {
                dependencies.push({ ecosystem: 'npm', name, version: ver.replace(/[^\d.]/g, ''), source: 'package.json' });
            });
        } catch (e) { console.error("Dep Parse Error", e); }
    }
    return dependencies;
}

function extractFileStructure(content) {
    const files = [];
    const matches = content.matchAll(/File:\s*(.+)/gi);
    for (const match of matches) {
        if (!match[1].includes('node_modules')) files.push(match[1].trim());
    }
    return files;
}

function generateSummary(content, fileCount) {
    const tech = [];
    if (content.toLowerCase().includes('react')) tech.push('React');
    if (content.toLowerCase().includes('express')) tech.push('Express');
    if (content.toLowerCase().includes('python')) tech.push('Python');
    return `${tech.join('/') || 'Web'} app with ${fileCount} files analyzed.`;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Bridge Online on port ${PORT}`));