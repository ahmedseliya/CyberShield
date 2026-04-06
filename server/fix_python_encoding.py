import sys
import os
import site
import subprocess

print("🔧 Fixing Python encoding for Semgrep...")

# Set environment variables for UTF-8
os.environ['PYTHONIOENCODING'] = 'utf-8'
os.environ['PYTHONUTF8'] = '1'

# Create a sitecustomize.py file to force UTF-8
site_packages = site.getsitepackages()[0]
sitecustomize_path = os.path.join(site_packages, 'sitecustomize.py')

sitecustomize_content = '''
import sys
import locale

# Force UTF-8 encoding
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')
sys.stdin.reconfigure(encoding='utf-8')

# Set default encoding
locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
'''

try:
    with open(sitecustomize_path, 'w', encoding='utf-8') as f:
        f.write(sitecustomize_content)
    print(f"✅ Created sitecustomize.py at {sitecustomize_path}")
except Exception as e:
    print(f"❌ Failed to create sitecustomize.py: {e}")

# Test Semgrep with UTF-8
semgrep_path = r"C:\Users\mrmsc\AppData\Local\Programs\Python\Python313\Scripts\semgrep.exe"
try:
    result = subprocess.run(
        [semgrep_path, "--version"],
        capture_output=True,
        text=True,
        encoding='utf-8',
        env={**os.environ, 'PYTHONIOENCODING': 'utf-8', 'PYTHONUTF8': '1'}
    )
    print(f"✅ Semgrep version: {result.stdout.strip()}")
except Exception as e:
    print(f"❌ Semgrep test failed: {e}")

print("✅ Python encoding fix completed!")