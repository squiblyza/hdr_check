# hdr_check

Small CLI tool to fetch one or more URLs and report on common HTTP security headers.

Features
- Uses `httpx` for HTTP(S) requests (default timeout 8s, TLS verification on).
- Uses `rich` for colored terminal output (green=PASS, red=FAIL, yellow=INFO).
- Optional machine-readable JSON output via `--json`.
- Checks: HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy/Feature-Policy, Expect-CT, Cross-Origin policies (COOP/COEP), Set-Cookie flags, Server/X-Powered-By disclosures.
- Exit codes: 0 = all PASS, 1 = any FAIL, 2 = network/runtime error or missing dependency.

Prerequisites
- Python 3.10+
- Required packages: httpx, rich (see Installation section)
# hdr_check

Small CLI tool to fetch one or more URLs and report on common HTTP security headers.

Features
- Uses `httpx` for HTTP(S) requests (default timeout 8s, TLS verification on).
- Uses `rich` for colored terminal output (green=PASS, red=FAIL, yellow=INFO).
- Optional machine-readable JSON output via `--json`.
- Checks: HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy/Feature-Policy, Expect-CT, Cross-Origin policies (COOP/COEP), Set-Cookie flags, Server/X-Powered-By disclosures.
- Exit codes: 0 = all PASS, 1 = any FAIL, 2 = network/runtime error or missing dependency.

Prerequisites
- Python 3.10+
- Required packages: httpx, rich (see Installation section)

Installation

Method 1: Using requirements.txt (recommended)
```bash
# Clone or download the repository
git clone <repository-url>
cd headersec

# Create and activate a virtual environment (recommended)
python -m venv venv
# Linux/macOS
source venv/bin/activate
# Windows (PowerShell)
venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

Method 2: Manual installation
```bash
# Install required packages directly
pip install httpx>=0.25.0 rich>=13.6.0
```
# hdr_check

Small CLI tool to fetch one or more URLs and report on common HTTP security headers.

Features
- Uses `httpx` for HTTP(S) requests (default timeout 8s, TLS verification on).
- Uses `rich` for colored terminal output (green=PASS, red=FAIL, yellow=INFO).
- Optional machine-readable JSON output via `--json`.
- Checks: HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy/Feature-Policy, Expect-CT, Cross-Origin policies (COOP/COEP), Set-Cookie flags, Server/X-Powered-By disclosures.
- Exit codes: 0 = all PASS, 1 = any FAIL, 2 = network/runtime error or missing dependency.

Prerequisites
- Python 3.10+
- Required packages: httpx, rich (see Installation section)

Installation

Method 1: Using requirements.txt (recommended)
```bash
# Clone or download the repository
git clone <repository-url>
cd headersec

# Create and activate a virtual environment (recommended)
python -m venv venv
# Linux/macOS
source venv/bin/activate
# Windows (Command Prompt)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

Method 2: Manual installation
```bash
# Install required packages directly
pip install httpx>=0.25.0 rich>=13.6.0
```
# hdr_check

Small CLI tool to fetch one or more URLs and report on common HTTP security headers.

Features
- Uses `httpx` for HTTP(S) requests (default timeout 8s, TLS verification on).
- Uses `rich` for colored terminal output (green=PASS, red=FAIL, yellow=INFO).
- Optional machine-readable JSON output via `--json`.
- Checks: HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy/Feature-Policy, Expect-CT, Cross-Origin policies (COOP/COEP), Set-Cookie flags, Server/X-Powered-By disclosures.
- Exit codes: 0 = all PASS, 1 = any FAIL, 2 = network/runtime error or missing dependency.

Prerequisites
- Python 3.10+
- Required packages: httpx, rich (see Installation section)

Installation

Method 1: Using requirements.txt (recommended)
```bash
# Clone the repository
git clone https://github.com/squiblyza/hdr_check.git
cd hdr_check

# Create and activate a virtual environment (recommended)
python -m venv venv
# Linux/macOS
source venv/bin/activate
# Windows (Command Prompt or PowerShell)
venv\\Scripts\\activate

# Install dependencies
pip install -r requirements.txt
```

Method 2: Manual installation
```bash
# Install required packages directly
pip install httpx>=0.25.0 rich>=13.6.0
```

After installation:
1. Ensure `hdr_check.py` is executable (on Linux/macOS) or run with `python hdr_check.py`.
2. Test the installation:
```bash
python hdr_check.py --help
```

Quick usage
```bash
# Basic single URL
python hdr_check.py https://example.com

# Multiple URLs
python hdr_check.py https://example.com https://example.org

# Follow redirects
python hdr_check.py --follow-redirects https://example.com

# Custom timeout (seconds)
python hdr_check.py --timeout 5 https://example.com

# JSON output for automation
python hdr_check.py --json https://example.com > report.json
```

Notes
- The script intentionally does not crawl or paginate; it checks only the provided URL(s).
- If you see a message about missing `httpx` or `rich`, install them with `pip install httpx rich`.
- Recommendations shown are concise OWASP WSTG-style guidance; use them as starting points for remediation and testing.

License
MIT-style permissive for private use. Modify as needed.

You can enable the provided GitHub Actions workflow (already included at `.github/workflows/ci.yml`) to run CI on pushes and PRs.
