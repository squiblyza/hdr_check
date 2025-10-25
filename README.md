# 🔍 HDR CHECK

A lightweight **Python CLI tool** for penetration testers and security engineers to quickly assess **HTTP response headers** for missing or misconfigured security controls — aligned with the [**OWASP Web Security Testing Guide (WSTG)**](https://owasp.org/www-project-web-security-testing-guide/).

This tool helps you identify common header misconfigurations that weaken browser-level protections and provides **clear, high-level remediation recommendations**.

---

## 🚀 Features

- ✅ Checks for common HTTP security headers:
  - **Strict-Transport-Security (HSTS)**
  - **Content-Security-Policy (CSP)**
  - **X-Frame-Options**
  - **X-Content-Type-Options**
  - **Referrer-Policy**
  - **Permissions-Policy (Feature-Policy)**
  - **Expect-CT**
  - **Set-Cookie** flags (`Secure`, `HttpOnly`, `SameSite`)
  - **Cross-Origin** headers (`COOP`, `COEP`, `CORP`)
  - **Server / X-Powered-By** info leakage
- 🧠 Recommendations aligned with OWASP WSTG & OWASP Secure Headers Cheat Sheet
- 🎨 Color-coded CLI output (red for FAIL, green for PASS)
- ⚙️ Optional JSON output for pipelines or automated reporting
- 🧪 Simple to run, easy to extend

---

## 🧰 Installation

Clone this repository and install the required dependencies:

```bash
git clone https://github.com/squiblyza/hdr_check.git
cd hdr_check
pip install -r requirements.txt
