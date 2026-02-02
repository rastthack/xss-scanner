# XSS Scanner

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8+-green.svg)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)

Professional Cross-Site Scripting (XSS) vulnerability scanner for web applications.

---

## 👋 About Developer

**Name:** rastthack 
**GitHub:** [@rastthack](https://github.com/rastthack)  
**Email:** rastthack@gmail.com  
**Profession:** Cyber Security Researcher  
**Location:** Dhaka, Bangladesh

---

## 📋 About This Tool

XSS Scanner is a professional, production-ready tool for detecting Cross-Site Scripting (XSS) vulnerabilities in web applications. Built with security researchers and penetration testers in mind.

This tool helps identify reflected XSS vulnerabilities by:
- Testing parameters with 20+ carefully crafted payloads
- Analyzing responses for vulnerable patterns
- Generating professional reports for documentation

**Perfect for:**
- ✅ Security researchers
- ✅ Penetration testers
- ✅ Web developers
- ✅ Bug bounty hunters
- ✅ Security audits

---

## ✨ Features

- 🎯 **20+ XSS Payloads** - From basic to advanced filter evasion techniques
- 🔍 **Smart Detection System** - Distinguishes safe reflection from exploitable XSS
- 📊 **Multiple Report Formats** - JSON and text reports for documentation
- 🚀 **Cross-Platform Support** - Works on Windows, Mac, and Linux
- ⚡ **Fast & Efficient** - Rapid vulnerability scanning
- 📖 **Well Documented** - Complete documentation and examples
- 🔒 **Production Ready** - Error handling, rate limiting, SSL verification
- 📦 **Standalone Executables** - No Python installation required for users

---

## 🚀 Quick Start

### Windows
```bash
# Download XSSScanner.exe from Releases
XSSScanner.exe -u "http://example.com/search?q=test"
```

### Mac
```bash
# Download XSSScanner from Releases
chmod +x XSSScanner
./XSSScanner -u "http://example.com/search?q=test"
```

### Linux
```bash
# Download xss-scanner from Releases
chmod +x xss-scanner
./xss-scanner -u "http://example.com/search?q=test"
```

### Python (Any OS)
```bash
# Install dependencies
pip install -r requirements.txt

# Run scanner
python xss_scanner.py -u "http://example.com/search?q=test"
```

---

## 📥 Installation Methods

### Method 1: Download Executable (Easiest)
1. Go to [Releases](https://github.com/rastthack/xss-scanner/releases)
2. Download for your OS
3. Run directly!

### Method 2: From Source
```bash
git clone https://github.com/rastthack/xss-scanner.git
cd xss-scanner
pip install -r requirements.txt
python xss_scanner.py -u "http://example.com/search?q=test"
```

### Method 3: pip Install
```bash
pip install xss-scanner
xss-scanner -u "http://example.com/search?q=test"
```

---

## 🎯 Usage Examples

### Basic Scan
```bash
xss-scanner -u "http://example.com/search?q=test"
```

### Save Results to JSON
```bash
xss-scanner -u "http://example.com/search?q=test" -f json -o results.json
```

### Verbose Output
```bash
xss-scanner -u "http://example.com/search?q=test" -v
```

### Custom Timeout
```bash
xss-scanner -u "http://example.com/search?q=test" --timeout 20
```

---

## 🔍 How It Works

### Step 1: Parameter Extraction
Extracts all GET/POST parameters from the target URL.

### Step 2: Payload Testing
Tests each parameter with 20+ payloads of varying complexity:
- Basic payloads: `<script>alert(1)</script>`
- Intermediate: `<img src=x onerror="alert(1)">`
- Advanced: `<ScRiPt>alert(1)</ScRiPt>`
- Bypass: Special encoding techniques

### Step 3: Reflection Detection
Checks if payloads appear in the response without proper encoding.

### Step 4: Vulnerability Analysis
Analyzes the context to determine if the reflection is exploitable as XSS.

### Step 5: Report Generation
Creates detailed reports (JSON/Text) with findings.

---

## 📊 Output Example

```
[*] Starting XSS Vulnerability Scan
[*] Target URL: http://example.com/search?q=test

[*] Extracting parameters from URL...
[+] Found 1 parameters: q

[*] Testing parameter: q
[+] VULNERABILITY FOUND!
    Parameter: q
    Pattern: script_tag
    Payload: <script>alert("xss")</script>
    Context: Search results contain unescaped payload

[!] Found 1 vulnerability(ies)
```

---

## ⚖️ Legal & Ethical Notice

### ✅ Authorized Use

This tool should ONLY be used for:
- ✅ Your own applications and websites
- ✅ Authorized security testing with written permission
- ✅ Bug bounty programs (verify rules first)
- ✅ Penetration testing engagements
- ✅ Security research and education

### ❌ Unauthorized Use

- ❌ **Unauthorized access to systems is ILLEGAL**
- ❌ Testing without explicit permission is a crime
- ❌ Violating computer fraud laws
- ❌ Unauthorized network testing

### ⚠️ Disclaimer

The author is NOT responsible for:
- Misuse of this tool
- Unauthorized testing
- Legal consequences
- Damage to systems

**Always get written permission before testing!**

---

## 🔧 Requirements

- Python 3.8 or higher
- requests library (for HTTP requests)
- pyinstaller (only for building executables)

## 📦 Dependencies

```
requests>=2.28.0
```

---

## 🏗️ Project Structure

```
xss-scanner/
├── xss_scanner.py           # Main scanner
├── requirements.txt         # Dependencies
├── README.md               # This file
├── LICENSE                 # MIT License
├── .github/
│   └── workflows/
│       └── build.yml       # GitHub Actions CI/CD
└── dist/                   # Compiled executables
    ├── xss-scanner         # Linux
    ├── XSSScanner          # Mac
    └── XSSScanner.exe      # Windows
```

---

## 🛠️ Technologies Used

- **Language:** Python 3.10+
- **Framework:** Requests library
- **Packaging:** PyInstaller
- **CI/CD:** GitHub Actions
- **Version Control:** Git & GitHub

---

## 📈 Performance

- **Scanning Speed:** 2-5 minutes per parameter
- **Payload Count:** 20+ payloads per parameter
- **Network Efficiency:** Rate limiting (0.2s delay)
- **Memory Usage:** Minimal footprint
- **CPU Usage:** Efficient single-threaded design

---

## 🐛 Known Limitations

1. **Reflected XSS Only** - Detects reflected XSS (DOM-based XSS in future)
2. **No JavaScript Execution** - Doesn't execute JavaScript
3. **Manual Session Handling** - Limited session management
4. **Encoding Detection** - May have false positives

---

## 🚀 Roadmap

- [ ] DOM-based XSS detection
- [ ] JavaScript execution support
- [ ] Advanced session handling
- [ ] Proxy support
- [ ] Web UI dashboard
- [ ] Parallel scanning
- [ ] Custom payload support

---

## 🤝 Contributing

Found a bug? Have an idea? Want to contribute?

1. **Report Issues:** [GitHub Issues](https://github.com/rastthack/xss-scanner/issues)
2. **Feature Requests:** [Discussions](https://github.com/rastthack/xss-scanner/discussions)
3. **Pull Requests:** Always welcome!

---

## 📞 Contact & Support

- **Email:** rastthack@gmail.com
- **GitHub:** [@rastthack](https://github.com/rastthack)
- **Issues:** [Report here](https://github.com/rastthack/xss-scanner/issues)

---

## 📚 Learning Resources

### About XSS
- [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Tutorial](https://portswigger.net/web-security/cross-site-scripting)
- [HackerOne XSS Basics](https://www.hackerone.com/hackers/how-to-report-xss-vulnerabilities)

### Web Security
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTheBox](https://www.hackthebox.com/)

---

### MIT License Summary
- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ⚠️ Liability limited
- ⚠️ Warranty limited

---

## 🎯 Statistics

- **Payloads:** 20+
- **Supported Platforms:** 3 (Windows, Mac, Linux)
- **Python Version:** 3.8+
- **License:** MIT
- **Repository:** [GitHub](https://github.com/rastthack/xss-scanner)

---

## 🌟 Show Your Support

If you find this tool useful:

- ⭐ **Star** this repository
- 🍴 **Fork** it and contribute
- 🐦 **Share** on social media
- 💬 **Discuss** in the community
- 🐛 **Report** bugs and issues
- 💡 **Suggest** features

---

## 👨‍💻 Author

**rastthack**
- 🏆 Cyber Security Researcher
- 🐱 GitHub: [@rastthack](https://github.com/rastthack)

---

## 📋 Changelog

### Version 3.0.0
- ✅ Initial public release
- ✅ 20+ XSS payloads
- ✅ Smart detection algorithm
- ✅ Cross-platform support
- ✅ Professional reporting

---

<div align="center">

## Made with ❤️ by rastthack

### Security is not a feature, it's a responsibility.

</div>

---

**Last Updated:** February 2, 2026  
**Status:** Production Ready ✅  
**Maintained By:** (rastthack)


