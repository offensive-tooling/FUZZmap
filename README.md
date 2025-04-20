# FUZZmap 

<div align="center">
  
[![Python 3.13.0](https://img.shields.io/badge/python-3.13.0-yellow.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)

**Web Application Vulnerability Fuzzing Tool**

*Current version: 0.2 (SQL Injection, XSS)*

</div>

<p align="center">
  <img src="https://img.shields.io/badge/%F0%9F%94%8D-Fuzzing-blueviolet" alt="Fuzzing">
  <img src="https://img.shields.io/badge/%F0%9F%93%8A-Parameter%20Collection-green" alt="Parameter Reconnaissance">
  <img src="https://img.shields.io/badge/%F0%9F%9B%A1%EF%B8%8F-Vulnerability%20Detection-orange" alt="Vulnerability Detection">
</p>

FUZZmap is a web application vulnerability fuzzing tool designed to detect security flaws. It identifies web application vulnerabilities through automated parameter Reconnaissance and advanced payload testing.
![alt text](image.png)


## 💻 FUZZmap Developers
- [arrester](https://github.com/arrester)
- [jhanks](https://github.com/jeongahn)
- [mathe](https://github.com/ma4the)
- [arecia](https://github.com/areciah)
- [hansowon](https://github.com/hansowon)

## ✨ Features

- **Parameter Reconnaissance**
- **Common Payload Testing**
- **Advanced Payload Testing**
  - **SQL Injection Detection** - Advanced analysis including error-based, time-based, and boolean-based techniques (v0.1)
  - **XSS Detection** - Advanced analysis including advanced xss in v0.2
  - **SSTI Detection** - *(Advanced analysis coming in v0.3)*
- **Asynchronous Architecture** - Utilizes `asyncio` and semaphores for optimized concurrent testing
- **Expandable Framework** - Designed for easy addition of new vulnerability types in future versions

## 📋 Installation

### Using pip
```bash
# Installation
pip install fuzzmap
```

### From GitHub
```bash
# Git clone
git clone https://github.com/offensive-tooling/FUZZmap.git
cd fuzzmap

# Installation
pip install -e .
```

## 🚀 Usage

### Command Line Usage

```bash
# Test specific parameter
fuzzmap -t <target_url> -m get -p <target_parameter>

# Test multiple parameters
fuzzmap -t <target_url> -m get -p <target_parameter 1>,<target_parameter 2>

# Use POST method
fuzzmap -t <target_url> -m post -p <target_parameter>

# Test with Parameter Reconnaissance 
fuzzmap -t <target_url> -rp
```

### Python Module Usage

```python
import asyncio
from fuzzmap.core.controller.controller import Controller

async def main():
    # Test with specific parameters
    fm = Controller(target="http://target.com", method="GET", param=["target_parameter"])
    results = await fm.async_run()
    
    # Test with Parameter Reconnaissance
    fm = Controller(target="http://target.com", recon_param=True)
    results = await fm.async_run()

asyncio.run(main())
```

## 🛠️ How It Works

FuzzMap operates in four main phases:

1. **Parameter Reconnaissance**: Automatically identifies parameters through:
   - URL query extraction
   - Form field analysis (inputs, selects, textareas)
   - Form action paths and methods
   - *(JavaScript hidden parameters - release later)*
   - *(Dynamic parameter collection module - release later)*

2. **Common Payload Testing**: Tests various vulnerabilities with common payloads:
   - SQL Injection
   - XSS (Cross Site Scripting)
   - SSTI (Server Side Template Injection)
   - *(More types to be continuously added)*

3. **Advanced Payload Testing** (Currently for SQL Injection only):
   - SQL Injection (error-based, time-based, boolean-based)
   - *(XSS payloads and features coming in v0.2)*
   - *(SSTI payloads and features coming in v0.3)*

4. **Result Classification**: Categorize findings as follows:
   - Vulnerability type and subtype
   - Detection confidence scoring (0-100%)
   - Detection details and evidence

## 📊 Example Output

```
handler: common, advanced
🎯 url: http://target.com/
parameters: ['test', 'searchFor']
method: GET
Type: xss
💰 Detected: True
Common_payload: '"><iframe onload=alert('{{1234**3}}');>
Common_Confidence: 50
🔍 Detail_Vuln: Error-Based SQL Injection
Advanced_payload: ' UNION SELECT NULL-- -
Advanced_Confidence: 100
Context: ECT NULL-- -</h2>Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '

------------------------------------------------------------------
handler: common, advanced
🎯 url: http://target.com/
parameters: ['test', 'searchFor']
method: GET
Type: sql_injection
💰 Detected: True
Common_payload: ' || BEGIN DBMS_SESSION.SLEEP(5); END; -- 
Common_Confidence: 70
🔍 Detail_Vuln: Error-Based SQL Injection
Advanced_payload: ' UNION SELECT NULL-- -
Advanced_Confidence: 100
Context: ECT NULL-- -</h2>Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '
```

## ⚙️ Command Line Options

```
-t, --target    🎯 Target URL to scan
-m, --method    📡 HTTP method (GET/POST)
-p, --param     🔍 Parameters to test (comma separated)
-rp, --recon    🔎 Enable parameter reconnaissance
-v, --verbose   📝 Enable verbose output
-h, --help      ℹ️  Show help message
```

## 📝 Translations

- [English (Original)](README.md)
- [Korean](fuzzmap/doc/translations/README-KR.md)

## 🔔 Disclaimer

FUZZmap is designed for legitimate security testing with proper authorization. Always ensure you have permission before testing any website or application.

---

<div align="center">
  <b>FUZZmap - Slogan (Coming Soon)</b>
</div>