# Cybersecurity & Password Security Analyzer

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.29.0-FF4B4B.svg)](https://streamlit.io)

> A comprehensive security assessment tool demonstrating enterprise password protection strategies

## 🔐 Overview

This project applies cybersecurity principles from my **Goldman Sachs** and **Mastercard** job simulations on Forage to deliver a robust password security analysis platform. It provides real-time password strength assessment, hash algorithm comparisons, vulnerability detection, and educational insights into password security best practices.

## ✨ Features

### 1. **Password Strength Analyzer**
- Real-time password strength evaluation
- Entropy calculation and complexity scoring
- Character pattern analysis
- Dictionary and common password detection
- Visual strength indicators

### 2. **Hash Algorithm Comparison Tool**
- Support for multiple hash algorithms (MD5, SHA-1, SHA-256, SHA-512, bcrypt)
- Performance benchmarking
- Rainbow table vulnerability assessment
- Salt and pepper implementation demonstration

### 3. **Vulnerability Scanner**
- Common password detection against a bundled list of known weak passwords
- Pattern-based attack simulation
- Breach database cross-reference capability
- Password reuse detection

### 4. **Security Recommendations Engine**
- Personalized security recommendations
- Industry-standard compliance checking (NIST, OWASP)
- Password policy generator
- Multi-factor authentication guidance

### 5. **Educational Dashboard**
- Interactive learning modules
- Password security statistics
- Attack method demonstrations
- Best practices visualization

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/Abhinavsathyadas07/cybersecurity-password-analyzer.git
cd cybersecurity-password-analyzer

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Application

```bash
# Run the Streamlit dashboard
streamlit run app.py

# Or run CLI version
python cli_analyzer.py
```

## 📁 Project Structure

```
cybersecurity-password-analyzer/
│
├── app.py                          # Streamlit web application
├── cli_analyzer.py                 # Command-line interface
├── requirements.txt                # Project dependencies
├── README.md                       # Project documentation
├── LICENSE                         # MIT License
│
├── src/
│   ├── __init__.py
│   ├── password_analyzer.py        # Core password analysis logic
│   ├── hash_comparator.py          # Hash algorithm comparison
│   ├── vulnerability_scanner.py    # Vulnerability detection
│   ├── recommendation_engine.py    # Security recommendations
│   └── utils.py                    # Utility functions
│
├── data/
│   ├── common_passwords.txt        # Common password database
│   └── password_policies.json      # Industry password policies
│
├── tests/
│   ├── __init__.py
│   ├── test_analyzer.py
│   ├── test_hash_comparator.py
│   └── test_vulnerability_scanner.py
│
└── docs/
    ├── architecture.md
    ├── security_principles.md
    └── api_reference.md
```

## 🛠️ Tech Stack

- **Python 3.8+**: Core programming language
- **bcrypt**: Industry-standard password hashing
- **hashlib**: Cryptographic hash functions
- **Streamlit**: Interactive web dashboard
- **Plotly**: Data visualization
- **zxcvbn**: Password strength estimation
- **passlib**: Password hashing utilities

## 📊 Use Cases

- **Security Audits**: Assess organizational password policies
- **Education**: Learn about password security and cryptography
- **Development**: Integrate password validation into applications
- **Research**: Compare hashing algorithms and security strategies

## 🎯 Key Learnings

This project demonstrates:

- **Enterprise Security Practices**: Applied ideas from the Goldman Sachs and Mastercard job simulations on Forage
- **Cryptographic Principles**: Implementation of secure hashing, salting, and key derivation
- **Risk Assessment**: Vulnerability identification and mitigation strategies
- **Compliance Standards**: NIST SP 800-63B, OWASP password guidelines

## 📈 Features Roadmap

- [ ] Password breach API integration (HaveIBeenPwned)
- [ ] Machine learning-based password prediction
- [ ] Two-factor authentication simulator
- [ ] Password manager integration
- [ ] Advanced reporting and analytics
- [ ] Multi-language support

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Abhinav T S**
- GitHub: [@Abhinavsathyadas07](https://github.com/Abhinavsathyadas07)
- LinkedIn: [Abhinav T S](https://www.linkedin.com/in/abhinavsathyadas)
- Email: abhinavsathyadas@gmail.com

## 🙏 Acknowledgments

- Goldman Sachs Governance Analyst Simulation
- Mastercard Cybersecurity Job Simulation
- OWASP Foundation for security guidelines
- NIST for password security standards

---

**Note**: This tool is for educational and assessment purposes. Always follow your organization's security policies and guidelines.