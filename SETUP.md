# Setup Guide

Comprehensive setup instructions for the Cybersecurity & Password Security Analyzer.

## Prerequisites

- **Python 3.8 or higher**
- **pip** (Python package manager)
- **git** (for cloning the repository)

## Installation Methods

### Method 1: Standard Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/Abhinavsathyadas07/cybersecurity-password-analyzer.git
cd cybersecurity-password-analyzer

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Method 2: Quick Test (No Virtual Environment)

```bash
# Clone and install
git clone https://github.com/Abhinavsathyadas07/cybersecurity-password-analyzer.git
cd cybersecurity-password-analyzer
pip install -r requirements.txt
```

### Method 3: Development Installation

For developers who want to modify the code:

```bash
# Clone the repository
git clone https://github.com/Abhinavsathyadas07/cybersecurity-password-analyzer.git
cd cybersecurity-password-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install in editable mode
pip install -e .

# Install development dependencies
pip install pytest pytest-cov black flake8
```

## Running the Application

### Streamlit Web Dashboard

```bash
# Make sure you're in the project directory
streamlit run app.py
```

The dashboard will open automatically in your default web browser at `http://localhost:8501`.

### Command-Line Interface

#### Basic Usage

```bash
# Analyze a password
python cli_analyzer.py "MyPassword123!"

# Verbose mode (detailed analysis)
python cli_analyzer.py "MyPassword123!" --verbose

# Interactive mode
python cli_analyzer.py --interactive

# Compare hash algorithms
python cli_analyzer.py "MyPassword123!" --hash
```

#### Making CLI Executable (Optional)

**On macOS/Linux:**
```bash
chmod +x cli_analyzer.py
./cli_analyzer.py "MyPassword123!"
```

**On Windows:**
Create a batch file `analyze.bat`:
```batch
@echo off
python cli_analyzer.py %*
```

Then use:
```cmd
analyze.bat "MyPassword123!"
```

## Verification

### Test Installation

```bash
# Test imports
python -c "from src.password_analyzer import PasswordAnalyzer; print('✓ Installation successful!')"

# Run a quick analysis
python cli_analyzer.py "TestPassword123!"
```

### Run Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=src tests/
```

## Troubleshooting

### Common Issues

#### ImportError: No module named 'streamlit'

**Solution:** Install dependencies
```bash
pip install -r requirements.txt
```

#### bcrypt installation fails

**Solution:** Install build tools

**On Windows:**
```bash
pip install --upgrade pip setuptools wheel
pip install bcrypt
```

**On macOS:**
```bash
brew install rust
pip install bcrypt
```

**On Linux:**
```bash
sudo apt-get install build-essential libffi-dev python3-dev
pip install bcrypt
```

#### Port 8501 already in use (Streamlit)

**Solution:** Use a different port
```bash
streamlit run app.py --server.port 8502
```

#### Permission denied on cli_analyzer.py

**Solution:** Make it executable
```bash
chmod +x cli_analyzer.py
```

### Python Version Issues

This project requires **Python 3.8+**. Check your version:

```bash
python --version
```

If you have multiple Python versions, use:
```bash
python3 --version
python3 -m venv venv
```

## Platform-Specific Notes

### macOS

- If using Homebrew Python: `brew install python@3.11`
- Default Python may be 2.7, use `python3` explicitly

### Windows

- Use PowerShell or Command Prompt
- Activate venv: `.\venv\Scripts\activate`
- May need to enable script execution: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

### Linux

- Install Python dev packages: `sudo apt-get install python3-dev`
- May need to install pip separately: `sudo apt-get install python3-pip`

## Configuration

### Customizing Common Passwords Database

Edit `data/common_passwords.txt` to add or remove passwords:

```bash
echo "newweakpassword" >> data/common_passwords.txt
```

### Customizing Password Policies

Edit `data/password_policies.json` to modify compliance standards:

```json
{
    "CustomPolicy": {
        "min_length": 16,
        "requirements": ["uppercase", "lowercase", "digit", "special"]
    }
}
```

### Adjusting bcrypt Work Factor

In `src/hash_comparator.py`, modify:

```python
self.bcrypt_rounds = 12  # Increase for more security (slower)
```

## Production Deployment

### Using Docker (Future)

```bash
# Build image
docker build -t password-analyzer .

# Run container
docker run -p 8501:8501 password-analyzer
```

### Using Cloud Services

**Streamlit Cloud:**
1. Push to GitHub
2. Visit [streamlit.io/cloud](https://streamlit.io/cloud)
3. Connect repository
4. Deploy!

**Heroku:**
```bash
heroku create your-app-name
git push heroku main
```

## Getting Help

If you encounter issues:

1. Check the [GitHub Issues](https://github.com/Abhinavsathyadas07/cybersecurity-password-analyzer/issues)
2. Review the [Documentation](docs/)
3. Contact: abhinavsathyadas@gmail.com

## Next Steps

- Explore the [API Reference](docs/api_reference.md)
- Read about [Security Principles](docs/security_principles.md)
- Check the [Architecture](docs/architecture.md)
- Start analyzing passwords!

---

**Happy Analyzing! Stay Secure! 🔐**
