# API Reference

## PasswordAnalyzer
- **analyze(password)**: Returns strength, complexity, entropy, patterns, and feedback

## HashComparator
- **compare_all(password, iterations)**: Benchmarks all hash algorithms
- **hash_password(password, algorithm, salt=None)**: Creates hash (supports MD5, SHA1, SHA256, SHA512, bcrypt)
- **verify_password(password, algorithm, stored_hash, salt=None)**: Verifies password against a stored hash

## VulnerabilityScanner
- **scan(password)**: Checks password against weak/common passwords

## RecommendationEngine
- **generate(analysis)**: Creates textual feedback and improvement suggestions

See docstrings in each module for argument and return info.
