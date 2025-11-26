# Security Principles

This tool follows current enterprise and industry security standards:

- **Hashing:** Only secure hashing algorithms (bcrypt, future Argon2id)
- **Salting:** All hashes generated include a unique salt
- **Compliance:** Follows NIST and OWASP password recommendations
- **Education:** Explains vulnerabilities (rainbow tables, brute-force)
- **No password logging or storage**

For more, see `src/hash_comparator.py` and `data/password_policies.json`.
