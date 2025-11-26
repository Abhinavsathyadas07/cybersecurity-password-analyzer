"""Hash Algorithm Comparison Module

Compares different hashing algorithms for password storage:
- MD5 (legacy, insecure)
- SHA-1 (legacy, insecure)
- SHA-256, SHA-512 (better but not recommended for passwords)
- bcrypt (recommended)
"""

import hashlib
import time
import bcrypt
from typing import Dict, List, Tuple
import secrets


class HashComparator:
    """Compares performance and security of different hash algorithms."""
    
    def __init__(self):
        self.algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt']
        self.bcrypt_rounds = 12  # Default bcrypt work factor
        
    def compare_all(self, password: str, iterations: int = 1000) -> Dict:
        """Compare all hash algorithms.
        
        Args:
            password: Password to hash
            iterations: Number of iterations for benchmarking
            
        Returns:
            Dictionary with comparison results
        """
        results = {}
        
        for algo in self.algorithms:
            results[algo] = self._benchmark_algorithm(algo, password, iterations)
        
        # Add security analysis
        results['security_analysis'] = self._security_analysis()
        results['recommendations'] = self._generate_recommendations()
        
        return results
    
    def hash_password(self, password: str, algorithm: str, salt: str = None) -> Dict:
        """Hash a password using specified algorithm.
        
        Args:
            password: Password to hash
            algorithm: Algorithm to use
            salt: Optional salt (generated if not provided)
            
        Returns:
            Dictionary with hash results
        """
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        result = {
            'algorithm': algorithm,
            'password_length': len(password),
            'salt': None,
            'hash': None,
            'hash_length': 0,
            'time_taken': 0
        }
        
        start_time = time.perf_counter()
        
        if algorithm == 'bcrypt':
            # bcrypt includes salt automatically
            hash_bytes = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=self.bcrypt_rounds))
            result['hash'] = hash_bytes.decode('utf-8')
            result['salt'] = 'Included in hash'
        else:
            # Generate salt if not provided
            if salt is None:
                salt = secrets.token_hex(16)
            result['salt'] = salt
            
            # Hash with salt
            salted_password = salt + password
            hash_obj = hashlib.new(algorithm)
            hash_obj.update(salted_password.encode('utf-8'))
            result['hash'] = hash_obj.hexdigest()
        
        result['time_taken'] = round((time.perf_counter() - start_time) * 1000, 4)  # milliseconds
        result['hash_length'] = len(result['hash'])
        
        return result
    
    def verify_password(self, password: str, algorithm: str, stored_hash: str, salt: str = None) -> bool:
        """Verify a password against a stored hash.
        
        Args:
            password: Password to verify
            algorithm: Algorithm used for hashing
            stored_hash: Stored hash to compare against
            salt: Salt used (not needed for bcrypt)
            
        Returns:
            True if password matches, False otherwise
        """
        if algorithm == 'bcrypt':
            try:
                return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
            except:
                return False
        else:
            if salt is None:
                raise ValueError(f"Salt required for {algorithm}")
            
            # Recreate hash and compare
            salted_password = salt + password
            hash_obj = hashlib.new(algorithm)
            hash_obj.update(salted_password.encode('utf-8'))
            computed_hash = hash_obj.hexdigest()
            
            return computed_hash == stored_hash
    
    def _benchmark_algorithm(self, algorithm: str, password: str, iterations: int) -> Dict:
        """Benchmark a specific algorithm.
        
        Args:
            algorithm: Algorithm to benchmark
            password: Test password
            iterations: Number of iterations
            
        Returns:
            Benchmark results
        """
        times = []
        hash_result = None
        
        for _ in range(iterations):
            start = time.perf_counter()
            
            if algorithm == 'bcrypt':
                hash_bytes = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=self.bcrypt_rounds))
                hash_result = hash_bytes.decode('utf-8')
            else:
                salt = secrets.token_hex(16)
                salted = salt + password
                hash_obj = hashlib.new(algorithm)
                hash_obj.update(salted.encode('utf-8'))
                hash_result = hash_obj.hexdigest()
            
            times.append(time.perf_counter() - start)
        
        avg_time = sum(times) / len(times) * 1000  # Convert to milliseconds
        min_time = min(times) * 1000
        max_time = max(times) * 1000
        
        return {
            'algorithm': algorithm,
            'iterations': iterations,
            'avg_time_ms': round(avg_time, 4),
            'min_time_ms': round(min_time, 4),
            'max_time_ms': round(max_time, 4),
            'sample_hash': hash_result,
            'hash_length': len(hash_result),
            'security_rating': self._get_security_rating(algorithm)
        }
    
    def _get_security_rating(self, algorithm: str) -> str:
        """Get security rating for an algorithm."""
        ratings = {
            'md5': 'Insecure - Not recommended',
            'sha1': 'Insecure - Deprecated',
            'sha256': 'Moderate - Not ideal for passwords',
            'sha512': 'Moderate - Not ideal for passwords',
            'bcrypt': 'Secure - Recommended'
        }
        return ratings.get(algorithm, 'Unknown')
    
    def _security_analysis(self) -> Dict:
        """Provide security analysis of algorithms."""
        return {
            'md5': {
                'year_introduced': 1992,
                'vulnerabilities': [
                    'Collision attacks possible',
                    'Rainbow table attacks',
                    'Very fast to compute',
                    'Broken since 2004'
                ],
                'use_case': 'Checksums only, never for passwords'
            },
            'sha1': {
                'year_introduced': 1995,
                'vulnerabilities': [
                    'Collision attacks demonstrated (SHAttered)',
                    'Rainbow table attacks',
                    'Fast to compute',
                    'Deprecated by NIST'
                ],
                'use_case': 'Legacy systems only, migrate away'
            },
            'sha256': {
                'year_introduced': 2001,
                'vulnerabilities': [
                    'Too fast for password hashing',
                    'Vulnerable to GPU acceleration',
                    'No built-in salt or key stretching'
                ],
                'use_case': 'Data integrity, not password storage'
            },
            'sha512': {
                'year_introduced': 2001,
                'vulnerabilities': [
                    'Too fast for password hashing',
                    'Vulnerable to GPU acceleration',
                    'No built-in salt or key stretching'
                ],
                'use_case': 'Data integrity, not password storage'
            },
            'bcrypt': {
                'year_introduced': 1999,
                'vulnerabilities': [
                    'Relatively slow (by design)',
                    'Password length limited to 72 bytes'
                ],
                'use_case': 'Password storage (recommended)'
            }
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations."""
        return [
            "Always use bcrypt, scrypt, or Argon2 for password storage",
            "Never use MD5 or SHA-1 for passwords",
            "SHA-256/512 are not designed for password hashing",
            "Use a minimum of 12 rounds for bcrypt",
            "Always use a unique salt per password",
            "Consider using Argon2id for new applications",
            "Implement rate limiting to prevent brute force attacks",
            "Store hashes in a secure database with proper access controls",
            "Use HTTPS to protect passwords in transit",
            "Implement proper password policies and complexity requirements"
        ]
    
    def demonstrate_rainbow_table_vulnerability(self, password: str) -> Dict:
        """Demonstrate rainbow table vulnerability with unsalted hashes.
        
        Args:
            password: Password to demonstrate with
            
        Returns:
            Demonstration results
        """
        results = {
            'password': password,
            'unsalted_hashes': {},
            'salted_hashes': {},
            'explanation': ''
        }
        
        # Generate unsalted hashes
        for algo in ['md5', 'sha1', 'sha256']:
            hash_obj = hashlib.new(algo)
            hash_obj.update(password.encode('utf-8'))
            results['unsalted_hashes'][algo] = hash_obj.hexdigest()
        
        # Generate salted hashes
        salt = secrets.token_hex(16)
        for algo in ['md5', 'sha1', 'sha256']:
            hash_obj = hashlib.new(algo)
            hash_obj.update((salt + password).encode('utf-8'))
            results['salted_hashes'][algo] = {
                'salt': salt,
                'hash': hash_obj.hexdigest()
            }
        
        results['explanation'] = (
            "Rainbow tables contain precomputed hashes of common passwords. "
            "Unsalted hashes can be looked up instantly in these tables. "
            "Adding a unique salt to each password prevents rainbow table attacks, "
            "as attackers would need to compute a new rainbow table for each salt."
        )
        
        return results
    
    def calculate_hash_rate(self, algorithm: str, duration_seconds: int = 1) -> Dict:
        """Calculate hashes per second for an algorithm.
        
        Args:
            algorithm: Algorithm to test
            duration_seconds: How long to run the test
            
        Returns:
            Hash rate results
        """
        password = "test_password_123"
        count = 0
        start_time = time.time()
        
        while time.time() - start_time < duration_seconds:
            if algorithm == 'bcrypt':
                bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=self.bcrypt_rounds))
            else:
                hash_obj = hashlib.new(algorithm)
                hash_obj.update(password.encode('utf-8'))
                _ = hash_obj.hexdigest()
            count += 1
        
        actual_duration = time.time() - start_time
        hashes_per_second = count / actual_duration
        
        return {
            'algorithm': algorithm,
            'duration_seconds': round(actual_duration, 2),
            'total_hashes': count,
            'hashes_per_second': round(hashes_per_second, 2),
            'interpretation': self._interpret_hash_rate(algorithm, hashes_per_second)
        }
    
    def _interpret_hash_rate(self, algorithm: str, rate: float) -> str:
        """Interpret what the hash rate means for security."""
        if algorithm == 'bcrypt':
            return f"Slow by design. Attackers can try ~{rate:.0f} passwords/second (good for security)."
        else:
            return f"Very fast. Attackers with GPUs can try billions/second (bad for passwords)."