"""Password Strength Analyzer Module

Provides comprehensive password strength analysis including:
- Entropy calculation
- Character complexity scoring
- Pattern detection
- Dictionary attack resistance
"""

import re
import math
import string
from typing import Dict, List, Tuple
try:
    import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False


class PasswordAnalyzer:
    """Analyzes password strength using multiple metrics and algorithms."""
    
    def __init__(self):
        self.min_length = 8
        self.recommended_length = 12
        self.strong_length = 16
        
    def analyze(self, password: str) -> Dict:
        """Perform comprehensive password analysis.
        
        Args:
            password: The password to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        if not password:
            return self._empty_result()
            
        results = {
            'length': len(password),
            'entropy': self._calculate_entropy(password),
            'complexity_score': self._calculate_complexity(password),
            'character_analysis': self._analyze_characters(password),
            'pattern_analysis': self._detect_patterns(password),
            'strength_level': '',
            'score': 0,
            'feedback': [],
            'crack_time': ''
        }
        
        # Calculate overall score (0-100)
        results['score'] = self._calculate_overall_score(results)
        results['strength_level'] = self._determine_strength_level(results['score'])
        results['crack_time'] = self._estimate_crack_time(results['entropy'])
        results['feedback'] = self._generate_feedback(password, results)
        
        # Use zxcvbn if available for additional insights
        if ZXCVBN_AVAILABLE:
            zxcvbn_result = zxcvbn.zxcvbn(password)
            results['zxcvbn_score'] = zxcvbn_result['score']
            results['zxcvbn_feedback'] = zxcvbn_result.get('feedback', {})
        
        return results
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate Shannon entropy of password."""
        if not password:
            return 0.0
            
        # Calculate character pool size
        pool_size = 0
        if any(c.islower() for c in password):
            pool_size += 26
        if any(c.isupper() for c in password):
            pool_size += 26
        if any(c.isdigit() for c in password):
            pool_size += 10
        if any(c in string.punctuation for c in password):
            pool_size += 32
            
        if pool_size == 0:
            return 0.0
            
        # Entropy = log2(pool_size^length)
        entropy = len(password) * math.log2(pool_size)
        return round(entropy, 2)
    
    def _calculate_complexity(self, password: str) -> int:
        """Calculate complexity score (0-100) based on character diversity."""
        score = 0
        
        # Length scoring (max 25 points)
        if len(password) >= self.strong_length:
            score += 25
        elif len(password) >= self.recommended_length:
            score += 20
        elif len(password) >= self.min_length:
            score += 15
        else:
            score += len(password) * 1.5
            
        # Character diversity (max 40 points)
        if any(c.islower() for c in password):
            score += 10
        if any(c.isupper() for c in password):
            score += 10
        if any(c.isdigit() for c in password):
            score += 10
        if any(c in string.punctuation for c in password):
            score += 10
            
        # Character variety within types (max 20 points)
        unique_chars = len(set(password))
        variety_ratio = unique_chars / len(password) if password else 0
        score += variety_ratio * 20
        
        # Penalize common patterns (max -15 points)
        penalties = self._calculate_pattern_penalties(password)
        score -= penalties
        
        return max(0, min(100, int(score)))
    
    def _analyze_characters(self, password: str) -> Dict:
        """Analyze character composition of password."""
        return {
            'lowercase': sum(1 for c in password if c.islower()),
            'uppercase': sum(1 for c in password if c.isupper()),
            'digits': sum(1 for c in password if c.isdigit()),
            'special': sum(1 for c in password if c in string.punctuation),
            'spaces': sum(1 for c in password if c.isspace()),
            'unique_chars': len(set(password)),
            'repeated_chars': len(password) - len(set(password))
        }
    
    def _detect_patterns(self, password: str) -> Dict:
        """Detect common password patterns."""
        patterns = {
            'sequential_letters': bool(re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower())),
            'sequential_numbers': bool(re.search(r'(012|123|234|345|456|567|678|789)', password)),
            'repeated_chars': bool(re.search(r'(.)\1{2,}', password)),
            'keyboard_pattern': self._detect_keyboard_pattern(password),
            'common_substitutions': self._detect_common_substitutions(password),
            'year_pattern': bool(re.search(r'(19|20)\d{2}', password)),
            'date_pattern': bool(re.search(r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}', password))
        }
        return patterns
    
    def _detect_keyboard_pattern(self, password: str) -> bool:
        """Detect keyboard patterns like qwerty, asdf."""
        keyboard_patterns = [
            'qwerty', 'qwertz', 'azerty', 'asdf', 'asdfgh',
            'zxcv', 'zxcvb', '!@#$', '1qaz', '2wsx'
        ]
        pwd_lower = password.lower()
        return any(pattern in pwd_lower for pattern in keyboard_patterns)
    
    def _detect_common_substitutions(self, password: str) -> bool:
        """Detect common letter-to-number/symbol substitutions."""
        substitutions = {
            '@': 'a', '3': 'e', '1': 'i', '!': 'i',
            '0': 'o', '$': 's', '7': 't', '5': 's'
        }
        # Check if password uses these substitutions
        has_substitution = any(sub in password for sub in substitutions.keys())
        return has_substitution
    
    def _calculate_pattern_penalties(self, password: str) -> int:
        """Calculate penalty points for detected patterns."""
        penalties = 0
        patterns = self._detect_patterns(password)
        
        if patterns['sequential_letters']:
            penalties += 5
        if patterns['sequential_numbers']:
            penalties += 5
        if patterns['repeated_chars']:
            penalties += 3
        if patterns['keyboard_pattern']:
            penalties += 5
        if patterns['year_pattern']:
            penalties += 2
        if patterns['date_pattern']:
            penalties += 3
            
        return penalties
    
    def _calculate_overall_score(self, results: Dict) -> int:
        """Calculate overall password strength score (0-100)."""
        # Weight different factors
        complexity_weight = 0.5
        entropy_weight = 0.3
        length_weight = 0.2
        
        # Normalize entropy (assume max reasonable entropy is 128 bits)
        normalized_entropy = min(results['entropy'] / 128 * 100, 100)
        
        # Normalize length (assume max reasonable length is 64)
        normalized_length = min(results['length'] / 64 * 100, 100)
        
        score = (
            results['complexity_score'] * complexity_weight +
            normalized_entropy * entropy_weight +
            normalized_length * length_weight
        )
        
        return int(score)
    
    def _determine_strength_level(self, score: int) -> str:
        """Determine strength level based on score."""
        if score >= 80:
            return "Very Strong"
        elif score >= 60:
            return "Strong"
        elif score >= 40:
            return "Moderate"
        elif score >= 20:
            return "Weak"
        else:
            return "Very Weak"
    
    def _estimate_crack_time(self, entropy: float) -> str:
        """Estimate time to crack password using brute force.
        
        Assumes 10 billion guesses per second (modern GPU).
        """
        if entropy == 0:
            return "Instant"
            
        guesses_per_second = 10_000_000_000  # 10 billion
        total_combinations = 2 ** entropy
        seconds = total_combinations / (2 * guesses_per_second)  # Divide by 2 for average case
        
        if seconds < 1:
            return "Instant"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds / 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds / 3600)} hours"
        elif seconds < 2592000:
            return f"{int(seconds / 86400)} days"
        elif seconds < 31536000:
            return f"{int(seconds / 2592000)} months"
        else:
            years = int(seconds / 31536000)
            if years > 1000000:
                return f"{years / 1000000:.1f} million years"
            elif years > 1000:
                return f"{years / 1000:.1f} thousand years"
            else:
                return f"{years} years"
    
    def _generate_feedback(self, password: str, results: Dict) -> List[str]:
        """Generate actionable feedback for password improvement."""
        feedback = []
        
        # Length feedback
        if results['length'] < self.min_length:
            feedback.append(f"Password is too short. Use at least {self.min_length} characters.")
        elif results['length'] < self.recommended_length:
            feedback.append(f"Consider using at least {self.recommended_length} characters for better security.")
        
        # Character diversity feedback
        char_analysis = results['character_analysis']
        if char_analysis['lowercase'] == 0:
            feedback.append("Add lowercase letters for more complexity.")
        if char_analysis['uppercase'] == 0:
            feedback.append("Add uppercase letters for more complexity.")
        if char_analysis['digits'] == 0:
            feedback.append("Add numbers for more complexity.")
        if char_analysis['special'] == 0:
            feedback.append("Add special characters (!@#$%^&*) for more complexity.")
        
        # Pattern feedback
        patterns = results['pattern_analysis']
        if patterns['sequential_letters']:
            feedback.append("Avoid sequential letters (e.g., 'abc', 'xyz').")
        if patterns['sequential_numbers']:
            feedback.append("Avoid sequential numbers (e.g., '123', '789').")
        if patterns['repeated_chars']:
            feedback.append("Avoid repeating characters (e.g., 'aaa', '111').")
        if patterns['keyboard_pattern']:
            feedback.append("Avoid keyboard patterns (e.g., 'qwerty', 'asdf').")
        if patterns['year_pattern']:
            feedback.append("Avoid using years in your password.")
        if patterns['date_pattern']:
            feedback.append("Avoid using dates in your password.")
        
        # Uniqueness feedback
        if char_analysis['unique_chars'] < len(password) * 0.5:
            feedback.append("Use more unique characters. Too many repeats detected.")
        
        if not feedback:
            feedback.append("Great password! Consider using a password manager to store it securely.")
        
        return feedback
    
    def _empty_result(self) -> Dict:
        """Return empty result structure."""
        return {
            'length': 0,
            'entropy': 0.0,
            'complexity_score': 0,
            'character_analysis': {},
            'pattern_analysis': {},
            'strength_level': 'Invalid',
            'score': 0,
            'feedback': ['Please enter a password to analyze.'],
            'crack_time': 'N/A'
        }